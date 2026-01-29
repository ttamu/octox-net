use super::{
    ip::{egress_route, IpAddr, IpHeader},
    util::{checksum, verify_checksum, write_u16},
};
use crate::{
    error::{Error, Result},
    net::{socket::SocketHandle, socket::SocketSet},
    spinlock::Mutex,
    trace,
};
use alloc::{collections::VecDeque, vec, vec::Vec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcmpType {
    EchoReply = 0,
    DestinationUnreachable = 3,
    EchoRequest = 8,
    TimeExceeded = 11,
}

mod wire {
    use crate::error::{Error, Result};
    use crate::net::util::{read_u16, write_u16};

    pub mod field {
        pub type Field = core::ops::Range<usize>;

        pub const MSG_TYPE: Field = 0..1;
        pub const CODE: Field = 1..2;
        pub const CHECKSUM: Field = 2..4;
        pub const ID: Field = 4..6;
        pub const SEQ: Field = 6..8;
    }

    pub const ECHO_HEADER_LEN: usize = field::SEQ.end;

    pub struct Echo<'a> {
        buffer: &'a [u8],
    }

    impl<'a> Echo<'a> {
        pub fn new_checked(buffer: &'a [u8]) -> Result<Self> {
            if buffer.len() < ECHO_HEADER_LEN {
                return Err(Error::PacketTooShort);
            }
            Ok(Self { buffer })
        }

        pub fn msg_type(&self) -> u8 {
            self.buffer[field::MSG_TYPE.start]
        }

        #[allow(dead_code)]
        pub fn code(&self) -> u8 {
            self.buffer[field::CODE.start]
        }

        #[allow(dead_code)]
        pub fn checksum(&self) -> u16 {
            read_u16(&self.buffer[field::CHECKSUM])
        }

        pub fn id(&self) -> u16 {
            read_u16(&self.buffer[field::ID])
        }

        pub fn seq(&self) -> u16 {
            read_u16(&self.buffer[field::SEQ])
        }
    }

    pub struct EchoMut<'a> {
        buffer: &'a mut [u8],
    }

    impl<'a> EchoMut<'a> {
        pub fn new_unchecked(buffer: &'a mut [u8]) -> Self {
            Self { buffer }
        }

        pub fn set_msg_type(&mut self, value: u8) {
            self.buffer[field::MSG_TYPE.start] = value;
        }

        pub fn set_code(&mut self, value: u8) {
            self.buffer[field::CODE.start] = value;
        }

        pub fn set_checksum(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::CHECKSUM], value);
        }

        pub fn set_id(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::ID], value);
        }

        pub fn set_seq(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::SEQ], value);
        }

        pub fn payload_mut(&mut self) -> &mut [u8] {
            &mut self.buffer[ECHO_HEADER_LEN..]
        }
    }
}

#[derive(Debug, Clone)]
struct RawPacket {
    src: IpAddr,
    data: Vec<u8>,
}

pub struct RawSocket {
    protocol: u8,
    recv_queue: VecDeque<RawPacket>,
}

impl RawSocket {
    const fn new(protocol: u8) -> Self {
        Self {
            protocol,
            recv_queue: VecDeque::new(),
        }
    }
}

struct Icmp {
    sockets: Mutex<SocketSet<RawSocket>>,
}

impl Icmp {
    const SOCKET_CAPACITY: usize = 16;

    const fn new() -> Self {
        Self {
            sockets: Mutex::new(SocketSet::new(Self::SOCKET_CAPACITY), "icmp_sockets"),
        }
    }

    fn socket_alloc(&self) -> Result<usize> {
        let mut sockets = self.sockets.lock();
        let handle = sockets.alloc(RawSocket::new(IpHeader::ICMP))?;
        Ok(handle.index())
    }

    fn socket_free(&self, index: usize) -> Result<()> {
        let mut sockets = self.sockets.lock();
        let handle = SocketHandle::new(index);
        if handle.index() >= Self::SOCKET_CAPACITY {
            return Err(Error::InvalidSocketIndex);
        }
        match sockets.get(handle) {
            Ok(_) => sockets.free(handle),
            Err(Error::InvalidSocketState) => Err(Error::InvalidSocketIndex),
            Err(err) => Err(err),
        }
    }

    fn socket_sendto(&self, index: usize, dst: IpAddr, data: &[u8]) -> Result<usize> {
        let sockets = self.sockets.lock();
        let socket = sockets.get(SocketHandle::new(index))?;
        let protocol = socket.protocol;
        drop(sockets);

        if data.len() < wire::field::CHECKSUM.end {
            return Err(Error::PacketTooShort);
        }

        let mut packet = data.to_vec();
        write_u16(&mut packet[wire::field::CHECKSUM], 0);
        let csum = checksum(&packet);
        write_u16(&mut packet[wire::field::CHECKSUM], csum);

        trace!(
            ICMP,
            "[icmp] sending raw: {} bytes -> {:?}",
            packet.len(),
            dst.to_bytes()
        );

        egress_route(dst, protocol, &packet)?;
        Ok(packet.len())
    }

    fn socket_recvfrom(&self, index: usize, buf: &mut [u8]) -> Result<(usize, IpAddr)> {
        let mut sockets = self.sockets.lock();
        let socket = sockets.get_mut(SocketHandle::new(index))?;
        let Some(packet) = socket.recv_queue.pop_front() else {
            return Err(Error::WouldBlock);
        };

        let len = packet.data.len().min(buf.len());
        buf[..len].copy_from_slice(&packet.data[..len]);
        Ok((len, packet.src))
    }

    fn ingress(&self, src: IpAddr, dst: IpAddr, data: &[u8]) -> Result<()> {
        if !verify_checksum(data) {
            return Err(Error::ChecksumError);
        }

        let echo = wire::Echo::new_checked(data)?;
        if echo.msg_type() == IcmpType::EchoRequest as u8 {
            let id = echo.id();
            let seq = echo.seq();
            let payload = &data[wire::ECHO_HEADER_LEN..];
            self.echo_reply(dst, src, id, seq, payload)?;
        }

        self.enqueue_to_all(src, data);
        Ok(())
    }

    fn enqueue_to_all(&self, src: IpAddr, data: &[u8]) {
        let mut sockets = self.sockets.lock();
        for (_, socket) in sockets.iter_mut() {
            socket.recv_queue.push_back(RawPacket {
                src,
                data: data.to_vec(),
            });
        }
    }

    fn echo_reply(
        &self,
        _src: IpAddr,
        dst: IpAddr,
        id: u16,
        seq: u16,
        payload: &[u8],
    ) -> Result<()> {
        let total_len = wire::ECHO_HEADER_LEN + payload.len();
        let mut packet = vec![0u8; total_len];

        {
            let mut echo = wire::EchoMut::new_unchecked(&mut packet);
            echo.set_msg_type(IcmpType::EchoReply as u8);
            echo.set_code(0);
            echo.set_checksum(0);
            echo.set_id(id);
            echo.set_seq(seq);
            echo.payload_mut().copy_from_slice(payload);
        }
        let csum = checksum(&packet);
        write_u16(&mut packet[2..4], csum);

        trace!(
            ICMP,
            "[icmp] Sending Echo Reply to {:?}, id={}, seq={}",
            dst.to_bytes(),
            id,
            seq
        );

        egress_route(dst, IpHeader::ICMP, &packet)
    }
}

static ICMP: Icmp = Icmp::new();

pub fn socket_alloc() -> Result<usize> {
    ICMP.socket_alloc()
}

pub fn socket_free(index: usize) -> Result<()> {
    ICMP.socket_free(index)
}

pub fn socket_sendto(index: usize, dst: IpAddr, data: &[u8]) -> Result<usize> {
    ICMP.socket_sendto(index, dst, data)
}

pub fn socket_recvfrom(index: usize, buf: &mut [u8]) -> Result<(usize, IpAddr)> {
    ICMP.socket_recvfrom(index, buf)
}

pub fn ingress(src: IpAddr, dst: IpAddr, data: &[u8]) -> Result<()> {
    ICMP.ingress(src, dst, data)
}

#[cfg(test)]
mod tests {
    use super::{wire, Icmp, IpAddr, RawPacket, SocketHandle};
    use crate::error::Error;
    use alloc::vec;

    #[test_case]
    fn echo_too_short() {
        let data = [0u8; wire::ECHO_HEADER_LEN - 1];
        let err = wire::Echo::new_checked(&data).err().unwrap();
        assert_eq!(err, Error::PacketTooShort);
    }

    #[test_case]
    fn socket_alloc_release() {
        let icmp = Icmp::new();
        let idx = icmp.socket_alloc().unwrap();
        icmp.socket_free(idx).unwrap();
        let err = icmp.socket_free(idx).unwrap_err();
        assert_eq!(err, Error::InvalidSocketIndex);
    }

    #[test_case]
    fn socket_recvfrom_empty() {
        let icmp = Icmp::new();
        let idx = icmp.socket_alloc().unwrap();
        let mut buf = [0u8; 8];
        let err = icmp.socket_recvfrom(idx, &mut buf).unwrap_err();
        assert_eq!(err, Error::WouldBlock);
    }

    #[test_case]
    fn socket_recvfrom_packet() {
        let icmp = Icmp::new();
        let idx = icmp.socket_alloc().unwrap();
        let src = IpAddr::new(192, 0, 2, 1);
        {
            let mut sockets = icmp.sockets.lock();
            let socket = sockets.get_mut(SocketHandle::new(idx)).unwrap();
            socket.recv_queue.push_back(RawPacket {
                src,
                data: vec![1, 2, 3, 4],
            });
        }

        let mut buf = [0u8; 8];
        let (len, recv_src) = icmp.socket_recvfrom(idx, &mut buf).unwrap();
        assert_eq!(len, 4);
        assert_eq!(recv_src, src);
        assert_eq!(&buf[..len], &[1, 2, 3, 4]);
    }
}
