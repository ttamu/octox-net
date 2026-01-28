use super::{
    ip::{egress_route, IpAddr, IpEndpoint, IpHeader},
    util::checksum,
};
use crate::{
    error::{Error, Result},
    net::socket::{SocketHandle, SocketSet},
    spinlock::Mutex,
    trace,
};
extern crate alloc;
use alloc::{collections::VecDeque, vec::Vec};

pub const UDP_PROTOCOL: u8 = IpHeader::UDP;

const UDP_SOURCE_PORT_MIN: u16 = 49152;
const UDP_SOURCE_PORT_MAX: u16 = 65535;

const UDP_SOCKET_SIZE: usize = 16;

mod wire {
    use crate::error::{Error, Result};
    use crate::net::util::{read_u16, write_u16};

    pub mod field {
        pub type Field = core::ops::Range<usize>;

        pub const SRC_PORT: Field = 0..2;
        pub const DST_PORT: Field = 2..4;
        pub const LENGTH: Field = 4..6;
        pub const CHECKSUM: Field = 6..8;
    }

    pub const HEADER_LEN: usize = field::CHECKSUM.end;

    pub struct Packet<'a> {
        buffer: &'a [u8],
    }

    impl<'a> Packet<'a> {
        pub fn new_checked(buffer: &'a [u8]) -> Result<Self> {
            if buffer.len() < HEADER_LEN {
                return Err(Error::PacketTooShort);
            }
            Ok(Self { buffer })
        }

        pub fn src_port(&self) -> u16 {
            read_u16(&self.buffer[field::SRC_PORT])
        }

        pub fn dst_port(&self) -> u16 {
            read_u16(&self.buffer[field::DST_PORT])
        }

        pub fn length(&self) -> u16 {
            read_u16(&self.buffer[field::LENGTH])
        }

        pub fn checksum(&self) -> u16 {
            read_u16(&self.buffer[field::CHECKSUM])
        }
    }

    pub struct PacketMut<'a> {
        buffer: &'a mut [u8],
    }

    impl<'a> PacketMut<'a> {
        pub fn new_unchecked(buffer: &'a mut [u8]) -> Self {
            Self { buffer }
        }

        pub fn set_src_port(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::SRC_PORT], value);
        }

        pub fn set_dst_port(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::DST_PORT], value);
        }

        pub fn set_length(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::LENGTH], value);
        }

        pub fn set_checksum(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::CHECKSUM], value);
        }

        pub fn payload_mut(&mut self) -> &mut [u8] {
            &mut self.buffer[HEADER_LEN..]
        }
    }
}

#[derive(Debug, Clone)]
struct UdpPacket {
    foreign: IpEndpoint,
    data: Vec<u8>,
}

struct UdpSocket {
    local: IpEndpoint,
    recv_queue: VecDeque<UdpPacket>,
}
impl UdpSocket {
    const fn new() -> Self {
        Self {
            local: IpEndpoint::unspecified(),
            recv_queue: VecDeque::new(),
        }
    }
}
pub struct Udp {
    sockets: Mutex<SocketSet<UdpSocket>>,
    next_ephemeral_port: Mutex<u16>,
}

impl Udp {
    const SOCKET_CAPACITY: usize = UDP_SOCKET_SIZE;

    const fn new() -> Self {
        Self {
            sockets: Mutex::new(SocketSet::new(Self::SOCKET_CAPACITY), "udp_sockets"),
            next_ephemeral_port: Mutex::new(UDP_SOURCE_PORT_MIN, "udp_port"),
        }
    }
}

static UDP: Udp = Udp::new();

impl Udp {
    fn socket_alloc(&self) -> Result<usize> {
        let mut sockets = self.sockets.lock();
        let handle = sockets.alloc(UdpSocket::new())?;
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

    fn socket_bind(&self, index: usize, mut local: IpEndpoint) -> Result<()> {
        let mut sockets = self.sockets.lock();
        let handle = SocketHandle::new(index);
        let _ = sockets.get(handle)?;

        if local.port != 0 {
            for (other_handle, other) in sockets.iter() {
                if other_handle.index() != index
                    && other.local.port == local.port
                    && (other.local.addr.0 == 0
                        || local.addr.0 == 0
                        || other.local.addr.0 == local.addr.0)
                {
                    return Err(Error::PortInUse);
                }
            }
        } else {
            let mut next_port = self.next_ephemeral_port.lock();
            for _ in 0..(UDP_SOURCE_PORT_MAX - UDP_SOURCE_PORT_MIN + 1) {
                let port = *next_port;
                *next_port = next_port.wrapping_add(1);
                if *next_port < UDP_SOURCE_PORT_MIN {
                    *next_port = UDP_SOURCE_PORT_MIN;
                }

                let mut available = true;
                for (other_handle, other) in sockets.iter() {
                    if other_handle.index() != index && other.local.port == port {
                        available = false;
                        break;
                    }
                }

                if available {
                    local.port = port;
                    break;
                }
            }

            if local.port == 0 {
                return Err(Error::NoPortAvailable);
            }
        }

        let socket = sockets.get_mut(handle)?;
        socket.local = local;
        Ok(())
    }

    fn ingress(&self, src: IpAddr, dst: IpAddr, data: &[u8]) -> Result<()> {
        let header = wire::Packet::new_checked(data)?;
        let src_port = header.src_port();
        let dst_port = header.dst_port();
        let length = header.length() as usize;
        if length < wire::HEADER_LEN || length > data.len() {
            return Err(Error::InvalidLength);
        }

        trace!(
            UDP,
            "[udp] received: {}:{} -> {}:{}, {} bytes",
            src.to_bytes()[0],
            src_port,
            dst.to_bytes()[0],
            dst_port,
            length
        );

        if header.checksum() != 0 {
            let csum = udp_checksum(src, dst, &data[..length]);
            if csum != 0xFFFF && csum != 0 {
                return Err(Error::ChecksumError);
            }
        }

        let mut sockets = self.sockets.lock();
        for (_, socket) in sockets.iter_mut() {
            if socket.local.port != dst_port {
                continue;
            }
            if socket.local.addr.0 != 0 && socket.local.addr.0 != dst.0 {
                continue;
            }

            let payload = &data[wire::HEADER_LEN..length];
            let packet = UdpPacket {
                foreign: IpEndpoint::new(src, src_port),
                data: payload.to_vec(),
            };
            socket.recv_queue.push_back(packet);
            trace!(UDP, "[udp] packet queued for port {}", dst_port);
            return Ok(());
        }

        Err(Error::NoMatchingSocket)
    }

    fn socket_sendto(&self, index: usize, dst: IpEndpoint, data: &[u8]) -> Result<()> {
        let sockets = self.sockets.lock();
        let socket = sockets.get(SocketHandle::new(index))?;
        let src = socket.local;
        drop(sockets);

        egress(src, dst, data)
    }

    fn socket_recvfrom(&self, index: usize, buf: &mut [u8]) -> Result<(usize, IpEndpoint)> {
        let mut sockets = self.sockets.lock();
        let socket = sockets.get_mut(SocketHandle::new(index))?;

        let Some(packet) = socket.recv_queue.pop_front() else {
            return Err(Error::WouldBlock);
        };

        let len = packet.data.len().min(buf.len());
        buf[..len].copy_from_slice(&packet.data[..len]);
        Ok((len, packet.foreign))
    }
}

pub fn socket_alloc() -> Result<usize> {
    UDP.socket_alloc()
}

pub fn socket_free(index: usize) -> Result<()> {
    UDP.socket_free(index)
}

pub fn socket_bind(index: usize, local: IpEndpoint) -> Result<()> {
    UDP.socket_bind(index, local)
}

fn udp_checksum(src: IpAddr, dst: IpAddr, data: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + data.len());
    buf.extend_from_slice(&src.0.to_be_bytes());
    buf.extend_from_slice(&dst.0.to_be_bytes());
    buf.push(0);
    buf.push(UDP_PROTOCOL);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);

    checksum(&buf)
}

pub fn ingress(src: IpAddr, dst: IpAddr, data: &[u8]) -> Result<()> {
    UDP.ingress(src, dst, data)
}

pub fn egress(src: IpEndpoint, dst: IpEndpoint, data: &[u8]) -> Result<()> {
    let total_len = wire::HEADER_LEN + data.len();
    if total_len > 65535 {
        return Err(Error::PacketTooLarge);
    }

    let mut packet = alloc::vec![0u8; total_len];
    {
        let mut header = wire::PacketMut::new_unchecked(&mut packet);
        header.set_src_port(src.port);
        header.set_dst_port(dst.port);
        header.set_length(total_len as u16);
        header.set_checksum(0);
        header.payload_mut().copy_from_slice(data);
    }

    let src_ip = if src.addr.0 != 0 {
        src.addr
    } else {
        super::ip::get_source_address(dst.addr).ok_or(Error::NoSuchNode)?
    };

    let csum = udp_checksum(src_ip, dst.addr, &packet);
    let checksum_value = if csum == 0 { 0xFFFF } else { csum };
    let mut header = wire::PacketMut::new_unchecked(&mut packet);
    header.set_checksum(checksum_value);

    trace!(
        UDP,
        "[udp] sending: {}:{} -> {}:{}, {} bytes",
        src.addr.to_bytes()[0],
        src.port,
        dst.addr.to_bytes()[0],
        dst.port,
        total_len
    );

    egress_route(dst.addr, UDP_PROTOCOL, &packet)
}

pub fn socket_sendto(index: usize, dst: IpEndpoint, data: &[u8]) -> Result<()> {
    UDP.socket_sendto(index, dst, data)
}

pub fn socket_recvfrom(index: usize, buf: &mut [u8]) -> Result<(usize, IpEndpoint)> {
    UDP.socket_recvfrom(index, buf)
}

#[cfg(test)]
mod tests {
    use super::{wire, IpEndpoint, Udp};
    use crate::error::Error;
    use crate::net::socket::SocketHandle;

    #[test_case]
    fn packet_too_short() {
        let data = [0u8; wire::HEADER_LEN - 1];
        let err = wire::Packet::new_checked(&data).err().unwrap();
        assert_eq!(err, Error::PacketTooShort);
    }

    #[test_case]
    fn socket_alloc_release() {
        let udp = Udp::new();
        let idx = udp.socket_alloc().unwrap();
        udp.socket_free(idx).unwrap();
        let err = udp.socket_free(idx).unwrap_err();
        assert_eq!(err, Error::InvalidSocketIndex);
    }

    #[test_case]
    fn bind_port_in_use() {
        let udp = Udp::new();
        let a = udp.socket_alloc().unwrap();
        let b = udp.socket_alloc().unwrap();
        udp.socket_bind(a, IpEndpoint::any(1000)).unwrap();
        let err = udp.socket_bind(b, IpEndpoint::any(1000)).unwrap_err();
        assert_eq!(err, Error::PortInUse);
    }

    #[test_case]
    fn socket_recvfrom_empty() {
        let udp = Udp::new();
        let idx = udp.socket_alloc().unwrap();
        let mut buf = [0u8; 4];
        let err = udp.socket_recvfrom(idx, &mut buf).unwrap_err();
        assert_eq!(err, Error::WouldBlock);
    }

    #[test_case]
    fn bind_ephemeral_ports_unique() {
        let udp = Udp::new();
        let a = udp.socket_alloc().unwrap();
        let b = udp.socket_alloc().unwrap();
        udp.socket_bind(a, IpEndpoint::any(0)).unwrap();
        udp.socket_bind(b, IpEndpoint::any(0)).unwrap();

        let sockets = udp.sockets.lock();
        let a_port = sockets.get(SocketHandle::new(a)).unwrap().local.port;
        let b_port = sockets.get(SocketHandle::new(b)).unwrap().local.port;

        assert_ne!(a_port, 0);
        assert_ne!(b_port, 0);
        assert_ne!(a_port, b_port);
    }
}
