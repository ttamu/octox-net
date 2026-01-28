use super::{
    ip::{egress, IpAddr, IpHeader},
    util::{checksum, verify_checksum, write_u16},
};
use crate::{
    condvar::Condvar,
    error::{Error, Result},
    net::device::net_device_by_name,
    spinlock::Mutex,
};
use alloc::{collections::VecDeque, vec, vec::Vec};
use core::mem::size_of;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcmpType {
    EchoReply = 0,
    DestinationUnreachable = 3,
    EchoRequest = 8,
    TimeExceeded = 11,
}

impl IcmpType {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::EchoReply),
            3 => Some(Self::DestinationUnreachable),
            8 => Some(Self::EchoRequest),
            11 => Some(Self::TimeExceeded),
            _ => None,
        }
    }
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

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IcmpEcho {
    pub msg_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub id: u16,
    pub seq: u16,
}
impl IcmpEcho {
    pub const HEADER_SIZE: usize = size_of::<Self>();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpReplyKind {
    Echo,
    Unreachable(u8),
}

#[derive(Debug, Clone)]
pub struct IcmpReply {
    pub src: IpAddr,
    pub id: u16,
    pub seq: u16,
    pub payload: Vec<u8>,
    pub kind: IcmpReplyKind,
    pub timestamp: usize,
}

use super::ip;

struct IcmpCore {
    replies: Mutex<VecDeque<IcmpReply>>,
    cv: Condvar,
}

impl IcmpCore {
    const fn new() -> Self {
        Self {
            replies: Mutex::new(VecDeque::new(), "icmp_queue"),
            cv: Condvar::new(),
        }
    }

    fn ingress(&self, src: IpAddr, dst: IpAddr, data: &[u8]) -> Result<()> {
        if !verify_checksum(data) {
            return Err(Error::ChecksumError);
        }

        let echo = wire::Echo::new_checked(data)?;
        let id = echo.id();
        let seq = echo.seq();
        let payload = &data[wire::ECHO_HEADER_LEN..];

        match IcmpType::from_u8(echo.msg_type()) {
            Some(IcmpType::EchoRequest) => self.handle_echo_request(dst, src, id, seq, payload),
            Some(IcmpType::EchoReply) => self.handle_echo_reply(src, id, seq, payload),
            Some(IcmpType::DestinationUnreachable) => {
                self.handle_unreachable(src, echo.code(), payload)
            }
            Some(IcmpType::TimeExceeded) => Err(Error::UnsupportedProtocol),
            None => Err(Error::UnsupportedProtocol),
        }
    }

    fn handle_echo_request(
        &self,
        dst: IpAddr,
        src: IpAddr,
        id: u16,
        seq: u16,
        payload: &[u8],
    ) -> Result<()> {
        crate::trace!(
            ICMP,
            "[icmp] Received Echo Request from {:?}, id={}, seq={}",
            src.to_bytes(),
            id,
            seq
        );
        self.echo_reply(dst, src, id, seq, payload)
    }

    fn handle_echo_reply(&self, src: IpAddr, id: u16, seq: u16, payload: &[u8]) -> Result<()> {
        crate::trace!(
            ICMP,
            "[icmp] Received Echo Reply from {:?}, id={}, seq={}",
            src.to_bytes(),
            id,
            seq
        );
        self.notify_reply(src, id, seq, payload, IcmpReplyKind::Echo)
    }

    fn handle_unreachable(&self, src: IpAddr, code: u8, payload: &[u8]) -> Result<()> {
        let (orig_id, orig_seq) = self.parse_unreachable(payload)?;
        crate::trace!(
            ICMP,
            "[icmp] Destination Unreachable code={} for id={}, seq={}",
            code,
            orig_id,
            orig_seq
        );
        self.notify_reply(
            src,
            orig_id,
            orig_seq,
            payload,
            IcmpReplyKind::Unreachable(code),
        )
    }

    fn parse_unreachable(&self, payload: &[u8]) -> Result<(u16, u16)> {
        if payload.len() < 28 {
            return Err(Error::PacketTooShort);
        }

        let inner_ip_hdr = &payload[..20];
        let inner_protocol = inner_ip_hdr[9];

        if inner_protocol != IpHeader::ICMP {
            return Err(Error::UnsupportedProtocol);
        }

        let inner_icmp = &payload[20..];
        if inner_icmp.len() < wire::ECHO_HEADER_LEN {
            return Err(Error::UnsupportedProtocol);
        }

        let orig_id = u16::from_be_bytes([inner_icmp[4], inner_icmp[5]]);
        let orig_seq = u16::from_be_bytes([inner_icmp[6], inner_icmp[7]]);
        Ok((orig_id, orig_seq))
    }

    fn echo_reply(
        &self,
        src: IpAddr,
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

        crate::trace!(
            ICMP,
            "[icmp] Sending Echo Reply to {:?}, id={}, seq={}",
            dst.to_bytes(),
            id,
            seq
        );

        let dev = net_device_by_name("lo").ok_or(Error::DeviceNotFound)?;
        egress(&dev, IpHeader::ICMP, src, dst, &packet)
    }

    fn echo_request(&self, dst: IpAddr, id: u16, seq: u16, payload: &[u8]) -> Result<()> {
        let total_len = wire::ECHO_HEADER_LEN + payload.len();
        let mut packet = vec![0u8; total_len];
        {
            let mut echo = wire::EchoMut::new_unchecked(&mut packet);
            echo.set_msg_type(IcmpType::EchoRequest as u8);
            echo.set_code(0);
            echo.set_checksum(0);
            echo.set_id(id);
            echo.set_seq(seq);
            echo.payload_mut().copy_from_slice(payload);
        }
        let csum = checksum(&packet);
        write_u16(&mut packet[2..4], csum);

        crate::trace!(
            ICMP,
            "[icmp] Sending Echo Request to {:?}, id={}, seq={}",
            dst.to_bytes(),
            id,
            seq
        );

        ip::egress_route(dst, IpHeader::ICMP, &packet)
    }

    fn notify_reply(
        &self,
        src: IpAddr,
        id: u16,
        seq: u16,
        payload: &[u8],
        kind: IcmpReplyKind,
    ) -> Result<()> {
        {
            let mut q = self.replies.lock();
            let now = *crate::trap::TICKS.lock();
            q.push_back(IcmpReply {
                src,
                id,
                seq,
                payload: payload.to_vec(),
                kind,
                timestamp: now,
            });
        }
        self.cv.notify_all();
        Ok(())
    }

    fn recv_reply(&self, id: u16, timeout_ms: u64) -> Result<IcmpReply> {
        let start = *crate::trap::TICKS.lock();
        let tick_ms = crate::param::TICK_MS as u64;
        let timeout_ticks = timeout_ms.div_ceil(tick_ms);
        loop {
            crate::net::poll();
            if let Some(reply) = {
                let mut q = self.replies.lock();
                q.iter()
                    .position(|r| r.id == id)
                    .map(|pos| q.remove(pos).unwrap())
            } {
                return Ok(reply);
            }
            let elapsed = *crate::trap::TICKS.lock() - start;
            if (elapsed as u64) >= timeout_ticks {
                return Err(Error::Timeout);
            }
            crate::proc::yielding();
        }
    }
}

static ICMP: IcmpCore = IcmpCore::new();

pub fn ingress(src: IpAddr, dst: IpAddr, data: &[u8]) -> Result<()> {
    ICMP.ingress(src, dst, data)
}

pub fn echo_reply(src: IpAddr, dst: IpAddr, id: u16, seq: u16, payload: &[u8]) -> Result<()> {
    ICMP.echo_reply(src, dst, id, seq, payload)
}

pub fn echo_request(dst: IpAddr, id: u16, seq: u16, payload: &[u8]) -> Result<()> {
    ICMP.echo_request(dst, id, seq, payload)
}

pub fn notify_reply(
    src: IpAddr,
    id: u16,
    seq: u16,
    payload: &[u8],
    kind: IcmpReplyKind,
) -> Result<()> {
    ICMP.notify_reply(src, id, seq, payload, kind)
}

pub fn recv_reply(id: u16, timeout_ms: u64) -> Result<IcmpReply> {
    ICMP.recv_reply(id, timeout_ms)
}

#[cfg(test)]
mod tests {
    use super::wire;
    use crate::error::Error;

    #[test_case]
    fn echo_too_short() {
        let data = [0u8; wire::ECHO_HEADER_LEN - 1];
        let err = wire::Echo::new_checked(&data).err().unwrap();
        assert_eq!(err, Error::PacketTooShort);
    }
}
