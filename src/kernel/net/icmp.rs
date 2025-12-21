use super::{
    ip::{ip_output, IpAddr, IpHeader},
    util::{checksum, verify_checksum},
};
use crate::net::ip::ip_output_route;
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

static ICMP_REPLY_QUEUE: Mutex<VecDeque<IcmpReply>> = Mutex::new(VecDeque::new(), "icmp_queue");
static ICMP_REPLY_CV: Condvar = Condvar::new();

pub fn icmp_input(src: IpAddr, dst: IpAddr, data: &[u8]) -> Result<()> {
    if data.len() < IcmpEcho::HEADER_SIZE {
        return Err(Error::PacketTooShort);
    }

    if !verify_checksum(data) {
        return Err(Error::ChecksumError);
    }

    let echo = unsafe { &*(data.as_ptr() as *const IcmpEcho) };
    let id = u16::from_be(echo.id);
    let seq = u16::from_be(echo.seq);
    let payload = &data[IcmpEcho::HEADER_SIZE..];

    match echo.msg_type {
        t if t == IcmpType::EchoRequest as u8 => {
            crate::println!(
                "[icmp] Received Echo Request from {:?}, id={}, seq={}",
                src.to_bytes(),
                id,
                seq
            );
            icmp_echo_reply(dst, src, id, seq, payload)
        }
        t if t == IcmpType::EchoReply as u8 => {
            crate::println!(
                "[icmp] Received Echo Reply from {:?}, id={}, seq={}",
                src.to_bytes(),
                id,
                seq
            );
            icmp_notify_reply(src, id, seq, payload, IcmpReplyKind::Echo)
        }
        t if t == IcmpType::DestinationUnreachable as u8 => {
            let code = echo.code;

            if payload.len() < 28 {
                return Err(Error::PacketTooShort);
            }

            let inner_ip_hdr = &payload[..20];
            let inner_protocol = inner_ip_hdr[9];

            if inner_protocol != IpHeader::ICMP {
                return Err(Error::UnsupportedProtocol);
            }

            let inner_icmp = &payload[20..];
            if inner_icmp.len() < IcmpEcho::HEADER_SIZE {
                return Err(Error::UnsupportedProtocol);
            }

            let orig_id = u16::from_be_bytes([inner_icmp[4], inner_icmp[5]]);
            let orig_seq = u16::from_be_bytes([inner_icmp[6], inner_icmp[7]]);
            crate::println!(
                "[icmp] Destination Unreachable code={} for id={}, seq={}",
                code,
                orig_id,
                orig_seq
            );
            icmp_notify_reply(
                src,
                orig_id,
                orig_seq,
                payload,
                IcmpReplyKind::Unreachable(code),
            )
        }
        _ => Err(Error::UnsupportedProtocol),
    }
}

pub fn icmp_echo_reply(src: IpAddr, dst: IpAddr, id: u16, seq: u16, payload: &[u8]) -> Result<()> {
    let total_len = IcmpEcho::HEADER_SIZE + payload.len();
    let mut packet = vec![0u8; total_len];

    let echo = unsafe { &mut *(packet.as_mut_ptr() as *mut IcmpEcho) };
    echo.msg_type = IcmpType::EchoReply as u8;
    echo.code = 0;
    echo.checksum = 0;
    echo.id = id.to_be();
    echo.seq = seq.to_be();
    packet[IcmpEcho::HEADER_SIZE..].copy_from_slice(payload);
    echo.checksum = checksum(&packet).to_be();

    crate::println!(
        "[icmp] Sending Echo Reply to {:?}, id={}, seq={}",
        dst.to_bytes(),
        id,
        seq
    );

    let dev = net_device_by_name("lo").ok_or(Error::DeviceNotFound)?;
    ip_output(&dev, IpHeader::ICMP, src, dst, &packet)
}

pub fn icmp_echo_request(dst: IpAddr, id: u16, seq: u16, payload: &[u8]) -> Result<()> {
    let total_len = IcmpEcho::HEADER_SIZE + payload.len();
    let mut packet = vec![0u8; total_len];
    let echo = unsafe { &mut *(packet.as_mut_ptr() as *mut IcmpEcho) };
    echo.msg_type = IcmpType::EchoRequest as u8;
    echo.code = 0;
    echo.checksum = 0;
    echo.id = id.to_be();
    echo.seq = seq.to_be();
    packet[IcmpEcho::HEADER_SIZE..].copy_from_slice(payload);
    echo.checksum = checksum(&packet).to_be();

    crate::println!(
        "[icmp] Sending Echo Request to {:?}, id={}, seq={}",
        dst.to_bytes(),
        id,
        seq
    );

    ip_output_route(dst, IpHeader::ICMP, &packet)
}

pub fn icmp_notify_reply(
    src: IpAddr,
    id: u16,
    seq: u16,
    payload: &[u8],
    kind: IcmpReplyKind,
) -> Result<()> {
    {
        let mut q = ICMP_REPLY_QUEUE.lock();
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
    ICMP_REPLY_CV.notify_all();
    Ok(())
}

pub fn icmp_recv_reply(id: u16, timeout_ms: u64) -> Result<IcmpReply> {
    let start = *crate::trap::TICKS.lock();
    let tick_ms = crate::param::TICK_MS as u64;
    let timeout_ticks = (timeout_ms + tick_ms - 1) / tick_ms;
    loop {
        // TODO: virtio-net実装後にコメントアウトを外す
        // crate::net::driver::virtio_net::poll_rx();
        if let Some(reply) = {
            let mut q = ICMP_REPLY_QUEUE.lock();
            if let Some(pos) = q.iter().position(|r| r.id == id) {
                Some(q.remove(pos).unwrap())
            } else {
                None
            }
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
