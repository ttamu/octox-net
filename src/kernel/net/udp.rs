use super::{
    ip::{output_route, IpAddr, IpHeader},
    util::{checksum, hton16, hton32, ntoh16, parse_header, parse_header_mut},
};
use crate::net::{device::net_device_by_name, route};
use crate::{
    error::{Error, Result},
    spinlock::Mutex,
};
extern crate alloc;
use alloc::{collections::VecDeque, vec::Vec};
use core::mem::size_of;

pub const UDP_PROTOCOL: u8 = IpHeader::UDP;

/// UDP source port range (ephemeral ports)
const UDP_SOURCE_PORT_MIN: u16 = 49152;
const UDP_SOURCE_PORT_MAX: u16 = 65535;

/// Maximum number of UDP PCBs
const UDP_PCB_SIZE: usize = 16;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

#[repr(C, packed)]
struct PseudoHeader {
    src: u32,
    dst: u32,
    zero: u8,
    protocol: u8,
    length: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpEndpoint {
    pub addr: IpAddr,
    pub port: u16,
}
impl UdpEndpoint {
    pub const fn new(addr: IpAddr, port: u16) -> Self {
        Self { addr, port }
    }

    pub const fn any(port: u16) -> Self {
        Self {
            addr: IpAddr(0),
            port,
        }
    }
}

/// UDP PCB(Protocol Control Block) state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpState {
    Free,
    Open,
}

#[derive(Debug, Clone)]
struct UdpPacket {
    foreign: UdpEndpoint,
    data: Vec<u8>,
}

struct UdpPcb {
    state: UdpState,
    local: UdpEndpoint,
    recv_queue: VecDeque<UdpPacket>,
}
impl UdpPcb {
    const fn new() -> Self {
        Self {
            state: UdpState::Free,
            local: UdpEndpoint::new(IpAddr(0), 0),
            recv_queue: VecDeque::new(),
        }
    }
}

static UDP_PCBS: Mutex<[UdpPcb; UDP_PCB_SIZE]> =
    Mutex::new([const { UdpPcb::new() }; UDP_PCB_SIZE], "udp_pcbs");

static NEXT_EPHEMERAL_PORT: Mutex<u16> = Mutex::new(UDP_SOURCE_PORT_MIN, "udp_port");

pub fn pcb_alloc() -> Result<usize> {
    let mut pcbs = UDP_PCBS.lock();
    for (i, pcb) in pcbs.iter_mut().enumerate() {
        if pcb.state == UdpState::Free {
            pcb.state = UdpState::Open;
            pcb.recv_queue.clear();
            return Ok(i);
        }
    }
    Err(Error::NoPcbAvailable)
}

pub fn pcb_release(index: usize) -> Result<()> {
    let mut pcbs = UDP_PCBS.lock();
    if index >= UDP_PCB_SIZE {
        return Err(Error::InvalidPcbIndex);
    }
    let pcb = &mut pcbs[index];
    if pcb.state == UdpState::Free {
        return Err(Error::InvalidPcbIndex);
    }
    pcb.state = UdpState::Free;
    pcb.recv_queue.clear();
    Ok(())
}

pub fn bind(index: usize, mut local: UdpEndpoint) -> Result<()> {
    let mut pcbs = UDP_PCBS.lock();
    if index >= UDP_PCB_SIZE {
        return Err(Error::InvalidPcbIndex);
    }
    if pcbs[index].state != UdpState::Open {
        return Err(Error::InvalidPcbState);
    }

    if local.port != 0 {
        for (i, other) in pcbs.iter().enumerate() {
            if i != index
                && other.state == UdpState::Open
                && other.local.port == local.port
                && (other.local.addr.0 == 0
                    || local.addr.0 == 0
                    || other.local.addr.0 == local.addr.0)
            {
                return Err(Error::PortInUse);
            }
        }
    } else {
        let mut next_port = NEXT_EPHEMERAL_PORT.lock();
        for _ in 0..(UDP_SOURCE_PORT_MAX - UDP_SOURCE_PORT_MIN + 1) {
            let port = *next_port;
            *next_port += 1;
            if *next_port > UDP_SOURCE_PORT_MAX {
                *next_port = UDP_SOURCE_PORT_MIN;
            }

            let mut available = true;
            for (i, other) in pcbs.iter().enumerate() {
                if i != index && other.state == UdpState::Open && other.local.port == port {
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

    pcbs[index].local = local;
    Ok(())
}

fn udp_checksum(src: IpAddr, dst: IpAddr, data: &[u8]) -> u16 {
    let mut buf = Vec::new();

    let pseudo = PseudoHeader {
        src: hton32(src.0),
        dst: hton32(dst.0),
        zero: 0,
        protocol: UDP_PROTOCOL,
        length: hton16(data.len() as u16),
    };
    let pseudo_bytes = unsafe {
        core::slice::from_raw_parts(&pseudo as *const _ as *const u8, size_of::<PseudoHeader>())
    };
    buf.extend_from_slice(pseudo_bytes);
    buf.extend_from_slice(data);

    checksum(&buf)
}

fn verify_udp_checksum(src: IpAddr, dst: IpAddr, data: &[u8]) -> bool {
    let header = match parse_header::<UdpHeader>(data) {
        Ok(h) => h,
        Err(_) => return false,
    };
    if header.checksum == 0 {
        return true;
    }

    let csum: u16 = udp_checksum(src, dst, data);
    csum == 0xFFFF || csum == 0
}

fn select_src_addr(dst: IpAddr) -> Result<IpAddr> {
    if dst.0 == IpAddr::LOOPBACK.0 {
        return Ok(IpAddr::LOOPBACK);
    }
    if let Some(route) = route::lookup(dst) {
        if let Some(dev) = net_device_by_name(route.dev) {
            if let Some(iface) = dev
                .interfaces
                .iter()
                .find(|i| (dst.0 & i.netmask.0) == (i.addr.0 & i.netmask.0))
            {
                return Ok(iface.addr);
            }
            if let Some(iface) = dev.interfaces.first() {
                return Ok(iface.addr);
            }
        }
    }
    Err(Error::NoSuchNode)
}

pub fn input(src: IpAddr, dst: IpAddr, data: &[u8]) -> Result<()> {
    let header = parse_header::<UdpHeader>(data)?;
    let src_port = ntoh16(header.src_port);
    let dst_port = ntoh16(header.dst_port);
    let length = ntoh16(header.length) as usize;
    if length < size_of::<UdpHeader>() || length > data.len() {
        return Err(Error::InvalidLength);
    }

    crate::println!(
        "[udp] received: {}:{} -> {}:{}, {} bytes",
        src.to_bytes()[0],
        src_port,
        dst.to_bytes()[0],
        dst_port,
        length
    );

    if !verify_udp_checksum(src, dst, &data[..length]) {
        return Err(Error::ChecksumError);
    }

    let mut pcbs = UDP_PCBS.lock();
    for pcb in pcbs.iter_mut() {
        if pcb.state == UdpState::Open {
            if pcb.local.port != dst_port {
                continue;
            }
            if pcb.local.addr.0 != 0 && pcb.local.addr.0 != dst.0 {
                continue;
            }

            let payload = &data[size_of::<UdpHeader>()..length];
            let packet = UdpPacket {
                foreign: UdpEndpoint::new(src, src_port),
                data: payload.to_vec(),
            };
            pcb.recv_queue.push_back(packet);
            crate::println!("[udp] packet queued for port {}", dst_port);
            return Ok(());
        }
    }

    Err(Error::NoMatchingPcb)
}

pub fn output(src: UdpEndpoint, dst: UdpEndpoint, data: &[u8]) -> Result<()> {
    let total_len = size_of::<UdpHeader>() + data.len();
    if total_len > 65535 {
        return Err(Error::PacketTooLarge);
    }

    let mut packet = alloc::vec![0u8; total_len];
    {
        let header = parse_header_mut::<UdpHeader>(&mut packet)?;
        header.src_port = hton16(src.port);
        header.dst_port = hton16(dst.port);
        header.length = hton16(total_len as u16);
        header.checksum = 0;
    }

    packet[size_of::<UdpHeader>()..].copy_from_slice(data);

    let src_ip = if src.addr.0 != 0 {
        src.addr
    } else {
        select_src_addr(dst.addr)?
    };

    let csum = udp_checksum(src_ip, dst.addr, &packet);
    let checksum_value = if csum == 0 { 0xFFFF } else { hton16(csum) };
    packet[6..8].copy_from_slice(&checksum_value.to_ne_bytes());

    crate::println!(
        "[udp] sending: {}:{} -> {}:{}, {} bytes",
        src.addr.to_bytes()[0],
        src.port,
        dst.addr.to_bytes()[0],
        dst.port,
        total_len
    );

    output_route(dst.addr, UDP_PROTOCOL, &packet)
}

pub fn sendto(index: usize, dst: UdpEndpoint, data: &[u8]) -> Result<()> {
    let pcbs = UDP_PCBS.lock();
    if index >= UDP_PCB_SIZE {
        return Err(Error::InvalidPcbIndex);
    }
    let pcb = &pcbs[index];
    if pcb.state != UdpState::Open {
        return Err(Error::InvalidPcbState);
    }

    let src = pcb.local;
    drop(pcbs);

    output(src, dst, data)
}

pub fn recvfrom(index: usize, buf: &mut [u8]) -> Result<(usize, UdpEndpoint)> {
    let mut pcbs = UDP_PCBS.lock();
    if index >= UDP_PCB_SIZE {
        return Err(Error::InvalidPcbIndex);
    }
    let pcb = &mut pcbs[index];
    if pcb.state != UdpState::Open {
        return Err(Error::InvalidPcbState);
    }

    let Some(packet) = pcb.recv_queue.pop_front() else {
        return Err(Error::WouldBlock);
    };

    let len = packet.data.len().min(buf.len());
    buf[..len].copy_from_slice(&packet.data[..len]);
    Ok((len, packet.foreign))
}
