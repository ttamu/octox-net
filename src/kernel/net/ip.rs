use super::{
    protocol::{net_protocol_register, ProtocolType},
    util::{
        checksum, hton16, hton32, ntoh16, ntoh32, parse_header, parse_header_mut, verify_checksum,
    },
};
use crate::{
    error::{Error, Result},
    net::{
        device::{net_device_by_name, NetDevice},
        icmp, tcp, udp,
    },
};
extern crate alloc;
use core::mem::size_of;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IpHeader {
    pub version_ihl: u8,   // Version (4bit) + IHL (4bit)
    pub tos: u8,           // Type of Service
    pub total_len: u16,    // Total Length
    pub id: u16,           // Identification
    pub flags_offset: u16, // Flags + Fragment Offset
    pub ttl: u8,           // Time To Live
    pub protocol: u8,      // Protocol (1=ICMP, 6=TCP, 17=UDP)
    pub checksum: u16,     // Header Checksum
    pub src: u32,          // Source Address
    pub dst: u32,          // Destination Address
}
impl IpHeader {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;

    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }

    pub fn header_len(&self) -> usize {
        (self.ihl() as usize) * 4
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IpAddr(pub u32);

impl IpAddr {
    pub const LOOPBACK: IpAddr = IpAddr(0x7F00_0001);

    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        IpAddr(u32::from_be_bytes([a, b, c, d]))
    }

    pub fn to_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

pub fn input(_dev: &NetDevice, data: &[u8]) -> Result<()> {
    let header = parse_header::<IpHeader>(data)?;
    if header.version() != 4 {
        return Err(Error::InvalidVersion);
    }

    let hlen = header.header_len();
    if hlen < 20 || hlen > data.len() {
        return Err(Error::InvalidHeaderLen);
    }

    if !verify_checksum(&data[..hlen]) {
        return Err(Error::ChecksumError);
    }

    let total_len = ntoh16(header.total_len) as usize;
    if total_len > data.len() {
        return Err(Error::PacketTruncated);
    }

    let src = IpAddr(ntoh32(header.src));
    let dst = IpAddr(ntoh32(header.dst));

    crate::trace!(
        IP,
        "[ip] received packet: {:?} -> {:?}, proto={}",
        src.to_bytes(),
        dst.to_bytes(),
        header.protocol
    );

    let payload = &data[hlen..total_len];
    match header.protocol {
        IpHeader::ICMP => icmp::input(src, dst, payload),
        IpHeader::TCP => tcp::input(src, dst, payload),
        IpHeader::UDP => udp::input(src, dst, payload),
        _ => Err(Error::UnsupportedProtocol),
    }
}

pub fn output(dev: &NetDevice, protocol: u8, src: IpAddr, dst: IpAddr, data: &[u8]) -> Result<()> {
    let total_len = size_of::<IpHeader>() + data.len();
    if total_len > 65535 {
        return Err(Error::PacketTooLarge);
    }
    let mut packet = alloc::vec![0u8; total_len];
    {
        let header = parse_header_mut::<IpHeader>(&mut packet)?;
        header.version_ihl = 0x45;
        header.tos = 0;
        header.total_len = hton16(total_len as u16);
        header.id = 0;
        header.flags_offset = 0;
        header.ttl = 64;
        header.protocol = protocol;
        header.checksum = 0;
        header.src = hton32(src.0);
        header.dst = hton32(dst.0);
    }
    let csum = hton16(checksum(&packet[..size_of::<IpHeader>()]));
    packet[10..12].copy_from_slice(&csum.to_ne_bytes());
    packet[size_of::<IpHeader>()..].copy_from_slice(data);

    crate::trace!(
        IP,
        "[ip] sending packet: {:?} -> {:?}, {} bytes",
        src.to_bytes(),
        dst.to_bytes(),
        total_len
    );

    let mut dev_clone = dev.clone();
    dev_clone.transmit(&packet)
}

pub fn get_source_address(dst: IpAddr) -> Option<IpAddr> {
    if dst.0 == IpAddr::LOOPBACK.0 {
        return Some(IpAddr::LOOPBACK);
    }

    let route = crate::net::route::lookup(dst)?;
    let dev = net_device_by_name(route.dev)?;

    if let Some(iface) = dev
        .interfaces
        .iter()
        .find(|i| (dst.0 & i.netmask.0) == (i.addr.0 & i.netmask.0))
    {
        return Some(iface.addr);
    }

    dev.interfaces.first().map(|i| i.addr)
}

pub fn output_route(dst: IpAddr, protocol: u8, payload: &[u8]) -> Result<()> {
    if dst.0 == IpAddr::LOOPBACK.0 {
        let dev = crate::net::device::net_device_by_name("lo").ok_or(Error::DeviceNotFound)?;
        return output(&dev, protocol, IpAddr::LOOPBACK, dst, payload);
    }

    if let Some(route) = crate::net::route::lookup(dst) {
        let dev = net_device_by_name(route.dev).ok_or(Error::DeviceNotFound)?;
        let src = get_source_address(dst).unwrap_or(IpAddr::LOOPBACK);

        let next_hop = route.gateway.unwrap_or(dst);
        let mac = crate::net::arp::resolve(dev.name(), next_hop, src, crate::param::TICK_HZ)
            .map_err(|_| Error::Timeout)?;
        let mut dev_clone = dev.clone();
        let total_len = core::mem::size_of::<super::ip::IpHeader>() + payload.len();
        let mut ip_packet = alloc::vec![0u8; total_len];
        {
            let hdr = parse_header_mut::<super::ip::IpHeader>(&mut ip_packet)?;
            hdr.version_ihl = 0x45;
            hdr.tos = 0;
            hdr.total_len = (total_len as u16).to_be();
            hdr.id = 0;
            hdr.flags_offset = 0;
            hdr.ttl = 64;
            hdr.protocol = protocol;
            hdr.checksum = 0;
            hdr.src = src.0.to_be();
            hdr.dst = dst.0.to_be();
        }
        let csum = super::util::checksum(&ip_packet[..core::mem::size_of::<super::ip::IpHeader>()])
            .to_be();
        ip_packet[10..12].copy_from_slice(&csum.to_ne_bytes());
        ip_packet[core::mem::size_of::<super::ip::IpHeader>()..].copy_from_slice(payload);
        return crate::net::ethernet::output(
            &mut dev_clone,
            mac,
            crate::net::ethernet::ETHERTYPE_IPV4,
            &ip_packet,
        );
    }

    Err(Error::NoSuchNode)
}

pub fn ip_init() {
    crate::println!("[net] IP layer init");
    net_protocol_register(ProtocolType::IP, input);
}

pub fn parse_ip_str(s: &str) -> Result<IpAddr> {
    let parts: alloc::vec::Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(Error::InvalidAddress);
    }
    let a = parts[0].parse::<u8>().map_err(|_| Error::InvalidAddress)?;
    let b = parts[1].parse::<u8>().map_err(|_| Error::InvalidAddress)?;
    let c = parts[2].parse::<u8>().map_err(|_| Error::InvalidAddress)?;
    let d = parts[3].parse::<u8>().map_err(|_| Error::InvalidAddress)?;
    Ok(IpAddr::new(a, b, c, d))
}
