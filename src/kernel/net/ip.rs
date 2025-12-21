use super::{
    protocol::{net_protocol_register, ProtocolType},
    util::{checksum, hton16, hton32, ntoh16, ntoh32, verify_checksum},
};
use crate::{
    error::{Error, Result},
    net::device::NetDevice,
    net::icmp
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

pub fn ip_input(_dev: &NetDevice, data: &[u8]) -> Result<()> {
    if data.len() < size_of::<IpHeader>() {
        return Err(Error::PacketTooShort);
    }

    let header = unsafe { &*(data.as_ptr() as *const IpHeader) };
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

    crate::println!(
        "[ip] received packet: {:?} -> {:?}, proto={}",
        src.to_bytes(),
        dst.to_bytes(),
        header.protocol
    );

    let payload = &data[hlen..total_len];
    match header.protocol {
        IpHeader::ICMP => icmp::icmp_input(src, dst, payload),
        _ => Err(Error::UnsupportedProtocol),
    }
}

pub fn ip_output(
    dev: &NetDevice,
    protocol: u8,
    src: IpAddr,
    dst: IpAddr,
    data: &[u8],
) -> Result<()> {
    let total_len = size_of::<IpHeader>() + data.len();
    if total_len > 65535 {
        return Err(Error::PacketTooLarge);
    }
    let mut packet = alloc::vec![0u8; total_len];
    let header = unsafe { &mut *(packet.as_mut_ptr() as *mut IpHeader) };
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
    header.checksum = hton16(checksum(&packet[..size_of::<IpHeader>()]));
    packet[size_of::<IpHeader>()..].copy_from_slice(data);

    crate::println!(
        "[ip] sending packet: {:?} -> {:?}, {} bytes",
        src.to_bytes(),
        dst.to_bytes(),
        total_len
    );

    let mut dev_clone = dev.clone();
    dev_clone.transmit(&packet)
}

pub fn ip_output_route(dst: IpAddr, protocol: u8, payload: &[u8]) -> Result<()> {
    if dst.0 == IpAddr::LOOPBACK.0 {
        let dev = crate::net::device::net_device_by_name("lo").ok_or(Error::DeviceNotFound)?;
        return ip_output(&dev, protocol, IpAddr::LOOPBACK, dst, payload);
    }

    // TODO: router実装時に詳細を実装

    Err(Error::NoSuchNode)
}

pub fn ip_init() {
    crate::println!("[net] IP layer init");
    net_protocol_register(ProtocolType::IP, |dev, data| ip_input(dev, data));
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
