use super::{
    protocol::{net_protocol_register, ProtocolType},
    util::verify_checksum,
};
use crate::{
    error::{Error, Result},
    net::{
        arp,
        device::{net_device_by_name, NetDevice},
        ethernet, icmp, route, tcp, udp,
    },
    println, trace,
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
    pub protocol: u8,      // Protocol
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

mod wire {
    use crate::error::{Error, Result};
    use crate::net::util::{read_u16, write_u16};

    pub mod field {
        pub type Field = core::ops::Range<usize>;

        pub const VERSION_IHL: Field = 0..1;
        pub const TOS: Field = 1..2;
        pub const TOTAL_LEN: Field = 2..4;
        pub const ID: Field = 4..6;
        pub const FLAGS_OFFSET: Field = 6..8;
        pub const TTL: Field = 8..9;
        pub const PROTOCOL: Field = 9..10;
        pub const CHECKSUM: Field = 10..12;
        pub const SRC: Field = 12..16;
        pub const DST: Field = 16..20;
    }

    pub const MIN_HEADER_LEN: usize = field::DST.end;

    pub struct Packet<'a> {
        buffer: &'a [u8],
    }

    impl<'a> Packet<'a> {
        pub fn new_checked(buffer: &'a [u8]) -> Result<Self> {
            if buffer.len() < MIN_HEADER_LEN {
                return Err(Error::PacketTooShort);
            }
            Ok(Self { buffer })
        }

        pub fn version(&self) -> u8 {
            self.buffer[field::VERSION_IHL.start] >> 4
        }

        pub fn header_len(&self) -> usize {
            (self.buffer[field::VERSION_IHL.start] & 0x0f) as usize * 4
        }

        pub fn total_len(&self) -> u16 {
            read_u16(&self.buffer[field::TOTAL_LEN])
        }

        pub fn protocol(&self) -> u8 {
            self.buffer[field::PROTOCOL.start]
        }

        pub fn src(&self) -> u32 {
            read_u32(&self.buffer[field::SRC])
        }

        pub fn dst(&self) -> u32 {
            read_u32(&self.buffer[field::DST])
        }

        #[allow(dead_code)]
        pub fn header_bytes(&self) -> &'a [u8] {
            let header_len = self.header_len();
            &self.buffer[..header_len]
        }
    }

    pub struct PacketMut<'a> {
        buffer: &'a mut [u8],
    }

    impl<'a> PacketMut<'a> {
        pub fn new_unchecked(buffer: &'a mut [u8]) -> Self {
            Self { buffer }
        }

        pub fn set_version_ihl(&mut self, version: u8, ihl: u8) {
            self.buffer[field::VERSION_IHL.start] = (version << 4) | (ihl & 0x0f);
        }

        pub fn set_tos(&mut self, value: u8) {
            self.buffer[field::TOS.start] = value;
        }

        pub fn set_total_len(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::TOTAL_LEN], value);
        }

        pub fn set_id(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::ID], value);
        }

        pub fn set_flags_offset(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::FLAGS_OFFSET], value);
        }

        pub fn set_ttl(&mut self, value: u8) {
            self.buffer[field::TTL.start] = value;
        }

        pub fn set_protocol(&mut self, value: u8) {
            self.buffer[field::PROTOCOL.start] = value;
        }

        pub fn set_checksum(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::CHECKSUM], value);
        }

        pub fn set_src(&mut self, value: u32) {
            write_u32(&mut self.buffer[field::SRC], value);
        }

        pub fn set_dst(&mut self, value: u32) {
            write_u32(&mut self.buffer[field::DST], value);
        }

        pub fn fill_checksum(&mut self) {
            self.set_checksum(0);
            let header_len = (self.buffer[field::VERSION_IHL.start] & 0x0f) as usize * 4;
            let checksum = crate::net::util::checksum(&self.buffer[..header_len]);
            self.set_checksum(checksum);
        }
    }

    fn read_u32(data: &[u8]) -> u32 {
        u32::from_be_bytes([data[0], data[1], data[2], data[3]])
    }

    fn write_u32(data: &mut [u8], value: u32) {
        data[..4].copy_from_slice(&value.to_be_bytes());
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IpEndpoint {
    pub addr: IpAddr,
    pub port: u16,
}

impl IpEndpoint {
    pub const fn new(addr: IpAddr, port: u16) -> Self {
        Self { addr, port }
    }

    pub const fn any(port: u16) -> Self {
        Self {
            addr: IpAddr(0),
            port,
        }
    }

    pub const fn unspecified() -> Self {
        Self::any(0)
    }

    pub fn is_unspecified(&self) -> bool {
        self.addr.0 == 0 && self.port == 0
    }
}

pub fn ingress(_dev: &NetDevice, data: &[u8]) -> Result<()> {
    let header = wire::Packet::new_checked(data)?;
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

    let total_len = header.total_len() as usize;
    if total_len > data.len() {
        return Err(Error::PacketTruncated);
    }
    if total_len < hlen {
        return Err(Error::InvalidLength);
    }

    let src = IpAddr(header.src());
    let dst = IpAddr(header.dst());

    trace!(
        IP,
        "[ip] received packet: {:?} -> {:?}, proto={}",
        src.to_bytes(),
        dst.to_bytes(),
        header.protocol()
    );

    let payload = &data[hlen..total_len];
    match header.protocol() {
        IpHeader::ICMP => icmp::ingress(src, dst, payload),
        IpHeader::TCP => tcp::ingress(src, dst, payload),
        IpHeader::UDP => udp::ingress(src, dst, payload),
        _ => Err(Error::UnsupportedProtocol),
    }
}

pub fn egress(dev: &NetDevice, protocol: u8, src: IpAddr, dst: IpAddr, data: &[u8]) -> Result<()> {
    let total_len = size_of::<IpHeader>() + data.len();
    if total_len > 65535 {
        return Err(Error::PacketTooLarge);
    }
    let mut packet = alloc::vec![0u8; total_len];
    {
        let mut header = wire::PacketMut::new_unchecked(&mut packet);
        header.set_version_ihl(4, 5);
        header.set_tos(0);
        header.set_total_len(total_len as u16);
        header.set_id(0);
        header.set_flags_offset(0);
        header.set_ttl(64);
        header.set_protocol(protocol);
        header.set_checksum(0);
        header.set_src(src.0);
        header.set_dst(dst.0);
        header.fill_checksum();
    }
    packet[size_of::<IpHeader>()..].copy_from_slice(data);

    trace!(
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

    let route = route::lookup(dst)?;
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

pub fn egress_route(dst: IpAddr, protocol: u8, payload: &[u8]) -> Result<()> {
    if dst.0 == IpAddr::LOOPBACK.0 {
        let dev = net_device_by_name("lo").ok_or(Error::DeviceNotFound)?;
        return egress(&dev, protocol, IpAddr::LOOPBACK, dst, payload);
    }

    if let Some(route) = route::lookup(dst) {
        let dev = net_device_by_name(route.dev).ok_or(Error::DeviceNotFound)?;
        let src = get_source_address(dst).unwrap_or(IpAddr::LOOPBACK);

        let next_hop = route.gateway.unwrap_or(dst);
        let mac = arp::resolve(dev.name(), next_hop, src, crate::param::TICK_HZ)
            .map_err(|_| Error::Timeout)?;
        let mut dev_clone = dev.clone();
        let total_len = core::mem::size_of::<super::ip::IpHeader>() + payload.len();
        let mut ip_packet = alloc::vec![0u8; total_len];
        {
            let mut hdr = wire::PacketMut::new_unchecked(&mut ip_packet);
            hdr.set_version_ihl(4, 5);
            hdr.set_tos(0);
            hdr.set_total_len(total_len as u16);
            hdr.set_id(0);
            hdr.set_flags_offset(0);
            hdr.set_ttl(64);
            hdr.set_protocol(protocol);
            hdr.set_checksum(0);
            hdr.set_src(src.0);
            hdr.set_dst(dst.0);
            hdr.fill_checksum();
        }
        ip_packet[core::mem::size_of::<super::ip::IpHeader>()..].copy_from_slice(payload);
        return ethernet::egress(&mut dev_clone, mac, ethernet::ETHERTYPE_IPV4, &ip_packet);
    }

    Err(Error::NoSuchNode)
}

pub fn ip_init() {
    println!("[net] IP layer init");
    net_protocol_register(ProtocolType::IP, ingress);
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

#[cfg(test)]
mod tests {
    use super::{ingress, wire, IpHeader};
    use crate::error::Error;
    use crate::net::device::{
        NetDevice, NetDeviceConfig, NetDeviceFlags, NetDeviceOps, NetDeviceType,
    };
    use crate::net::ethernet::MacAddr;
    use crate::net::util::checksum;

    fn dummy_dev() -> NetDevice {
        NetDevice::new(NetDeviceConfig {
            name: "dummy",
            dev_type: NetDeviceType::Ethernet,
            mtu: 1500,
            flags: NetDeviceFlags::UP,
            header_len: wire::MIN_HEADER_LEN as u16,
            addr_len: 6,
            hw_addr: MacAddr::ZERO,
            ops: NetDeviceOps {
                transmit: |_dev, _data| Ok(()),
                open: |_dev| Ok(()),
                close: |_dev| Ok(()),
            },
        })
    }

    #[test_case]
    fn invalid_version() {
        let dev = dummy_dev();
        let mut data = [0u8; wire::MIN_HEADER_LEN];
        data[0] = 0x55; // version=5, ihl=5
        let err = ingress(&dev, &data).unwrap_err();
        assert_eq!(err, Error::InvalidVersion);
    }

    #[test_case]
    fn invalid_header_len() {
        let dev = dummy_dev();
        let mut data = [0u8; wire::MIN_HEADER_LEN];
        data[0] = 0x44; // version=4, ihl=4 -> 16 bytes
        let err = ingress(&dev, &data).unwrap_err();
        assert_eq!(err, Error::InvalidHeaderLen);
    }

    #[test_case]
    fn total_len_too_large() {
        let dev = dummy_dev();
        let mut data = [0u8; wire::MIN_HEADER_LEN];
        data[0] = 0x45; // version=4, ihl=5
        data[9] = IpHeader::UDP;
        let total_len = (wire::MIN_HEADER_LEN as u16) + 1;
        data[2..4].copy_from_slice(&total_len.to_be_bytes());
        let csum = checksum(&data);
        data[10..12].copy_from_slice(&csum.to_be_bytes());

        let err = ingress(&dev, &data).unwrap_err();
        assert_eq!(err, Error::PacketTruncated);
    }

    #[test_case]
    fn total_len_smaller_than_header() {
        let dev = dummy_dev();
        let mut data = [0u8; wire::MIN_HEADER_LEN];
        data[0] = 0x45; // version=4, ihl=5
        data[9] = IpHeader::UDP;
        let total_len = 19u16;
        data[2..4].copy_from_slice(&total_len.to_be_bytes());
        let csum = checksum(&data);
        data[10..12].copy_from_slice(&csum.to_be_bytes());

        let err = ingress(&dev, &data).unwrap_err();
        assert_eq!(err, Error::InvalidLength);
    }
}
