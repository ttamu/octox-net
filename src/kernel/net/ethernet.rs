extern crate alloc;
use crate::error::{Error, Result};
use crate::net::device::{NetDevice, NetDeviceFlags};
use crate::net::protocol::{net_protocol_handler, ProtocolType};
use crate::net::util::{ntoh16, parse_header, parse_header_mut};
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: Self = MacAddr([0xFF; 6]);
    pub const ZERO: Self = MacAddr([0x00; 6]);

    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xFF; 6]
    }

    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EthHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
}

impl EthHeader {
    pub const LEN: usize = core::mem::size_of::<EthHeader>();
}

pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV4: u16 = 0x0800;

pub fn input(dev: &NetDevice, data: &[u8]) -> Result<()> {
    let hdr = parse_header::<EthHeader>(data)?;
    let etype = ntoh16(hdr.ethertype);

    crate::println!(
        "[ether] input: ethertype=0x{:04x}, len={}",
        etype,
        data.len()
    );

    let payload = &data[EthHeader::LEN..];
    match etype {
        ETHERTYPE_ARP => crate::net::arp::input(dev, payload),
        ETHERTYPE_IPV4 => net_protocol_handler(dev, ProtocolType::IP, payload),
        _ => {
            crate::println!("[ether] unsupported ethertype: 0x{:04x}", etype);
            Err(Error::UnsupportedProtocol)
        }
    }
}

pub fn output(dev: &mut NetDevice, dst_mac: MacAddr, ethertype: u16, payload: &[u8]) -> Result<()> {
    if !dev.flags().contains(NetDeviceFlags::UP) {
        return Err(Error::NotConnected);
    }
    let mut frame = alloc::vec![0u8; EthHeader::LEN + payload.len()];
    {
        let hdr = parse_header_mut::<EthHeader>(&mut frame)?;
        hdr.dst = dst_mac.0;
        hdr.src = dev.hw_addr.0;
        hdr.ethertype = ethertype.to_be();
    }
    frame[EthHeader::LEN..].copy_from_slice(payload);
    dev.transmit(&frame)
}
