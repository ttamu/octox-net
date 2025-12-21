extern crate alloc;
use crate::error::{Error, Result};
use crate::net::device::{NetDevice, NetDeviceFlags};
use crate::net::protocol::{net_protocol_handler, ProtocolType};
use crate::net::util::ntoh16;

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
    if data.len() < EthHeader::LEN {
        return Err(Error::PacketTooShort);
    }
    let hdr = unsafe { &*(data.as_ptr() as *const EthHeader) };
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

pub fn output(dev: &mut NetDevice, dst_mac: [u8; 6], ethertype: u16, payload: &[u8]) -> Result<()> {
    if !dev.flags().contains(NetDeviceFlags::UP) {
        return Err(Error::NotConnected);
    }
    let mut frame = alloc::vec![0u8; EthHeader::LEN + payload.len()];
    {
        let hdr = unsafe { &mut *(frame.as_mut_ptr() as *mut EthHeader) };
        hdr.dst = dst_mac;
        hdr.src = dev.hw_addr;
        hdr.ethertype = ethertype.to_be();
    }
    frame[EthHeader::LEN..].copy_from_slice(payload);
    dev.transmit(&frame)
}
