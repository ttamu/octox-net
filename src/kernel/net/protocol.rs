use crate::{
    error::{Error, Result},
    net::{device::NetDevice, device::NetDeviceFlags},
    spinlock::Mutex,
};
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ProtocolType {
    IP = 0x0800,
    ARP = 0x0806,
    IPV6 = 0x86DD,
}
pub struct Protocol {
    ptype: ProtocolType,
    handler: fn(&NetDevice, &[u8]) -> Result<()>,
}

static PROTOCOLS: Mutex<Vec<Protocol>> = Mutex::new(Vec::new(), "net_protocols");

pub fn net_protocol_register(ptype: ProtocolType, handler: fn(&NetDevice, &[u8]) -> Result<()>) {
    let mut protocols = PROTOCOLS.lock();
    protocols.push(Protocol { ptype, handler });
    drop(protocols);
    crate::println!("[net] Registered protocol: {:?}", ptype);
}

pub fn net_protocol_handler(dev: &NetDevice, ptype: ProtocolType, data: &[u8]) -> Result<()> {
    let handler = {
        let protocols = PROTOCOLS.lock();
        protocols
            .iter()
            .find(|p| p.ptype == ptype)
            .map(|p| p.handler)
    };
    match handler {
        Some(h) => h(dev, data),
        None => Err(Error::ProtocolNotFound),
    }
}

pub fn net_input_handler(dev: &NetDevice, data: &[u8]) -> Result<()> {
    crate::trace!(DRIVER, "[net] input {} bytes from {}", data.len(), dev.name());

    if dev.flags().contains(NetDeviceFlags::LOOPBACK) {
        return net_protocol_handler(dev, ProtocolType::IP, data);
    }

    Err(Error::UnsupportedDevice)
}
