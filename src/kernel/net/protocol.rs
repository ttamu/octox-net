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

struct ProtocolRegistry {
    protocols: Mutex<Vec<Protocol>>,
}

impl ProtocolRegistry {
    const fn new() -> Self {
        Self {
            protocols: Mutex::new(Vec::new(), "net_protocols"),
        }
    }

    fn register(&self, ptype: ProtocolType, handler: fn(&NetDevice, &[u8]) -> Result<()>) {
        let mut protocols = self.protocols.lock();
        protocols.push(Protocol { ptype, handler });
        drop(protocols);
        crate::println!("[net] Registered protocol: {:?}", ptype);
    }

    fn handler(&self, dev: &NetDevice, ptype: ProtocolType, data: &[u8]) -> Result<()> {
        let handler = {
            let protocols = self.protocols.lock();
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

    fn ingress(&self, dev: &NetDevice, data: &[u8]) -> Result<()> {
        crate::trace!(
            DRIVER,
            "[net] ingress {} bytes from {}",
            data.len(),
            dev.name()
        );

        if dev.flags().contains(NetDeviceFlags::LOOPBACK) {
            return self.handler(dev, ProtocolType::IP, data);
        }

        Err(Error::UnsupportedDevice)
    }
}

static PROTOCOLS: ProtocolRegistry = ProtocolRegistry::new();

pub fn net_protocol_register(ptype: ProtocolType, handler: fn(&NetDevice, &[u8]) -> Result<()>) {
    PROTOCOLS.register(ptype, handler)
}

pub fn net_protocol_handler(dev: &NetDevice, ptype: ProtocolType, data: &[u8]) -> Result<()> {
    PROTOCOLS.handler(dev, ptype, data)
}

pub fn net_ingress_handler(dev: &NetDevice, data: &[u8]) -> Result<()> {
    PROTOCOLS.ingress(dev, data)
}
