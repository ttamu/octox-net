use crate::{
    error::{Error, Result},
    net::{ethernet::MacAddr, interface::NetInterface},
    spinlock::Mutex,
};
use alloc::{string::String, vec::Vec};
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetDeviceType {
    Loopback,
    Ethernet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetDeviceFlags(pub u16);
impl NetDeviceFlags {
    pub const UP: Self = Self(0x0001);
    pub const BROADCAST: Self = Self(0x0002);
    pub const LOOPBACK: Self = Self(0x0008);
    pub const RUNNING: Self = Self(0x0040);

    pub fn contains(self, other: NetDeviceFlags) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitOr for NetDeviceFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        NetDeviceFlags(self.0 | rhs.0)
    }
}
impl BitAnd for NetDeviceFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        NetDeviceFlags(self.0 & rhs.0)
    }
}
impl BitOrAssign for NetDeviceFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}
impl BitAndAssign for NetDeviceFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}
impl Not for NetDeviceFlags {
    type Output = Self;
    fn not(self) -> Self::Output {
        NetDeviceFlags(!self.0)
    }
}

pub struct NetDeviceOps {
    pub transmit: fn(&mut NetDevice, data: &[u8]) -> Result<()>,
    pub open: fn(&mut NetDevice) -> Result<()>,
    pub close: fn(&mut NetDevice) -> Result<()>,
}

pub struct NetDeviceConfig<'a> {
    pub name: &'a str,
    pub dev_type: NetDeviceType,
    pub mtu: u16,
    pub flags: NetDeviceFlags,
    pub header_len: u16,
    pub addr_len: u16,
    pub hw_addr: MacAddr,
    pub ops: NetDeviceOps,
}

pub struct NetDevice {
    name: [u8; 16],
    pub dev_type: NetDeviceType,
    mtu: u16,
    flags: NetDeviceFlags,
    pub header_len: u16,
    pub addr_len: u16,
    pub hw_addr: MacAddr,
    ops: NetDeviceOps,
    pub interfaces: Vec<NetInterface>,
}
impl NetDevice {
    pub fn new(config: NetDeviceConfig<'_>) -> Self {
        let mut name_buf = [0u8; 16];
        let bytes = config.name.as_bytes();
        let len = bytes.len().min(15);
        name_buf[..len].copy_from_slice(&bytes[..len]);
        NetDevice {
            name: name_buf,
            dev_type: config.dev_type,
            mtu: config.mtu,
            flags: config.flags,
            header_len: config.header_len,
            addr_len: config.addr_len,
            hw_addr: config.hw_addr,
            ops: config.ops,
            interfaces: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        let end = self
            .name
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..end]).unwrap_or("")
    }

    pub fn flags(&self) -> NetDeviceFlags {
        self.flags
    }

    pub fn set_flags(&mut self, flags: NetDeviceFlags) {
        self.flags = flags;
    }

    pub fn transmit(&mut self, data: &[u8]) -> Result<()> {
        (self.ops.transmit)(self, data)
    }

    pub fn open(&mut self) -> Result<()> {
        (self.ops.open)(self)
    }

    pub fn close(&mut self) -> Result<()> {
        (self.ops.close)(self)
    }

    pub fn add_interface(&mut self, iface: NetInterface) {
        self.interfaces.push(iface);
    }

    pub fn interface_by_addr(&self, addr: u32) -> Option<&NetInterface> {
        self.interfaces.iter().find(|i| i.addr.0 == addr)
    }
}

impl core::fmt::Debug for NetDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NetDevice")
            .field("name", &String::from(self.name()))
            .field("type", &self.dev_type)
            .field("mtu", &self.mtu)
            .field("flags", &self.flags)
            .finish()
    }
}

impl Clone for NetDevice {
    fn clone(&self) -> Self {
        NetDevice {
            name: self.name,
            dev_type: self.dev_type,
            mtu: self.mtu,
            flags: self.flags,
            header_len: self.header_len,
            addr_len: self.addr_len,
            hw_addr: self.hw_addr,
            ops: NetDeviceOps {
                transmit: self.ops.transmit,
                open: self.ops.open,
                close: self.ops.close,
            },
            interfaces: self.interfaces.clone(),
        }
    }
}

struct NetDeviceRegistry {
    devices: Mutex<Vec<NetDevice>>,
}

impl NetDeviceRegistry {
    const fn new() -> Self {
        Self {
            devices: Mutex::new(Vec::new(), "net_devices"),
        }
    }

    fn register(&self, device: NetDevice) -> Result<()> {
        let mut list = self.devices.lock();
        list.push(device);
        Ok(())
    }

    fn with_mut<F, R>(&self, name: &str, mut f: F) -> Result<R>
    where
        F: FnMut(&mut NetDevice) -> R,
    {
        let mut list = self.devices.lock();
        let dev = list
            .iter_mut()
            .find(|d| d.name() == name)
            .ok_or(Error::DeviceNotFound)?;
        Ok(f(dev))
    }

    fn by_name(&self, name: &str) -> Option<NetDevice> {
        let list = self.devices.lock();
        list.iter().find(|d| d.name() == name).cloned()
    }

    fn by_index(&self, index: usize) -> Option<NetDevice> {
        let list = self.devices.lock();
        list.get(index).cloned()
    }

    fn foreach<F>(&self, mut f: F)
    where
        F: FnMut(&NetDevice),
    {
        let list = self.devices.lock();
        for dev in list.iter() {
            f(dev);
        }
    }
}

static NET_DEVICES: NetDeviceRegistry = NetDeviceRegistry::new();

pub fn net_device_register(device: NetDevice) -> Result<()> {
    NET_DEVICES.register(device)
}

pub fn net_device_with_mut<F, R>(name: &str, f: F) -> Result<R>
where
    F: FnMut(&mut NetDevice) -> R,
{
    NET_DEVICES.with_mut(name, f)
}

pub fn net_device_by_name(name: &str) -> Option<NetDevice> {
    NET_DEVICES.by_name(name)
}

pub fn net_device_by_index(index: usize) -> Option<NetDevice> {
    NET_DEVICES.by_index(index)
}

pub fn net_device_foreach<F>(f: F)
where
    F: FnMut(&NetDevice),
{
    NET_DEVICES.foreach(f)
}
