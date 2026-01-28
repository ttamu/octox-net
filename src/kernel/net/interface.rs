use super::ip::IpAddr;
use crate::error::Result;
use crate::net::device::net_device_with_mut;

#[derive(Debug, Clone)]
pub struct NetInterface {
    pub family: u16, // AF_INET = 2
    pub addr: IpAddr,
    pub netmask: IpAddr,
    pub broadcast: IpAddr,
}

impl NetInterface {
    pub fn new(addr: IpAddr, netmask: IpAddr) -> Self {
        let broadcast = IpAddr(addr.0 | !netmask.0);
        NetInterface {
            family: 2,
            addr,
            netmask,
            broadcast,
        }
    }
}

pub fn net_interface_setup(dev_name: &str, addr: IpAddr, netmask: IpAddr) -> Result<()> {
    net_device_with_mut(dev_name, |dev| {
        let iface = NetInterface::new(addr, netmask);
        dev.add_interface(iface);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn new_sets_broadcast_and_family() {
        let iface = NetInterface::new(IpAddr::new(192, 168, 1, 10), IpAddr::new(255, 255, 255, 0));
        assert_eq!(iface.broadcast, IpAddr::new(192, 168, 1, 255));
        assert_eq!(iface.family, 2);
    }
}
