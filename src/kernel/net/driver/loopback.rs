use crate::{
    error::Result,
    net::{
        device::{
            net_device_register, net_device_with_mut, NetDevice, NetDeviceFlags, NetDeviceOps,
            NetDeviceType,
        },
        interface::NetInterface,
        ip::IpAddr,
        protocol,
    },
};

const LOOPBACK_MTU: u16 = u16::MAX;

fn loopback_transmit(dev: &mut NetDevice, data: &[u8]) -> Result<()> {
    crate::println!("[loopback] transmit {} bytes", data.len());
    protocol::net_input_handler(dev, data)
}

fn loopback_open(dev: &mut NetDevice) -> Result<()> {
    crate::println!("[loopback] device opened");
    dev.set_flags(dev.flags() | NetDeviceFlags::UP | NetDeviceFlags::RUNNING);
    Ok(())
}

fn loopback_close(dev: &mut NetDevice) -> Result<()> {
    crate::println!("[loopback] device closed");
    dev.set_flags(dev.flags() & !NetDeviceFlags::RUNNING);
    Ok(())
}

pub fn loopback_init() -> Result<()> {
    let ops = NetDeviceOps {
        transmit: loopback_transmit,
        open: loopback_open,
        close: loopback_close,
    };

    let mut dev = NetDevice::new(
        "lo",
        NetDeviceType::Loopback,
        LOOPBACK_MTU,
        NetDeviceFlags::LOOPBACK | NetDeviceFlags::BROADCAST,
        0,
        0,
        crate::net::ethernet::MacAddr([0; 6]),
        ops,
    );
    dev.open()?;
    net_device_register(dev)?;
    crate::println!("[net] Loopback device initialized");
    Ok(())
}

pub fn loopback_setup() -> Result<()> {
    net_device_with_mut("lo", |dev| {
        let iface = NetInterface::new(IpAddr::LOOPBACK, IpAddr::new(255, 0, 0, 0));
        dev.add_interface(iface);
    })?;
    crate::println!("[net] Loopback interface configured: 127.0.0.1/8");
    Ok(())
}
