extern crate alloc;
use crate::condvar::Condvar;
use crate::error::{Error, Result};
use crate::net::device::{NetDevice, NetDeviceFlags};
use crate::net::ethernet::{output as eth_output, MacAddr, ETHERTYPE_ARP};
use crate::net::ip::IpAddr;
use crate::spinlock::Mutex;
use alloc::vec::Vec;

const ARP_HTYPE_ETHERNET: u16 = 1;
const ARP_PTYPE_IPV4: u16 = 0x0800;
const ARP_HLEN_ETH: u8 = 6;
const ARP_PLEN_IPV4: u8 = 4;
const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;

mod wire {
    use crate::error::{Error, Result};
    use crate::net::util::{read_u16, write_u16};

    pub mod field {
        pub type Field = core::ops::Range<usize>;

        pub const HTYPE: Field = 0..2;
        pub const PTYPE: Field = 2..4;
        pub const HLEN: Field = 4..5;
        pub const PLEN: Field = 5..6;
        pub const OPER: Field = 6..8;
        pub const SHA: Field = 8..14;
        pub const SPA: Field = 14..18;
        pub const THA: Field = 18..24;
        pub const TPA: Field = 24..28;
    }

    pub const PACKET_LEN: usize = field::TPA.end;

    pub struct Packet<'a> {
        buffer: &'a [u8],
    }

    impl<'a> Packet<'a> {
        pub fn new_checked(buffer: &'a [u8]) -> Result<Self> {
            if buffer.len() < PACKET_LEN {
                return Err(Error::PacketTooShort);
            }
            Ok(Self { buffer })
        }

        pub fn htype(&self) -> u16 {
            read_u16(&self.buffer[field::HTYPE])
        }

        pub fn ptype(&self) -> u16 {
            read_u16(&self.buffer[field::PTYPE])
        }

        pub fn hlen(&self) -> u8 {
            self.buffer[field::HLEN.start]
        }

        pub fn plen(&self) -> u8 {
            self.buffer[field::PLEN.start]
        }

        pub fn oper(&self) -> u16 {
            read_u16(&self.buffer[field::OPER])
        }

        pub fn sha(&self) -> [u8; 6] {
            let mut sha = [0u8; 6];
            sha.copy_from_slice(&self.buffer[field::SHA]);
            sha
        }

        pub fn spa(&self) -> u32 {
            read_u32(&self.buffer[field::SPA])
        }

        #[allow(dead_code)]
        pub fn tha(&self) -> [u8; 6] {
            let mut tha = [0u8; 6];
            tha.copy_from_slice(&self.buffer[field::THA]);
            tha
        }

        pub fn tpa(&self) -> u32 {
            read_u32(&self.buffer[field::TPA])
        }
    }

    pub struct PacketMut<'a> {
        buffer: &'a mut [u8],
    }

    impl<'a> PacketMut<'a> {
        pub fn new_unchecked(buffer: &'a mut [u8]) -> Self {
            Self { buffer }
        }

        pub fn set_htype(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::HTYPE], value);
        }

        pub fn set_ptype(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::PTYPE], value);
        }

        pub fn set_hlen(&mut self, value: u8) {
            self.buffer[field::HLEN.start] = value;
        }

        pub fn set_plen(&mut self, value: u8) {
            self.buffer[field::PLEN.start] = value;
        }

        pub fn set_oper(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::OPER], value);
        }

        pub fn set_sha(&mut self, value: [u8; 6]) {
            self.buffer[field::SHA].copy_from_slice(&value);
        }

        pub fn set_spa(&mut self, value: u32) {
            write_u32(&mut self.buffer[field::SPA], value);
        }

        pub fn set_tha(&mut self, value: [u8; 6]) {
            self.buffer[field::THA].copy_from_slice(&value);
        }

        pub fn set_tpa(&mut self, value: u32) {
            write_u32(&mut self.buffer[field::TPA], value);
        }
    }

    fn read_u32(data: &[u8]) -> u32 {
        u32::from_be_bytes([data[0], data[1], data[2], data[3]])
    }

    fn write_u32(data: &mut [u8], value: u32) {
        data[..4].copy_from_slice(&value.to_be_bytes());
    }
}
#[derive(Clone, Copy, Debug)]
struct ArpEntry {
    ip: IpAddr,
    mac: MacAddr,
    valid: bool,
}

static ARP_TABLE: Mutex<Vec<ArpEntry>> = Mutex::new(Vec::new(), "arp_table");
static ARP_CV: Condvar = Condvar::new();

fn lookup(ip: IpAddr) -> Option<MacAddr> {
    let table = ARP_TABLE.lock();
    table
        .iter()
        .find(|e| e.valid && e.ip.0 == ip.0)
        .map(|e| e.mac)
}

fn insert(ip: IpAddr, mac: MacAddr) {
    {
        let mut table = ARP_TABLE.lock();
        if let Some(e) = table.iter_mut().find(|e| e.ip.0 == ip.0) {
            e.mac = mac;
            e.valid = true;
        } else {
            table.push(ArpEntry {
                ip,
                mac,
                valid: true,
            });
        }
    }
    crate::trace!(ARP, "[arp] insert {:?} -> {}", ip.to_bytes(), mac);
    ARP_CV.notify_all();
}

pub fn input(dev: &NetDevice, data: &[u8]) -> Result<()> {
    let pkt = wire::Packet::new_checked(data)?;
    if pkt.htype() != ARP_HTYPE_ETHERNET
        || pkt.ptype() != ARP_PTYPE_IPV4
        || pkt.hlen() != ARP_HLEN_ETH
        || pkt.plen() != ARP_PLEN_IPV4
    {
        return Err(Error::UnsupportedProtocol);
    }
    let oper = pkt.oper();
    let sender_ip = IpAddr(pkt.spa());
    let sender_mac = MacAddr(pkt.sha());
    let target_ip = IpAddr(pkt.tpa());

    crate::trace!(
        ARP,
        "[arp] oper={} sender={:?} target={:?}",
        oper,
        sender_ip.to_bytes(),
        target_ip.to_bytes()
    );

    match oper {
        ARP_OP_REPLY => {
            crate::trace!(ARP, "[arp] reply from {:?}", sender_ip.to_bytes());
            insert(sender_ip, sender_mac);
        }
        ARP_OP_REQUEST => {
            if let Some(iface) = dev.interfaces.iter().find(|i| i.addr.0 == target_ip.0) {
                send_reply(dev, sender_mac, sender_ip, iface.addr)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn send_reply(dev: &NetDevice, dst_mac: MacAddr, dst_ip: IpAddr, src_ip: IpAddr) -> Result<()> {
    let mut buf = [0u8; wire::PACKET_LEN];
    let mut pkt = wire::PacketMut::new_unchecked(&mut buf);
    pkt.set_htype(ARP_HTYPE_ETHERNET);
    pkt.set_ptype(ARP_PTYPE_IPV4);
    pkt.set_hlen(ARP_HLEN_ETH);
    pkt.set_plen(ARP_PLEN_IPV4);
    pkt.set_oper(ARP_OP_REPLY);
    pkt.set_sha(dev.hw_addr.0);
    pkt.set_spa(src_ip.0);
    pkt.set_tha(dst_mac.0);
    pkt.set_tpa(dst_ip.0);

    let mut dev_clone = dev.clone();
    eth_output(&mut dev_clone, dst_mac, ETHERTYPE_ARP, &buf)
}

fn send_request(dev: &mut NetDevice, target_ip: IpAddr, sender_ip: IpAddr) -> Result<()> {
    let mut buf = [0u8; wire::PACKET_LEN];
    let mut pkt = wire::PacketMut::new_unchecked(&mut buf);
    pkt.set_htype(ARP_HTYPE_ETHERNET);
    pkt.set_ptype(ARP_PTYPE_IPV4);
    pkt.set_hlen(ARP_HLEN_ETH);
    pkt.set_plen(ARP_PLEN_IPV4);
    pkt.set_oper(ARP_OP_REQUEST);
    pkt.set_sha(dev.hw_addr.0);
    pkt.set_spa(sender_ip.0);
    pkt.set_tha([0; 6]);
    pkt.set_tpa(target_ip.0);

    eth_output(dev, MacAddr::BROADCAST, ETHERTYPE_ARP, &buf)
}

pub fn resolve(
    dev_name: &str,
    target_ip: IpAddr,
    sender_ip: IpAddr,
    timeout_ticks: usize,
) -> Result<MacAddr> {
    if let Some(mac) = lookup(target_ip) {
        crate::trace!(ARP, "[arp] cache hit {:?}", mac);
        return Ok(mac);
    }
    {
        let mut list = crate::net::device::NET_DEVICES.lock();
        let dev = list
            .iter_mut()
            .find(|d| d.name() == dev_name)
            .ok_or(Error::DeviceNotFound)?;
        if !dev.flags().contains(NetDeviceFlags::UP) {
            return Err(Error::NotConnected);
        }
        crate::trace!(
            ARP,
            "[arp] send request who-has {:?} tell {:?}",
            target_ip.to_bytes(),
            sender_ip.to_bytes()
        );
        send_request(dev, target_ip, sender_ip)?;
    }

    let start = *crate::trap::TICKS.lock();
    loop {
        crate::net::driver::virtio_net::poll_rx();
        if let Some(mac) = lookup(target_ip) {
            crate::trace!(
                ARP,
                "[arp] resolved {:?} -> {:02x?}",
                target_ip.to_bytes(),
                mac
            );
            return Ok(mac);
        }
        let elapsed = *crate::trap::TICKS.lock() - start;
        if elapsed > timeout_ticks {
            crate::trace!(ARP, "[arp] timeout waiting reply");
            return Err(Error::Timeout);
        }
        crate::proc::yielding();
    }
}

#[cfg(test)]
mod tests {
    use super::wire;
    use crate::error::Error;

    #[test_case]
    fn packet_too_short() {
        let data = [0u8; wire::PACKET_LEN - 1];
        let err = wire::Packet::new_checked(&data).err().unwrap();
        assert_eq!(err, Error::PacketTooShort);
    }
}
