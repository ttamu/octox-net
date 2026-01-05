extern crate alloc;
use crate::condvar::Condvar;
use crate::error::{Error, Result};
use crate::net::device::{NetDevice, NetDeviceFlags};
use crate::net::ethernet::{output as eth_output, MacAddr, ETHERTYPE_ARP};
use crate::net::ip::IpAddr;
use crate::net::util::{hton16, ntoh16, parse_header, parse_header_mut};
use crate::spinlock::Mutex;
use alloc::vec::Vec;

const ARP_HTYPE_ETHERNET: u16 = 1;
const ARP_PTYPE_IPV4: u16 = 0x0800;
const ARP_HLEN_ETH: u8 = 6;
const ARP_PLEN_IPV4: u8 = 4;
const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ArpPacket {
    htype: u16,   // Hardware Type (1=Ethernet)
    ptype: u16,   // Protocol Type (0x0800=IPv4)
    hlen: u8,     // Hardware Address Length (6)
    plen: u8,     // Protocol Address Length (4)
    oper: u16,    // Operation (1=Request, 2=Reply)
    sha: [u8; 6], // Sender Hardware Address
    spa: u32,     // Sender Protocol Address
    tha: [u8; 6], // Target Hardware Address
    tpa: u32,     // Target Protocol Address
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
    crate::println!("[arp] insert {:?} -> {}", ip.to_bytes(), mac);
    ARP_CV.notify_all();
}

pub fn input(dev: &NetDevice, data: &[u8]) -> Result<()> {
    let pkt = parse_header::<ArpPacket>(data)?;
    if ntoh16(pkt.htype) != ARP_HTYPE_ETHERNET
        || ntoh16(pkt.ptype) != ARP_PTYPE_IPV4
        || pkt.hlen != ARP_HLEN_ETH
        || pkt.plen != ARP_PLEN_IPV4
    {
        return Err(Error::UnsupportedProtocol);
    }
    let oper = ntoh16(pkt.oper);
    let sender_ip = IpAddr(u32::from_be(pkt.spa));
    let sender_mac = MacAddr(pkt.sha);
    let target_ip = IpAddr(u32::from_be(pkt.tpa));

    crate::println!(
        "[arp] oper={} sender={:?} target={:?}",
        oper,
        sender_ip.to_bytes(),
        target_ip.to_bytes()
    );

    match oper {
        ARP_OP_REPLY => {
            crate::println!("[arp] reply from {:?}", sender_ip.to_bytes());
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
    let mut buf = [0u8; core::mem::size_of::<ArpPacket>()];
    let pkt = parse_header_mut::<ArpPacket>(&mut buf)?;
    pkt.htype = hton16(ARP_HTYPE_ETHERNET);
    pkt.ptype = hton16(ARP_PTYPE_IPV4);
    pkt.hlen = ARP_HLEN_ETH;
    pkt.plen = ARP_PLEN_IPV4;
    pkt.oper = hton16(ARP_OP_REPLY);
    pkt.sha = dev.hw_addr.0;
    pkt.spa = src_ip.0.to_be();
    pkt.tha = dst_mac.0;
    pkt.tpa = dst_ip.0.to_be();

    let mut dev_clone = dev.clone();
    eth_output(&mut dev_clone, dst_mac, ETHERTYPE_ARP, &buf)
}

fn send_request(dev: &mut NetDevice, target_ip: IpAddr, sender_ip: IpAddr) -> Result<()> {
    let mut buf = [0u8; core::mem::size_of::<ArpPacket>()];
    let pkt = parse_header_mut::<ArpPacket>(&mut buf)?;
    pkt.htype = hton16(ARP_HTYPE_ETHERNET);
    pkt.ptype = hton16(ARP_PTYPE_IPV4);
    pkt.hlen = ARP_HLEN_ETH;
    pkt.plen = ARP_PLEN_IPV4;
    pkt.oper = hton16(ARP_OP_REQUEST);
    pkt.sha = dev.hw_addr.0;
    pkt.spa = sender_ip.0.to_be();
    pkt.tha = [0; 6];
    pkt.tpa = target_ip.0.to_be();

    eth_output(dev, MacAddr::BROADCAST, ETHERTYPE_ARP, &buf)
}

pub fn resolve(
    dev_name: &str,
    target_ip: IpAddr,
    sender_ip: IpAddr,
    timeout_ticks: usize,
) -> Result<MacAddr> {
    if let Some(mac) = lookup(target_ip) {
        crate::println!("[arp] cache hit {:?}", mac);
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
        crate::println!(
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
            crate::println!("[arp] resolved {:?} -> {:02x?}", target_ip.to_bytes(), mac);
            return Ok(mac);
        }
        let elapsed = *crate::trap::TICKS.lock() - start;
        if elapsed > timeout_ticks {
            crate::println!("[arp] timeout waiting reply");
            return Err(Error::Timeout);
        }
        crate::proc::yielding();
    }
}
