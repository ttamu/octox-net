use super::{
    ip::IpAddr,
    udp::{self, UdpEndpoint},
    util::parse_header,
};
use crate::error::{Error, Result};
extern crate alloc;
use alloc::vec::Vec;

const DNS_TYPE_A: u16 = 1; // IPv4 address
const DNS_CLASS_IN: u16 = 1; // Internet class
const DNS_SERVER: IpAddr = IpAddr(0x0808_0808);
const DNS_PORT: u16 = 53;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct DnsHeader {
    id: u16,      // Transaction ID
    flags: u16,   // Flags
    qdcount: u16, // Question count
    ancount: u16, // Answer count
    nscount: u16, // Authority record count
    arcount: u16, // Additional record count
}
impl DnsHeader {
    fn new_query(id: u16) -> Self {
        Self {
            id: id.to_be(),
            flags: 0x0100u16.to_be(),
            qdcount: 1u16.to_be(),
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }
}

fn encode_domain_name(domain: &str, buf: &mut Vec<u8>) {
    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
}

fn build_dns_query(domain: &str, id: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    let header = DnsHeader::new_query(id);
    let header_bytes = unsafe {
        core::slice::from_raw_parts(
            &header as *const _ as *const u8,
            core::mem::size_of::<DnsHeader>(),
        )
    };
    packet.extend_from_slice(header_bytes);
    encode_domain_name(domain, &mut packet);
    packet.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

    packet
}

fn parse_dns_response(data: &[u8]) -> Result<IpAddr> {
    let header = parse_header::<DnsHeader>(data)?;
    let ancount = u16::from_be(header.ancount);

    crate::trace!(
        DNS,
        "[dns] Response: id={:04x}, flags={:04x}, questions={}, answers={}",
        u16::from_be(header.id),
        u16::from_be(header.flags),
        u16::from_be(header.qdcount),
        ancount
    );

    if ancount == 0 {
        return Err(Error::NotFound);
    }

    let mut offset = core::mem::size_of::<DnsHeader>();

    let qdcount = u16::from_be(header.qdcount);
    for _ in 0..qdcount {
        loop {
            if offset >= data.len() {
                return Err(Error::PacketTooShort);
            }

            let len = data[offset];
            if len & 0xC0 == 0xC0 {
                offset += 2;
                break;
            }

            offset += 1;

            if len == 0 {
                break;
            }

            offset += len as usize;
        }

        offset += 4;
    }

    for i in 0..ancount {
        if offset >= data.len() {
            return Err(Error::PacketTooShort);
        }

        loop {
            if offset >= data.len() {
                return Err(Error::PacketTooShort);
            }

            let len = data[offset];

            if len & 0xC0 == 0xC0 {
                offset += 2;
                break;
            }

            offset += 1;

            if len == 0 {
                break;
            }

            offset += len as usize;
        }

        if offset + 10 > data.len() {
            return Err(Error::PacketTooShort);
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]);

        offset += 10;

        crate::trace!(
            DNS,
            "[dns] Answer {}: type={}, class={}, ttl={}, rdlen={}",
            i + 1,
            rtype,
            rclass,
            ttl,
            rdlength
        );

        if rtype == DNS_TYPE_A && rclass == DNS_CLASS_IN && rdlength == 4 {
            if offset + 4 > data.len() {
                return Err(Error::PacketTooShort);
            }

            let addr = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);

            return Ok(IpAddr(addr));
        }

        offset += rdlength as usize;
    }

    Err(Error::NotFound)
}

pub fn resolve(domain: &str) -> Result<IpAddr> {
    crate::trace!(DNS, "[dns] Resolving: {}", domain);
    crate::trace!(DNS, "[dns] Querying upstream DNS server...");
    let sockfd = udp::pcb_alloc()?;
    let local = UdpEndpoint::any(0);
    udp::bind(sockfd, local)?;

    let query_id = 0x1234; // TODO: ランダムIDを使用
    let query = build_dns_query(domain, query_id);

    crate::trace!(
        DNS,
        "[dns] Sending query to {}.{}.{}.{}:53 ({} bytes)",
        (DNS_SERVER.0 >> 24) & 0xFF,
        (DNS_SERVER.0 >> 16) & 0xFF,
        (DNS_SERVER.0 >> 8) & 0xFF,
        DNS_SERVER.0 & 0xFF,
        query.len()
    );

    let dns_endpoint = UdpEndpoint::new(DNS_SERVER, DNS_PORT);
    udp::sendto(sockfd, dns_endpoint, &query)?;

    let mut buf = alloc::vec![0u8; 512];
    let max_attempts = 100;
    for attempt in 0..max_attempts {
        crate::net::driver::virtio_net::poll_rx();

        match udp::recvfrom(sockfd, &mut buf) {
            Ok((len, src)) => {
                crate::trace!(
                    DNS,
                    "[dns] Received {} bytes from {}:{} (attempt {})",
                    len,
                    src.addr.to_bytes()[0],
                    src.port,
                    attempt + 1
                );

                match parse_dns_response(&buf[..len]) {
                    Ok(addr) => {
                        udp::pcb_release(sockfd)?;
                        crate::trace!(
                            DNS,
                            "[dns] Resolved {} to {}.{}.{}.{}",
                            domain,
                            (addr.0 >> 24) & 0xFF,
                            (addr.0 >> 16) & 0xFF,
                            (addr.0 >> 8) & 0xFF,
                            addr.0 & 0xFF
                        );
                        return Ok(addr);
                    }
                    Err(e) => {
                        crate::trace!(DNS, "[dns] Failed to parse response: {:?}", e);
                    }
                }
            }
            Err(Error::WouldBlock) => {
                let mut ticks = crate::trap::TICKS.lock();
                let ticks0 = *ticks;
                while *ticks - ticks0 < 1 {
                    ticks = crate::proc::sleep(&(*ticks) as *const _ as usize, ticks);
                }
            }
            Err(e) => {
                udp::pcb_release(sockfd)?;
                return Err(e);
            }
        }
    }

    udp::pcb_release(sockfd)?;
    Err(Error::Timeout)
}
