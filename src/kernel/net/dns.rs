use super::{
    ip::{IpAddr, IpEndpoint},
    udp,
};
use crate::error::{Error, Result};
extern crate alloc;
use alloc::{vec, vec::Vec};

const DNS_TYPE_A: u16 = 1; // IPv4 address
const DNS_CLASS_IN: u16 = 1; // Internet class
const DNS_SERVER: IpAddr = IpAddr(0x0808_0808);
const DNS_PORT: u16 = 53;

mod wire {
    use crate::error::{Error, Result};
    use crate::net::util::{read_u16, write_u16};

    pub mod field {
        pub type Field = core::ops::Range<usize>;

        pub const ID: Field = 0..2;
        pub const FLAGS: Field = 2..4;
        pub const QDCOUNT: Field = 4..6;
        pub const ANCOUNT: Field = 6..8;
        pub const NSCOUNT: Field = 8..10;
        pub const ARCOUNT: Field = 10..12;
    }

    pub const HEADER_LEN: usize = field::ARCOUNT.end;

    pub struct Header<'a> {
        buffer: &'a [u8],
    }

    impl<'a> Header<'a> {
        pub fn new_checked(buffer: &'a [u8]) -> Result<Self> {
            if buffer.len() < HEADER_LEN {
                return Err(Error::PacketTooShort);
            }
            Ok(Self { buffer })
        }

        pub fn id(&self) -> u16 {
            read_u16(&self.buffer[field::ID])
        }

        pub fn flags(&self) -> u16 {
            read_u16(&self.buffer[field::FLAGS])
        }

        pub fn qdcount(&self) -> u16 {
            read_u16(&self.buffer[field::QDCOUNT])
        }

        pub fn ancount(&self) -> u16 {
            read_u16(&self.buffer[field::ANCOUNT])
        }

        #[allow(dead_code)]
        pub fn nscount(&self) -> u16 {
            read_u16(&self.buffer[field::NSCOUNT])
        }

        #[allow(dead_code)]
        pub fn arcount(&self) -> u16 {
            read_u16(&self.buffer[field::ARCOUNT])
        }
    }

    pub struct HeaderMut<'a> {
        buffer: &'a mut [u8],
    }

    impl<'a> HeaderMut<'a> {
        pub fn new_unchecked(buffer: &'a mut [u8]) -> Self {
            Self { buffer }
        }

        pub fn set_id(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::ID], value);
        }

        pub fn set_flags(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::FLAGS], value);
        }

        pub fn set_qdcount(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::QDCOUNT], value);
        }

        pub fn set_ancount(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::ANCOUNT], value);
        }

        pub fn set_nscount(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::NSCOUNT], value);
        }

        pub fn set_arcount(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::ARCOUNT], value);
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
    let mut packet = vec![0u8; wire::HEADER_LEN];
    {
        let mut header = wire::HeaderMut::new_unchecked(&mut packet);
        header.set_id(id);
        header.set_flags(0x0100);
        header.set_qdcount(1);
        header.set_ancount(0);
        header.set_nscount(0);
        header.set_arcount(0);
    }
    encode_domain_name(domain, &mut packet);
    packet.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

    packet
}

fn parse_dns_response(data: &[u8]) -> Result<IpAddr> {
    let header = wire::Header::new_checked(data)?;
    let ancount = header.ancount();

    crate::trace!(
        DNS,
        "[dns] Response: id={:04x}, flags={:04x}, questions={}, answers={}",
        header.id(),
        header.flags(),
        header.qdcount(),
        ancount
    );

    if ancount == 0 {
        return Err(Error::NotFound);
    }

    let mut offset = wire::HEADER_LEN;

    let qdcount = header.qdcount();
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
    let sockfd = udp::socket_alloc()?;
    let local = IpEndpoint::any(0);
    if let Err(err) = udp::socket_bind(sockfd, local) {
        let _ = udp::socket_free(sockfd);
        return Err(err);
    }

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

    let dns_endpoint = IpEndpoint::new(DNS_SERVER, DNS_PORT);
    if let Err(err) = udp::socket_sendto(sockfd, dns_endpoint, &query) {
        let _ = udp::socket_free(sockfd);
        return Err(err);
    }

    let mut buf = alloc::vec![0u8; 512];
    let max_attempts = 100;
    for attempt in 0..max_attempts {
        crate::net::poll();

        match udp::socket_recvfrom(sockfd, &mut buf) {
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
                        udp::socket_free(sockfd)?;
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
                udp::socket_free(sockfd)?;
                return Err(e);
            }
        }
    }

    udp::socket_free(sockfd)?;
    Err(Error::Timeout)
}

#[cfg(test)]
mod tests {
    use super::{parse_dns_response, wire};
    use crate::error::Error;
    use alloc::vec;

    #[test_case]
    fn header_too_short() {
        let data = [0u8; wire::HEADER_LEN - 1];
        let err = wire::Header::new_checked(&data).err().unwrap();
        assert_eq!(err, Error::PacketTooShort);
    }

    #[test_case]
    fn qdcount_incomplete() {
        let mut data = vec![0u8; wire::HEADER_LEN];
        {
            let mut header = wire::HeaderMut::new_unchecked(&mut data);
            header.set_qdcount(1);
            header.set_ancount(1);
        }
        let err = parse_dns_response(&data).unwrap_err();
        assert_eq!(err, Error::PacketTooShort);
    }
}
