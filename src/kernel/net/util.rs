// host to network 16bit
#[inline]
pub fn hton16(n: u16) -> u16 {
    n.to_be()
}

// network to host 16bit
#[inline]
pub fn ntoh16(n: u16) -> u16 {
    u16::from_be(n)
}

// host to network 32bit
#[inline]
pub fn hton32(n: u32) -> u32 {
    n.to_be()
}

// network to host 32bit
#[inline]
pub fn ntoh32(n: u32) -> u32 {
    u32::from_be(n)
}

// internet checksum (RFC1071)
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn verify_checksum(data: &[u8]) -> bool {
    checksum(data) == 0
}
