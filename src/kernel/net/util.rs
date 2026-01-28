/// host to network 16bit
#[inline]
pub fn hton16(n: u16) -> u16 {
    n.to_be()
}

/// network to host 16bit
#[inline]
pub fn ntoh16(n: u16) -> u16 {
    u16::from_be(n)
}

/// host to network 32bit
#[inline]
pub fn hton32(n: u32) -> u32 {
    n.to_be()
}

/// network to host 32bit
#[inline]
pub fn ntoh32(n: u32) -> u32 {
    u32::from_be(n)
}

/// Read a u16 from a slice in network byte order.
#[inline]
pub fn read_u16(data: &[u8]) -> u16 {
    u16::from_be_bytes([data[0], data[1]])
}

/// Read an i32 from a slice in network byte order.
#[inline]
pub fn read_i32(data: &[u8]) -> i32 {
    i32::from_be_bytes([data[0], data[1], data[2], data[3]])
}

/// Write a u16 to a slice in network byte order.
#[inline]
pub fn write_u16(data: &mut [u8], value: u16) {
    data[..2].copy_from_slice(&value.to_be_bytes());
}

/// Write an i32 to a slice in network byte order.
#[inline]
pub fn write_i32(data: &mut [u8], value: i32) {
    data[..4].copy_from_slice(&value.to_be_bytes());
}

pub fn checksum_raw(data: &[u8]) -> u16 {
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
    sum as u16
}

pub fn checksum(data: &[u8]) -> u16 {
    !checksum_raw(data)
}

pub fn verify_checksum(data: &[u8]) -> bool {
    checksum(data) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn endian_roundtrip() {
        let v16 = 0x1234u16;
        let v32 = 0x1234_5678u32;
        assert_eq!(ntoh16(hton16(v16)), v16);
        assert_eq!(ntoh32(hton32(v32)), v32);
    }

    #[test_case]
    fn checksum_verification() {
        let payload = [0x12u8, 0x34, 0x56, 0x78];
        let sum = checksum(&payload);
        let packet = [
            payload[0],
            payload[1],
            payload[2],
            payload[3],
            (sum >> 8) as u8,
            sum as u8,
        ];
        assert!(verify_checksum(&packet));
    }
}
