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

use crate::error::{Error, Result};
use core::mem::size_of;

pub fn parse_header<'a, H: Sized>(data: &'a [u8]) -> Result<&'a H> {
    if data.len() < size_of::<H>() {
        return Err(Error::PacketTooShort);
    }
    Ok(unsafe { &*(data.as_ptr() as *const H) })
}

pub fn parse_header_mut<'a, H: Sized>(data: &'a mut [u8]) -> Result<&'a mut H> {
    if data.len() < size_of::<H>() {
        return Err(Error::PacketTooShort);
    }
    Ok(unsafe { &mut *(data.as_mut_ptr() as *mut H) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

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

    #[test_case]
    fn parse_header_too_short() {
        let data = [0u8; 2];
        let err = parse_header::<u32>(&data).unwrap_err();
        assert_eq!(err, Error::PacketTooShort);
    }
}
