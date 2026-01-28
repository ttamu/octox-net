use crate::error::{Error, Result};
use crate::net::ip::IpAddr;
use crate::net::util::{read_u16, write_u16};

pub mod field {
    pub type Field = core::ops::Range<usize>;

    pub const SRC_PORT: Field = 0..2;
    pub const DST_PORT: Field = 2..4;
    pub const SEQ_NUM: Field = 4..8;
    pub const ACK_NUM: Field = 8..12;
    pub const FLAGS: Field = 12..14;
    pub const WIN_SIZE: Field = 14..16;
    pub const CHECKSUM: Field = 16..18;
    pub const URGENT: Field = 18..20;

    pub const FLG_FIN: u8 = 0x01;
    pub const FLG_SYN: u8 = 0x02;
    pub const FLG_RST: u8 = 0x04;
    pub const FLG_PSH: u8 = 0x08;
    pub const FLG_ACK: u8 = 0x10;
}

pub const HEADER_LEN: usize = field::URGENT.end;
pub const PROTOCOL_TCP: u8 = 6;

pub struct Packet<'a> {
    buffer: &'a [u8],
}
impl<'a> Packet<'a> {
    pub fn new_checked(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < HEADER_LEN {
            return Err(Error::PacketTooShort);
        }
        let packet = Self { buffer };
        let header_len = packet.header_len();
        if header_len < HEADER_LEN || header_len > buffer.len() {
            return Err(Error::InvalidHeaderLen);
        }
        Ok(packet)
    }

    pub fn header_len(&self) -> usize {
        ((self.buffer[field::FLAGS.start] >> 4) as usize) * 4
    }

    pub fn src_port(&self) -> u16 {
        read_u16(&self.buffer[field::SRC_PORT])
    }

    pub fn dst_port(&self) -> u16 {
        read_u16(&self.buffer[field::DST_PORT])
    }

    pub fn seq_number(&self) -> u32 {
        read_u32(&self.buffer[field::SEQ_NUM])
    }

    pub fn ack_number(&self) -> u32 {
        read_u32(&self.buffer[field::ACK_NUM])
    }

    pub fn flags(&self) -> u8 {
        self.buffer[field::FLAGS.start + 1]
    }

    pub fn window_len(&self) -> u16 {
        read_u16(&self.buffer[field::WIN_SIZE])
    }

    pub fn payload(&self) -> &'a [u8] {
        let header_len = self.header_len();
        &self.buffer[header_len..]
    }

    pub fn verify_checksum(&self, src: IpAddr, dst: IpAddr) -> bool {
        checksum_sum(src, dst, self.buffer) == 0xffff
    }
}

pub struct PacketMut<'a> {
    buffer: &'a mut [u8],
}
impl<'a> PacketMut<'a> {
    pub fn new_unchecked(buffer: &'a mut [u8]) -> Self {
        Self { buffer }
    }

    pub fn set_src_port(&mut self, value: u16) {
        write_u16(&mut self.buffer[field::SRC_PORT], value);
    }

    pub fn set_dst_port(&mut self, value: u16) {
        write_u16(&mut self.buffer[field::DST_PORT], value);
    }

    pub fn set_seq_number(&mut self, value: u32) {
        write_u32(&mut self.buffer[field::SEQ_NUM], value);
    }

    pub fn set_ack_number(&mut self, value: u32) {
        write_u32(&mut self.buffer[field::ACK_NUM], value);
    }

    pub fn set_header_len(&mut self, header_len: usize) {
        self.buffer[field::FLAGS.start] = ((header_len / 4) as u8) << 4;
    }

    pub fn set_flags(&mut self, flags: u8) {
        self.buffer[field::FLAGS.start + 1] = flags;
    }

    pub fn set_window_len(&mut self, value: u16) {
        write_u16(&mut self.buffer[field::WIN_SIZE], value);
    }

    pub fn set_checksum(&mut self, value: u16) {
        write_u16(&mut self.buffer[field::CHECKSUM], value);
    }

    pub fn set_urg_ptr(&mut self, value: u16) {
        write_u16(&mut self.buffer[field::URGENT], value);
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[HEADER_LEN..]
    }

    pub fn fill_checksum(&mut self, src: IpAddr, dst: IpAddr) {
        self.set_checksum(0);
        let sum = checksum_sum(src, dst, self.buffer);
        let checksum = (!sum) as u16;
        self.set_checksum(checksum);
    }
}

fn read_u32(data: &[u8]) -> u32 {
    u32::from_be_bytes([data[0], data[1], data[2], data[3]])
}

fn write_u32(data: &mut [u8], value: u32) {
    data[..4].copy_from_slice(&value.to_be_bytes());
}

fn checksum_sum(src: IpAddr, dst: IpAddr, segment: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let src_bytes = src.0.to_be_bytes();
    let dst_bytes = dst.0.to_be_bytes();

    sum = checksum_acc(&src_bytes, sum);
    sum = checksum_acc(&dst_bytes, sum);
    sum = checksum_acc(&[0, 6], sum);
    let len = (segment.len() as u16).to_be_bytes();
    sum = checksum_acc(&len, sum);
    sum = checksum_acc(segment, sum);

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

fn checksum_acc(data: &[u8], mut sum: u32) -> u32 {
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
    sum
}
