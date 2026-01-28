extern crate alloc;
use crate::error::{Error, Result};
use crate::net::device::{NetDevice, NetDeviceFlags};
use crate::net::protocol::{net_protocol_handler, ProtocolType};
use crate::trace;
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: Self = MacAddr([0xFF; 6]);
    pub const ZERO: Self = MacAddr([0x00; 6]);

    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xFF; 6]
    }

    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

mod wire {
    use crate::error::{Error, Result};
    use crate::net::util::{read_u16, write_u16};

    pub mod field {
        pub type Field = core::ops::Range<usize>;

        pub const DST: Field = 0..6;
        pub const SRC: Field = 6..12;
        pub const ETHERTYPE: Field = 12..14;
    }

    pub const HEADER_LEN: usize = field::ETHERTYPE.end;

    pub struct Frame<'a> {
        buffer: &'a [u8],
    }

    impl<'a> Frame<'a> {
        pub fn new_checked(buffer: &'a [u8]) -> Result<Self> {
            if buffer.len() < HEADER_LEN {
                return Err(Error::PacketTooShort);
            }
            Ok(Self { buffer })
        }

        #[allow(dead_code)]
        pub fn dst(&self) -> [u8; 6] {
            let mut dst = [0u8; 6];
            dst.copy_from_slice(&self.buffer[field::DST]);
            dst
        }

        #[allow(dead_code)]
        pub fn src(&self) -> [u8; 6] {
            let mut src = [0u8; 6];
            src.copy_from_slice(&self.buffer[field::SRC]);
            src
        }

        pub fn ethertype(&self) -> u16 {
            read_u16(&self.buffer[field::ETHERTYPE])
        }

        pub fn payload(&self) -> &'a [u8] {
            &self.buffer[HEADER_LEN..]
        }
    }

    pub struct FrameMut<'a> {
        buffer: &'a mut [u8],
    }

    impl<'a> FrameMut<'a> {
        pub fn new_unchecked(buffer: &'a mut [u8]) -> Self {
            Self { buffer }
        }

        pub fn set_dst(&mut self, mac: [u8; 6]) {
            self.buffer[field::DST].copy_from_slice(&mac);
        }

        pub fn set_src(&mut self, mac: [u8; 6]) {
            self.buffer[field::SRC].copy_from_slice(&mac);
        }

        pub fn set_ethertype(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::ETHERTYPE], value);
        }

        pub fn payload_mut(&mut self) -> &mut [u8] {
            &mut self.buffer[HEADER_LEN..]
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EthHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
}

impl EthHeader {
    pub const LEN: usize = wire::HEADER_LEN;
}

pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV4: u16 = 0x0800;

pub fn ingress(dev: &NetDevice, data: &[u8]) -> Result<()> {
    let frame = wire::Frame::new_checked(data)?;
    let etype = frame.ethertype();

    trace!(
        ETHER,
        "[ether] ingress: ethertype=0x{:04x}, len={}",
        etype,
        data.len()
    );

    let payload = frame.payload();
    match etype {
        ETHERTYPE_ARP => crate::net::arp::ingress(dev, payload),
        ETHERTYPE_IPV4 => net_protocol_handler(dev, ProtocolType::IP, payload),
        _ => {
            trace!(ETHER, "[ether] unsupported ethertype: 0x{:04x}", etype);
            Err(Error::UnsupportedProtocol)
        }
    }
}

pub fn egress(dev: &mut NetDevice, dst_mac: MacAddr, ethertype: u16, payload: &[u8]) -> Result<()> {
    if !dev.flags().contains(NetDeviceFlags::UP) {
        return Err(Error::NotConnected);
    }
    let mut frame = alloc::vec![0u8; wire::HEADER_LEN + payload.len()];
    {
        let mut hdr = wire::FrameMut::new_unchecked(&mut frame);
        hdr.set_dst(dst_mac.0);
        hdr.set_src(dev.hw_addr.0);
        hdr.set_ethertype(ethertype);
        hdr.payload_mut().copy_from_slice(payload);
    }
    trace!(
        ETHER,
        "[ether] egress: dst={:02x?} type=0x{:04x} len={}",
        dst_mac.0,
        ethertype,
        frame.len()
    );
    dev.transmit(&frame)
}

#[cfg(test)]
mod tests {
    use super::wire;
    use crate::error::{Error, Result};
    use crate::net::device::{
        NetDevice, NetDeviceConfig, NetDeviceFlags, NetDeviceOps, NetDeviceType,
    };
    use crate::net::ethernet::{ingress, MacAddr};

    #[test_case]
    fn frame_too_short() {
        let data = [0u8; wire::HEADER_LEN - 1];
        let err = wire::Frame::new_checked(&data).err().unwrap();
        assert_eq!(err, Error::PacketTooShort);
    }

    fn ok_transmit(_dev: &mut NetDevice, _data: &[u8]) -> Result<()> {
        Ok(())
    }
    fn ok_open(_dev: &mut NetDevice) -> Result<()> {
        Ok(())
    }
    fn ok_close(_dev: &mut NetDevice) -> Result<()> {
        Ok(())
    }

    fn dummy_dev() -> NetDevice {
        NetDevice::new(NetDeviceConfig {
            name: "dummy",
            dev_type: NetDeviceType::Ethernet,
            mtu: 1500,
            flags: NetDeviceFlags::UP,
            header_len: wire::HEADER_LEN as u16,
            addr_len: 6,
            hw_addr: MacAddr::ZERO,
            ops: NetDeviceOps {
                transmit: ok_transmit,
                open: ok_open,
                close: ok_close,
            },
        })
    }

    #[test_case]
    fn ingress_unsupported_ethertype() {
        let dev = dummy_dev();
        let mut frame = [0u8; wire::HEADER_LEN];
        frame[12] = 0x12;
        frame[13] = 0x34;
        let err = ingress(&dev, &frame).unwrap_err();
        assert_eq!(err, Error::UnsupportedProtocol);
    }
}
