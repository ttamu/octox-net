#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpAddr(pub u32);

impl IpAddr {
    pub const LOOPBACK: IpAddr = IpAddr(0x7F00_0001);

    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        IpAddr(u32::from_be_bytes([a, b, c, d]))
    }

    pub fn to_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}