#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EthHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
}

impl EthHeader {
    pub const LEN: usize = core::mem::size_of::<EthHeader>();
}
