use crate::net::ip::IpEndpoint;
use alloc::vec::Vec;

pub(crate) struct RetransmitEntry {
    pub(crate) first_at: u64,
    pub(crate) last_at: u64,
    pub(crate) rto: u64,
    pub(crate) seq: u32,
    pub(crate) flags: u8,
    pub(crate) payload: Vec<u8>,
}

pub(crate) struct SendRequest {
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) flags: u8,
    pub(crate) wnd: u16,
    pub(crate) payload: Vec<u8>,
    pub(crate) local: IpEndpoint,
    pub(crate) foreign: IpEndpoint,
}
