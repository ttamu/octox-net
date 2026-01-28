use core::fmt;

/// [RFC 9293](https://datatracker.ietf.org/doc/html/rfc9293#name-state-machine-overview)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    CloseWait,
    LastAck,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            State::Closed => write!(f, "CLOSED"),
            State::Listen => write!(f, "LISTEN"),
            State::SynSent => write!(f, "SYN-SENT"),
            State::SynReceived => write!(f, "SYN-RECEIVED"),
            State::Established => write!(f, "ESTABLISHED"),
            State::FinWait1 => write!(f, "FIN-WAIT-1"),
            State::FinWait2 => write!(f, "FIN-WAIT-2"),
            State::Closing => write!(f, "CLOSING"),
            State::TimeWait => write!(f, "TIME-WAIT"),
            State::CloseWait => write!(f, "CLOSE-WAIT"),
            State::LastAck => write!(f, "LAST-ACK"),
        }
    }
}
