use core::sync::atomic::{AtomicU32, Ordering};

#[derive(Clone, Copy)]
pub struct Flags(u32);

impl Flags {
    pub const ETHER: Flags = Flags(1 << 0);
    pub const ARP: Flags = Flags(1 << 1);
    pub const IP: Flags = Flags(1 << 2);
    pub const ICMP: Flags = Flags(1 << 3);
    pub const UDP: Flags = Flags(1 << 4);
    pub const TCP: Flags = Flags(1 << 5);
    pub const DNS: Flags = Flags(1 << 6);
    pub const DRIVER: Flags = Flags(1 << 7);

    pub const fn bits(&self) -> u32 {
        self.0
    }

    pub const fn from_bits(bits: u32) -> Self {
        Flags(bits)
    }

    pub const fn contains(&self, other: Flags) -> bool {
        (self.0 & other.0) == other.0
    }
}

// 今のところは初期値を変更してビルドすることで表示を切り替え (全てON: 0b1111_1111)
// TODO: ユーザ空間から制御できるようにする
static TRACE_FLAGS: AtomicU32 = AtomicU32::new(0);

pub fn is_enabled(flag: Flags) -> bool {
    let flags = Flags::from_bits(TRACE_FLAGS.load(Ordering::Relaxed));
    flags.contains(flag)
}

#[macro_export]
macro_rules! trace {
    ($flag:ident, $($arg:tt)*) => {
        if $crate::net::trace::is_enabled($crate::net::trace::Flags::$flag) {
            $crate::println!($($arg)*)
        }
    };
}
