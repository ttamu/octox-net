extern crate alloc;
use crate::{
    error::{Error, Result},
    memlayout::VIRTIO1,
    net::{
        device::{net_device_register, NetDevice, NetDeviceFlags, NetDeviceOps, NetDeviceType},
        ethernet,
        ip::IpAddr,
    },
    spinlock::Mutex,
};
use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering};

const VIRTIO_NET_F_MAC: u32 = 1 << 5;
const VIRTIO_NET_F_STATUS: u32 = 1 << 16;
const VIRTIO_NET_HDR_LEN: usize = 10;

const NUM: usize = 32;

#[repr(usize)]
enum Mmio {
    MagicValue = 0x00,
    Version = 0x004,
    DeviceId = 0x008,
    VendorId = 0x00c,
    DeviceFeatures = 0x010,
    DriverFeatures = 0x020,
    QueueSel = 0x030,
    QueueNumMax = 0x034,
    QueueNum = 0x038,
    QueueReady = 0x044,
    QueueNotify = 0x050,
    InterruptStatus = 0x060,
    InterruptAck = 0x064,
    Status = 0x070,
    QueueDescLow = 0x080,
    QueueDescHigh = 0x084,
    DriverDescLow = 0x090,
    DriverDescHigh = 0x094,
    DeviceDescLow = 0x0a0,
    DeviceDescHigh = 0x0a4,
    ConfigMac0 = 0x100,
}

impl Mmio {
    fn read(self) -> u32 {
        unsafe { core::ptr::read_volatile((VIRTIO1 + self as usize) as *const u32) }
    }
    unsafe fn write(self, data: u32) {
        core::ptr::write_volatile((VIRTIO1 + self as usize) as *mut u32, data);
    }
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

#[repr(C, align(2))]
#[derive(Clone, Copy)]
struct VirtqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; NUM],
    unused: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

#[repr(C, align(4))]
#[derive(Clone, Copy)]
struct VirtqUsed {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; NUM],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct VirtioNetHdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
}

pub struct VirtioNet {
    desc_rx: [VirtqDesc; NUM],
    avail_rx: VirtqAvail,
    used_rx: VirtqUsed,
    free_rx: [bool; NUM],
    used_idx_rx: u16,
    desc_tx: [VirtqDesc; NUM],
    avail_tx: VirtqAvail,
    used_tx: VirtqUsed,
    free_tx: [bool; NUM],
    used_idx_tx: u16,
    rx_bufs: [[u8; 2048]; NUM],
    tx_bufs: [[u8; 2048]; NUM],
    tx_hdr: VirtioNetHdr,
    mac: [u8; 6],
}

static NET: Mutex<VirtioNet> = Mutex::new(VirtioNet::new(), "virtio_net");

impl VirtioNet {
    const fn new() -> Self {
        Self {
            desc_rx: [VirtqDesc {
                addr: 0,
                len: 0,
                flags: 0,
                next: 0,
            }; NUM],
            avail_rx: VirtqAvail {
                flags: 0,
                idx: 0,
                ring: [0; NUM],
                unused: 0,
            },
            used_rx: VirtqUsed {
                flags: 0,
                idx: 0,
                ring: [VirtqUsedElem { id: 0, len: 0 }; NUM],
            },
            free_rx: [true; NUM],
            used_idx_rx: 0,
            desc_tx: [VirtqDesc {
                addr: 0,
                len: 0,
                flags: 0,
                next: 0,
            }; NUM],
            avail_tx: VirtqAvail {
                flags: 0,
                idx: 0,
                ring: [0; NUM],
                unused: 0,
            },
            used_tx: VirtqUsed {
                flags: 0,
                idx: 0,
                ring: [VirtqUsedElem { id: 0, len: 0 }; NUM],
            },
            free_tx: [true; NUM],
            used_idx_tx: 0,
            rx_bufs: [[0u8; 2048]; NUM],
            tx_bufs: [[0u8; 2048]; NUM],
            tx_hdr: VirtioNetHdr {
                flags: 0,
                gso_type: 0,
                hdr_len: 0,
                gso_size: 0,
                csum_start: 0,
                csum_offset: 0,
            },
            mac: [0; 6],
        }
    }

    fn mmio_init(&mut self) -> Result<()> {
        if Mmio::MagicValue.read() != 0x7472_6976
            || Mmio::Version.read() != 2
            || Mmio::DeviceId.read() != 1
        {
            return Err(Error::DeviceNotFound);
        }

        let mut status: u32 = 0;
        unsafe { Mmio::Status.write(status) };
        status |= 0x1; // ACKNOWLEDGE
        unsafe { Mmio::Status.write(status) };
        status |= 0x2; // DRIVER
        unsafe { Mmio::Status.write(status) };

        let features = Mmio::DeviceFeatures.read();
        if features & VIRTIO_NET_F_MAC == 0 {
            return Err(Error::UnsupportedDevice);
        }
        let driver_features = features & (VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS);
        unsafe { Mmio::DriverFeatures.write(driver_features) };

        status |= 0x8; // FEATURES_OK
        unsafe { Mmio::Status.write(status) };
        let readback = Mmio::Status.read();
        assert!(readback & 0x8 != 0, "virtio-net FEATURES_OK unset");

        unsafe { Mmio::QueueSel.write(0) };
        let max = Mmio::QueueNumMax.read();
        assert!(max >= NUM as u32, "virtio-net queue too short");
        unsafe { Mmio::QueueNum.write(NUM as u32) };
        unsafe {
            Mmio::QueueDescLow.write(&self.desc_rx as *const _ as u64 as u32);
            Mmio::QueueDescHigh.write((&self.desc_rx as *const _ as u64 >> 32) as u32);
            Mmio::DriverDescLow.write(&self.avail_rx as *const _ as u64 as u32);
            Mmio::DriverDescHigh.write((&self.avail_rx as *const _ as u64 >> 32) as u32);
            Mmio::DeviceDescLow.write(&self.used_rx as *const _ as u64 as u32);
            Mmio::DeviceDescHigh.write((&self.used_rx as *const _ as u64 >> 32) as u32);
            Mmio::QueueReady.write(1);
        }

        unsafe { Mmio::QueueSel.write(1) };
        let max1 = Mmio::QueueNumMax.read();
        assert!(max1 >= NUM as u32, "virtio-net queue too short");
        unsafe { Mmio::QueueNum.write(NUM as u32) };
        unsafe {
            Mmio::QueueDescLow.write(&self.desc_tx as *const _ as u64 as u32);
            Mmio::QueueDescHigh.write((&self.desc_tx as *const _ as u64 >> 32) as u32);
            Mmio::DriverDescLow.write(&self.avail_tx as *const _ as u64 as u32);
            Mmio::DriverDescHigh.write((&self.avail_tx as *const _ as u64 >> 32) as u32);
            Mmio::DeviceDescLow.write(&self.used_tx as *const _ as u64 as u32);
            Mmio::DeviceDescHigh.write((&self.used_tx as *const _ as u64 >> 32) as u32);
            Mmio::QueueReady.write(1);
        }

        for i in 0..6 {
            self.mac[i] = unsafe {
                core::ptr::read_volatile((VIRTIO1 + Mmio::ConfigMac0 as usize + i) as *const u8)
            };
        }

        for i in 0..NUM {
            self.alloc_rx_buf(i);
        }

        status |= 0x4; // DRIVER_OK
        unsafe { Mmio::Status.write(status) };
        Ok(())
    }

    fn alloc_desc_tx(&mut self) -> Option<usize> {
        self.free_tx
            .iter_mut()
            .enumerate()
            .find(|(_, f)| **f)
            .map(|(i, f)| {
                *f = false;
                i
            })
    }

    fn free_desc_tx(&mut self, idx: usize) {
        self.free_tx[idx] = true;
        self.desc_tx[idx].addr = 0;
        self.desc_tx[idx].len = 0;
        self.desc_tx[idx].flags = 0;
        self.desc_tx[idx].next = 0;
    }

    fn alloc_rx_buf(&mut self, slot: usize) {
        let hdr_len = core::mem::size_of::<VirtioNetHdr>();
        self.desc_rx[slot].addr = self.rx_bufs[slot].as_ptr() as u64;
        self.desc_rx[slot].len = self.rx_bufs[slot].len() as u32;
        self.desc_rx[slot].flags = VIRTQ_DESC_F_WRITE;
        self.desc_rx[slot].next = 0;
        let ring_idx = (self.avail_rx.idx as usize) % NUM;
        self.avail_rx.ring[ring_idx] = slot as u16;
        fence(Ordering::SeqCst);
        self.avail_rx.idx = self.avail_rx.idx.wrapping_add(1);
        fence(Ordering::SeqCst);
        unsafe { Mmio::QueueNotify.write(0) };
        for b in &mut self.rx_bufs[slot][..hdr_len] {
            *b = 0;
        }
    }

    fn transmit(&mut self, data: &[u8]) -> Result<()> {
        let mut idxs = [0usize; 2];
        for i in 0..2 {
            idxs[i] = self.alloc_desc_tx().ok_or(Error::NoBufferSpace)?;
        }
        self.desc_tx[idxs[0]].addr = &self.tx_hdr as *const _ as u64;
        self.desc_tx[idxs[0]].len = VIRTIO_NET_HDR_LEN as u32;
        self.desc_tx[idxs[0]].flags = VIRTQ_DESC_F_NEXT;
        self.desc_tx[idxs[0]].next = idxs[1] as u16;

        let data_len = data.len().min(self.tx_bufs[idxs[1]].len());
        self.tx_bufs[idxs[1]][..data_len].copy_from_slice(&data[..data_len]);

        self.desc_tx[idxs[1]].addr = self.tx_bufs[idxs[1]].as_ptr() as u64;
        self.desc_tx[idxs[1]].len = data_len as u32;
        self.desc_tx[idxs[1]].flags = 0;
        self.desc_tx[idxs[1]].next = 0;

        let ring_idx = (self.avail_tx.idx as usize) % NUM;
        self.avail_tx.ring[ring_idx] = idxs[0] as u16;
        fence(Ordering::SeqCst);
        self.avail_tx.idx = self.avail_tx.idx.wrapping_add(1);
        fence(Ordering::SeqCst);
        unsafe { Mmio::QueueNotify.write(1) };
        Ok(())
    }

    fn handle_used(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut packets = Vec::new();
        while self.used_idx_rx != self.used_rx.idx {
            let used_elem = self.used_rx.ring[(self.used_idx_rx as usize) % NUM];
            let id = used_elem.id as usize;
            if id >= NUM {
                crate::println!("[virtio-net] invalid RX descriptor id: {}", id);
                self.used_idx_rx = self.used_idx_rx.wrapping_add(1);
                continue;
            }
            let hdr_len = core::mem::size_of::<VirtioNetHdr>();
            let total_len = used_elem.len as usize;
            if total_len > hdr_len {
                let data_len = total_len.saturating_sub(hdr_len);
                let buf_len = self.rx_bufs[id].len();
                if hdr_len + data_len <= buf_len {
                    let mut buf = Vec::with_capacity(data_len);
                    buf.extend_from_slice(&self.rx_bufs[id][hdr_len..hdr_len + data_len]);
                    packets.push(buf);
                }
            }
            self.alloc_rx_buf(id);
            self.used_idx_rx = self.used_idx_rx.wrapping_add(1);
        }
        while self.used_idx_tx != self.used_tx.idx {
            let used_elem = self.used_tx.ring[(self.used_idx_tx as usize) % NUM];
            let id = used_elem.id as usize;
            if id >= NUM {
                crate::println!("[virtio-net] invalid TX descriptor id: {}", id);
                self.used_idx_tx = self.used_idx_tx.wrapping_add(1);
                continue;
            }
            self.free_desc_chain_tx(id);
            self.used_idx_tx = self.used_idx_tx.wrapping_add(1);
        }
        Ok(packets)
    }

    fn free_desc_chain_tx(&mut self, mut idx: usize) {
        loop {
            let flags = self.desc_tx[idx].flags;
            let next = self.desc_tx[idx].next;
            self.free_desc_tx(idx);
            if flags & VIRTQ_DESC_F_NEXT != 0 {
                idx = next as usize;
            } else {
                break;
            }
        }
    }
}

pub fn init() -> Result<()> {
    let mut guard = NET.lock();
    guard.mmio_init()?;

    let ops = NetDeviceOps {
        transmit: transmit,
        open: |dev| {
            dev.set_flags(dev.flags() | NetDeviceFlags::UP | NetDeviceFlags::RUNNING);
            Ok(())
        },
        close: |dev| {
            dev.set_flags(dev.flags() & !NetDeviceFlags::RUNNING);
            Ok(())
        },
    };

    let mut dev = NetDevice::new(
        "eth0",
        NetDeviceType::Ethernet,
        1500,
        NetDeviceFlags::BROADCAST,
        ethernet::EthHeader::LEN as u16,
        6,
        guard.mac,
        ops,
    );
    dev.open()?;
    net_device_register(dev)?;
    crate::println!("[net] virtio-net initialized MAC {:02x?}", guard.mac);
    Ok(())
}

pub fn setup_iface() -> Result<()> {
    crate::net::interface::net_interface_setup(
        "eth0",
        IpAddr::new(192, 0, 2, 2),
        IpAddr::new(255, 255, 255, 0),
    )?;
    // TODO: route実装時にコメントアウトを外す
    // crate::net::route::add_route(crate::net::route::Route {
    //     dest: IpAddr::new(0, 0, 0, 0),
    //     mask: IpAddr::new(0, 0, 0, 0),
    //     gateway: Some(IpAddr::new(192, 0, 2, 1)),
    //     dev: "eth0",
    // })?;
    Ok(())
}

fn transmit(_dev: &mut NetDevice, data: &[u8]) -> Result<()> {
    let mut guard = NET.lock();
    guard.transmit(data)
}

pub fn poll_rx() {
    let mut guard = NET.lock();
    if let Ok(pkts) = guard.handle_used() {
        if pkts.len() > 0 {
            crate::println!("[virtio-net] poll_rx: received {} packets", pkts.len());
        }
        drop(guard);
        for p in pkts {
            let dev = crate::net::device::net_device_by_name("eth0").unwrap();
            let _ = ethernet::input(&dev, p.as_slice());
        }
    }
}

pub fn intr() {
    let intr_stat = Mmio::InterruptStatus.read();
    unsafe { Mmio::InterruptAck.write(intr_stat & 0x3) };
    poll_rx();
}
