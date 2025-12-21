# ping

## 目次

- [ping](#ping)
  - [目次](#目次)
  - [1. 期待される動作](#1-期待される動作)
  - [2. システムアーキテクチャ](#2-システムアーキテクチャ)
    - [2.1 コンポーネント構成](#21-コンポーネント構成)
    - [2.2 ディレクトリ構造](#22-ディレクトリ構造)
    - [2.3 データフロー](#23-データフロー)
      - [2.3.1 ping送信時のデータフロー](#231-ping送信時のデータフロー)
      - [2.3.2 ping受信時のデータフロー](#232-ping受信時のデータフロー)
      - [2.3.3 パケット構造の変化](#233-パケット構造の変化)
        - [2.3.3.1 送信時](#2331-送信時)
        - [2.3.3.2 受信時](#2332-受信時)
  - [3. 実装](#3-実装)
    - [3.1 エラー型の拡張](#31-エラー型の拡張)
    - [3.2 ネットワークユーティリティ](#32-ネットワークユーティリティ)
    - [3.3 ネットワークデバイス抽象化](#33-ネットワークデバイス抽象化)
    - [3.4 ネットワークインターフェース](#34-ネットワークインターフェース)
    - [3.5 プロトコル層](#35-プロトコル層)
    - [3.6 IP層](#36-ip層)
    - [3.7 ICMP](#37-icmp)
    - [3.8 ループバックデバイス](#38-ループバックデバイス)
    - [3.9 virtio-netデバイスドライバ](#39-virtio-netデバイスドライバ)
    - [3.10 Ethernet層](#310-ethernet層)
    - [3.11 ARP (Address Resolution Protocol)](#311-arp-address-resolution-protocol)
    - [3.12 ルーティングテーブル](#312-ルーティングテーブル)
    - [3.13 システムコール](#313-システムコール)
    - [3.14 ユーザーライブラリ](#314-ユーザーライブラリ)
    - [3.15 pingコマンド](#315-pingコマンド)
    - [3.16 初期化処理](#316-初期化処理)

## 1. 期待される動作

pingコマンドを実行すると、以下のように出力される。

```bash
$ ping 8.8.8.8
PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=117 time=22.942 ms
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=21.885 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=14.602 ms
```

## 2. システムアーキテクチャ

### 2.1 コンポーネント構成

```text
┌─────────────────────────────────────────────────────────┐
│                  User Space (ユーザー空間)                │
├─────────────────────────────────────────────────────────┤
│  ping コマンド (src/user/bin/ping.rs)                    │
│   ↓ システムコール                                        │
├─────────────────────────────────────────────────────────┤
│                  Kernel Space (カーネル空間)              │
├─────────────────────────────────────────────────────────┤
│  System Call Layer (syscall.rs)                         │
│   - icmpechorequest()  送信システムコール                  │
│   - icmprecvreply()    受信システムコール                  │
│          ↓                        ↑                     │
├─────────────────────────────────────────────────────────┤
│  Network Layer (IP/ICMP)                                │
│   - icmp.rs     ICMPパケットの生成/解析                    │
│   - ip.rs       IPパケットの生成/解析/ルーティング           │
│          ↓                        ↑                     │
├─────────────────────────────────────────────────────────┤
│  Link Layer (Ethernet/ARP)                              │
│   - ethernet.rs  Ethernetフレーム処理                     │
│   - arp.rs       IPアドレス→MACアドレス解決                │
│          ↓                        ↑                     │
├─────────────────────────────────────────────────────────┤
│  Device Layer                                           │
│   - loopback.rs  ループバックデバイス (127.0.0.1用)         │
│   - virtio_net.rs  NIC (外部通信用)                       │
└─────────────────────────────────────────────────────────┘
```

### 2.2 ディレクトリ構造

```text
src/
├── kernel/
│   ├── net.rs              ネットワークスタックの初期化
│   ├── net/
│   │   ├── device.rs       ネットワークデバイスの抽象化
│   │   ├── interface.rs    IPアドレスの設定
│   │   ├── protocol.rs     プロトコルのディスパッチ
│   │   ├── ip.rs           IP層の実装
│   │   ├── icmp.rs         ICMPの実装
│   │   ├── ethernet.rs     Ethernetフレーム処理
│   │   ├── arp.rs          ARP処理
│   │   ├── route.rs        ルーティングテーブル
│   │   ├── util.rs         チェックサム計算など
│   │   ├── driver.rs       ドライバモジュール
│   │   └── driver/
│   │       ├── loopback.rs    ループバックドライバ
│   │       └── virtio_net.rs  virtio-netドライバ
│   ├── syscall.rs       システムコール実装
│   └── error.rs         エラー型定義
└── user/
    ├── bin/
    │   └── ping.rs      pingコマンド実装
    └── lib/
        └── lib.rs       ユーザーライブラリ
```

### 2.3 データフロー

#### 2.3.1 ping送信時のデータフロー

```text
┌─────────────────────────────────────────────────────────────┐
│ User Space: ping コマンド                                    │
│  1. icmp_echo_request("127.0.0.1", id, seq, payload)        │
└────────────────────┬────────────────────────────────────────┘
                     │ システムコール (SYS_ICMP_ECHO_REQUEST)
┌────────────────────▼────────────────────────────────────────┐
│ Kernel: syscall.rs                                          │
│  2. icmpechorequest()                                       │
│     - IPアドレスをパース                                       │
│     - ユーザー空間からデータをコピー                             │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ ICMP: icmp.rs                                               │
│  3. icmp_echo_request(dst, id, seq, payload)                │
│     - ICMPヘッダーを作成                                      │
│       Type=8 (Echo Request), Code=0                         │
│       ID, Sequence Number設定                                │
│     - チェックサムを計算                                       │
│     - ペイロードを付加                                         │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ IP Layer: ip.rs                                             │
│  4. ip_output_route(dst, ICMP, icmp_packet)                 │
│     - ループバック判定 (127.0.0.1?)                            │
│       YES → loopbackデバイスへ                                │
│       NO  → ルーティングテーブル検索                            │
│     - IPヘッダーを作成                                        │
│       Version=4, Protocol=1(ICMP), TTL=64                   │
│       Src/Dst IP設定                                         │
│     - IPチェックサムを計算                                     │
└────────────────────┬────────────────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
    (Loopback)              (Ethernet)
         │                       │
┌────────▼──────┐      ┌────────▼────────────────────────────┐
│ Loopback      │      │ Ethernet Layer: ethernet.rs         │
│ Driver        │      │  5-1. ARP解決 (IP→MAC)               │
│               │      │  5-2. Ethernetヘッダー追加            │
│  送信=受信     │      │       Dst MAC, Src MAC, Type=0x0800 │
│  (折り返し)    │      └────────┬────────────────────────────┘
└───────────────┘               │
                     ┌──────────▼─────────────────────────────┐
                     │ Device: virtio_net.rs                  │
                     │  6. transmit(ethernet_frame)           │
                     │     - virtioキューに追加                 │
                     │     - QEMUに送信通知                     │
                     └────────────────────────────────────────┘
```

#### 2.3.2 ping受信時のデータフロー

```text
┌─────────────────────────────────────────────────────────────┐
│ Hardware/QEMU: パケット受信                                   │
│  - virtio-net デバイスが割り込みを発生                          │
└────────────────────┬────────────────────────────────────────┘
                     │ 割り込み
┌────────────────────▼────────────────────────────────────────┐
│ Device: virtio_net.rs                                       │
│  1. 割り込みハンドラ / poll_rx()                               │
│     - virtioキューからパケットを取得                            │
└────────────────────┬────────────────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
    (Loopback)              (Ethernet)
         │                       │
         │              ┌────────▼────────────────────────────┐
         │              │ Ethernet Layer: ethernet.rs         │
         │              │  2. input(dev, frame)               │
         │              │     - Ethernetヘッダーをパース         │
         │              │     - EtherType判定 (0x0800=IP)      │
         │              └────────┬────────────────────────────┘
         │                       │
         └───────────┬───────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ Protocol Layer: protocol.rs                                 │
│  3. net_protocol_handler(dev, IP, payload)                  │
│     - 登録されたIPハンドラを呼び出し                             │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ IP Layer: ip.rs                                             │
│  4. ip_input(dev, packet)                                   │
│     - IPヘッダーをパース                                       │
│     - バージョン、チェックサム検証                               │
│     - Protocol判定 (1=ICMP)                                  │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ ICMP: icmp.rs                                               │
│  5. icmp_input(src, dst, data)                              │
│     - ICMPヘッダーをパース                                     │
│     - チェックサム検証                                         │
│     - Type判定                                               │
│       Type=8 (Echo Request)                                 │
│         → icmp_echo_reply() を呼び出し                        │
│       Type=0 (Echo Reply)                                   │
│         → icmp_notify_reply() でキューに追加                  │
└────────────────────┬────────────────────────────────────────┘
                     │ (Echo Replyの場合)
┌────────────────────▼────────────────────────────────────────┐
│ ICMP: icmp.rs                                               │
│  6. icmp_notify_reply(src, id, seq, payload)                │
│     - IcmpReply構造体を作成                                   │
│     - ICMP_REPLY_QUEUEに追加                                 │
│     - Condvarで待機中のスレッドを起床                           │
└─────────────────────────────────────────────────────────────┘
                     ▲
┌────────────────────┴────────────────────────────────────────┐
│ Kernel: syscall.rs                                          │
│  7. icmprecvreply()                                         │
│     - icmp_recv_reply(id, timeout) を呼び出し                 │
│     - キューから該当IDの応答を取得                              │
│     - ユーザー空間にコピー                                     │
└────────────────────┬────────────────────────────────────────┘
                     │ システムコールリターン
┌────────────────────▼────────────────────────────────────────┐
│ User Space: ping コマンド                                    │
│  8. icmp_recv_reply() が成功                                 │
│     - RTTを計算                                              │
│     - 結果を表示                                              │
└─────────────────────────────────────────────────────────────┘
```

#### 2.3.3 パケット構造の変化

##### 2.3.3.1 送信時

```text
[アプリケーション層]
  Payload (56 bytes)
    ↓
[ICMP] icmp_echo_request()
  ┌──────────────┬──────────┐
  │ ICMP Header  │ Payload  │
  │   (8 bytes)  │ (56 B)   │
  └──────────────┴──────────┘
    ↓
[IP層] ip_output()
  ┌──────────────┬──────────────┬──────────┐
  │  IP Header   │ ICMP Header  │ Payload  │
  │  (20 bytes)  │   (8 bytes)  │ (56 B)   │
  └──────────────┴──────────────┴──────────┘
    ↓
[Ethernet層] ethernet::output() ※外部通信の場合のみ
  ┌─────────────┬──────────────┬──────────────┬──────────┐
  │ Eth Header  │  IP Header   │ ICMP Header  │ Payload  │
  │  (14 bytes) │  (20 bytes)  │   (8 bytes)  │ (56 B)   │
  └─────────────┴──────────────┴──────────────┴──────────┘
    ↓
[物理層] → ネットワークへ送信
```

##### 2.3.3.2 受信時

```text
[物理層] ← ネットワークから受信
  ┌─────────────┬──────────────┬──────────────┬──────────┐
  │ Eth Header  │  IP Header   │ ICMP Header  │ Payload  │
  │  (14 bytes) │  (20 bytes)  │   (8 bytes)  │ (56 B)   │
  └─────────────┴──────────────┴──────────────┴──────────┘
    ↓
[Ethernet層] ethernet::input() Ethernetヘッダーを除去
  ┌──────────────┬──────────────┬──────────┐
  │  IP Header   │ ICMP Header  │ Payload  │
  │  (20 bytes)  │   (8 bytes)  │ (56 B)   │
  └──────────────┴──────────────┴──────────┘
    ↓
[IP層] ip_input() IPヘッダーを除去
  ┌──────────────┬──────────┐
  │ ICMP Header  │ Payload  │
  │   (8 bytes)  │ (56 B)   │
  └──────────────┴──────────┘
    ↓
[ICMP] icmp_input() ICMPヘッダーをパース
  Payload (56 bytes)
    ↓
[アプリケーション層]
  Payload (56 bytes)
```

## 3. 実装

### 3.1 エラー型の拡張

**ファイル:** `src/kernel/error.rs`

**ネットワーク関連のエラーを追加:**

```rust
#[repr(isize)]
#[derive(PartialEq, Debug)]
pub enum Error {
    // 既存のエラー...
    DeviceNotFound = -31,
    ProtocolNotFound = -32,
    PacketTooShort = -33,
    InvalidVersion = -34,
    InvalidHeaderLen = -35,
    ChecksumError = -36,
    PacketTruncated = -37,
    UnsupportedProtocol = -38,
    UnsupportedDevice = -39,
    PacketTooLarge = -40,
    InvalidAddress = -41,
    Timeout = -42,
}
```

**`as_str()`メソッドに追加:**

```rust
impl Error {
    pub fn as_str(&self) -> &'static str {
        use Error::*;
        match *self {
            // 既存のエラー...
            NotConnected => "not connected",
            DeviceNotFound => "device not found",
            ProtocolNotFound => "protocol not found",
            PacketTooShort => "packet too short",
            InvalidVersion => "invalid version",
            InvalidHeaderLen => "invalid header length",
            ChecksumError => "checksum error",
            PacketTruncated => "packet truncated",
            UnsupportedProtocol => "unsupported protocol",
            UnsupportedDevice => "unsupported device",
            PacketTooLarge => "packet too large",
            InvalidAddress => "invalid address",
            Timeout => "timeout",
            Uncategorized => "uncategorized error",
        }
    }
}
```

**`from_isize()`メソッドに追加:**

```rust
impl Error {
    pub fn from_isize(code: isize) -> Self {
        use Error::*;
        match code {
            // 既存のエラー...
            -30 => NotConnected,
            -31 => DeviceNotFound,
            -32 => ProtocolNotFound,
            -33 => PacketTooShort,
            -34 => InvalidVersion,
            -35 => InvalidHeaderLen,
            -36 => ChecksumError,
            -37 => PacketTruncated,
            -38 => UnsupportedProtocol,
            -39 => UnsupportedDevice,
            -40 => PacketTooLarge,
            -41 => InvalidAddress,
            -42 => Timeout,
            _ => Uncategorized,
        }
    }
}
```

### 3.2 ネットワークユーティリティ

**ファイル:** `src/kernel/net/util.rs`

**チェックサム計算とバイトオーダー変換を実装:**

```rust
/// Internet checksum (RFC1071)
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

pub fn hton16(n: u16) -> u16 { n.to_be() }
pub fn ntoh16(n: u16) -> u16 { u16::from_be(n) }
pub fn hton32(n: u32) -> u32 { n.to_be() }
pub fn ntoh32(n: u32) -> u32 { u32::from_be(n) }
```

### 3.3 ネットワークデバイス抽象化

**ファイル:** `src/kernel/net/device.rs`

**デバイスの種類を定義:**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetDeviceType {
    Loopback,
    Ethernet,
}
```

**デバイスのフラグ:**

```rust
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NetDeviceFlags(pub u16);

impl NetDeviceFlags {
    pub const UP: Self = Self(0x0001);
    pub const BROADCAST: Self = Self(0x0002);
    pub const LOOPBACK: Self = Self(0x0008);
    pub const RUNNING: Self = Self(0x0040);

    pub fn contains(self, other: NetDeviceFlags) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitOr for NetDeviceFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        NetDeviceFlags(self.0 | rhs.0)
    }
}

impl BitAnd for NetDeviceFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        NetDeviceFlags(self.0 & rhs.0)
    }
}

impl BitOrAssign for NetDeviceFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAndAssign for NetDeviceFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl Not for NetDeviceFlags {
    type Output = Self;
    fn not(self) -> Self::Output {
        NetDeviceFlags(!self.0)
    }
}
```

**デバイスの操作を定義:**

```rust
pub struct NetDeviceOps {
    pub transmit: fn(&mut NetDevice, data: &[u8]) -> Result<()>,
    pub open: fn(&mut NetDevice) -> Result<()>,
    pub close: fn(&mut NetDevice) -> Result<()>,
}
```

**デバイス構造体:**

```rust
pub struct NetDevice {
    name: [u8; 16],
    pub dev_type: NetDeviceType,
    mtu: u16,
    flags: NetDeviceFlags,
    pub header_len: u16,
    pub addr_len: u16,
    pub hw_addr: [u8; 6],
    ops: NetDeviceOps,
    pub interfaces: Vec<NetInterface>,
}

impl NetDevice {
    pub fn new(
        name: &str,
        dev_type: NetDeviceType,
        mtu: u16,
        flags: NetDeviceFlags,
        header_len: u16,
        addr_len: u16,
        hw_addr: [u8; 6],
        ops: NetDeviceOps,
    ) -> Self {
        let mut name_buf = [0u8; 16];
        let bytes = name.as_bytes();
        let len = bytes.len().min(15);
        name_buf[..len].copy_from_slice(&bytes[..len]);
        NetDevice {
            name: name_buf,
            dev_type,
            mtu,
            flags,
            header_len,
            addr_len,
            hw_addr,
            ops,
            interfaces: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..end]).unwrap_or("")
    }

    pub fn flags(&self) -> NetDeviceFlags {
        self.flags
    }

    pub fn set_flags(&mut self, flags: NetDeviceFlags) {
        self.flags = flags;
    }

    pub fn transmit(&mut self, data: &[u8]) -> Result<()> {
        (self.ops.transmit)(self, data)
    }

    pub fn open(&mut self) -> Result<()> {
        (self.ops.open)(self)
    }

    pub fn close(&mut self) -> Result<()> {
        (self.ops.close)(self)
    }

    pub fn add_interface(&mut self, iface: NetInterface) {
        self.interfaces.push(iface);
    }

    pub fn interface_by_addr(&self, addr: u32) -> Option<&NetInterface> {
        self.interfaces.iter().find(|i| i.addr.0 == addr)
    }
}

impl core::fmt::Debug for NetDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NetDevice")
            .field("name", &String::from(self.name()))
            .field("type", &self.dev_type)
            .field("mtu", &self.mtu)
            .field("flags", &self.flags)
            .finish()
    }
}

impl Clone for NetDevice {
    fn clone(&self) -> Self {
        NetDevice {
            name: self.name,
            dev_type: self.dev_type,
            mtu: self.mtu,
            flags: self.flags,
            header_len: self.header_len,
            addr_len: self.addr_len,
            hw_addr: self.hw_addr,
            ops: NetDeviceOps {
                transmit: self.ops.transmit,
                open: self.ops.open,
                close: self.ops.close,
            },
            interfaces: self.interfaces.clone(),
        }
    }
}
```

**グローバルデバイスリスト:**

```rust
static NET_DEVICES: Mutex<Vec<NetDevice>> = Mutex::new(Vec::new(), "net_devices");

pub fn net_device_register(device: NetDevice) -> Result<()> {
    let mut list = NET_DEVICES.lock();
    list.push(device);
    Ok(())
}

pub fn net_device_with_mut<F, R>(name: &str, mut f: F) -> Result<R>
where
    F: FnMut(&mut NetDevice) -> R,
{
    let mut list = NET_DEVICES.lock();
    let dev = list.iter_mut().find(|d| d.name() == name).ok_or(Error::DeviceNotFound)?;
    Ok(f(dev))
}

pub fn net_device_by_name(name: &str) -> Option<NetDevice> {
    let list = NET_DEVICES.lock();
    list.iter().find(|d| d.name() == name).cloned()
}

pub fn net_device_by_index(index: usize) -> Option<NetDevice> {
    let list = NET_DEVICES.lock();
    list.get(index).cloned()
}

pub fn net_device_foreach<F>(mut f: F)
where
    F: FnMut(&NetDevice),
{
    let list = NET_DEVICES.lock();
    for dev in list.iter() {
        f(dev);
    }
}
```

### 3.4 ネットワークインターフェース

**ファイル:** `src/kernel/net/interface.rs`

**IPアドレスの設定を管理:**

```rust
#[derive(Debug, Clone)]
pub struct NetInterface {
    pub family: u16,          // AF_INET = 2 (IPv4)
    pub addr: IpAddr,         // IPアドレス (例: 127.0.0.1)
    pub netmask: IpAddr,      // ネットマスク (例: 255.0.0.0)
    pub broadcast: IpAddr,    // ブロードキャストアドレス
}

impl NetInterface {
    pub fn new(addr: IpAddr, netmask: IpAddr) -> Self {
        let broadcast = IpAddr(addr.0 | !netmask.0);
        NetInterface {
            family: 2,
            addr,
            netmask,
            broadcast,
        }
    }
}

pub fn net_interface_setup(dev_name: &str, addr: IpAddr, netmask: IpAddr) -> Result<()> {
    net_device_with_mut(dev_name, |dev| {
        let iface = NetInterface::new(addr, netmask);
        dev.add_interface(iface);
    })
}
```

### 3.5 プロトコル層

**ファイル:** `src/kernel/net/protocol.rs`

**プロトコルのディスパッチャー:**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ProtocolType {
    IP = 0x0800,    // IPv4
    ARP = 0x0806,   // Address Resolution Protocol
    IPV6 = 0x86DD,  // IPv6
}

pub struct Protocol {
    ptype: ProtocolType,
    handler: fn(&NetDevice, &[u8]) -> Result<()>,
}

static PROTOCOLS: Mutex<Vec<Protocol>> = Mutex::new(Vec::new(), "net_protocols");

pub fn net_protocol_register(ptype: ProtocolType, handler: fn(&NetDevice, &[u8]) -> Result<()>) {
    let mut protos = PROTOCOLS.lock();
    protos.push(Protocol { ptype, handler });
}

pub fn net_protocol_handler(dev: &NetDevice, ptype: ProtocolType, data: &[u8]) -> Result<()> {
    let handler = {
        let protos = PROTOCOLS.lock();
        protos.iter().find(|p| p.ptype == ptype).map(|p| p.handler)
    };
    match handler {
        Some(h) => h(dev, data),
        None => Err(Error::ProtocolNotFound),
    }
}

pub fn net_input_handler(dev: &NetDevice, data: &[u8]) -> Result<()> {
    crate::println!("[net] input {} bytes from {}", data.len(), dev.name());

    if dev.flags().contains(NetDeviceFlags::LOOPBACK) {
        return net_protocol_handler(dev, ProtocolType::IP, data);
    }

    Err(Error::UnsupportedDevice)
}
```

### 3.6 IP層

**ファイル:** `src/kernel/net/ip.rs`

**IPアドレス型:**

```rust
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
```

**IPヘッダー:**

```rust
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IpHeader {
    pub version_ihl: u8,      // Version (4bit) + IHL (4bit)
    pub tos: u8,              // Type of Service
    pub total_len: u16,       // Total Length
    pub id: u16,              // Identification
    pub flags_offset: u16,    // Flags + Fragment Offset
    pub ttl: u8,              // Time To Live
    pub protocol: u8,         // Protocol (1=ICMP, 6=TCP, 17=UDP)
    pub checksum: u16,        // Header Checksum
    pub src: u32,             // Source Address
    pub dst: u32,             // Destination Address
}

impl IpHeader {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;

    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }

    pub fn header_len(&self) -> usize {
        (self.ihl() as usize) * 4
    }
}
```

**IP受信処理:**

```rust
pub fn ip_input(_dev: &NetDevice, data: &[u8]) -> Result<()> {
    if data.len() < size_of::<IpHeader>() {
        return Err(Error::PacketTooShort);
    }

    let header = unsafe { &*(data.as_ptr() as *const IpHeader) };

    if header.version() != 4 {
        return Err(Error::InvalidVersion);
    }

    let hlen = header.header_len();
    if hlen < 20 || hlen > data.len() {
        return Err(Error::InvalidHeaderLen);
    }

    if !verify_checksum(&data[..hlen]) {
        return Err(Error::ChecksumError);
    }

    let src = IpAddr(u32::from_be(header.src));
    let dst = IpAddr(u32::from_be(header.dst));

    let total_len = u16::from_be(header.total_len) as usize;
    let payload = &data[hlen..total_len];

    match header.protocol {
        IpHeader::ICMP => icmp::icmp_input(src, dst, payload),
        _ => Err(Error::UnsupportedProtocol),
    }
}
```

**IP送信処理:**

```rust
pub fn ip_output(
    dev: &NetDevice,
    protocol: u8,
    src: IpAddr,
    dst: IpAddr,
    data: &[u8],
) -> Result<()> {
    let total_len = size_of::<IpHeader>() + data.len();
    if total_len > 65535 {
        return Err(Error::PacketTooLarge);
    }

    let mut packet = vec![0u8; total_len];

    let header = unsafe { &mut *(packet.as_mut_ptr() as *mut IpHeader) };
    header.version_ihl = 0x45;  // Version=4, IHL=5 (20 bytes)
    header.tos = 0;
    header.total_len = (total_len as u16).to_be();
    header.id = 0;
    header.flags_offset = 0;
    header.ttl = 64;
    header.protocol = protocol;
    header.checksum = 0;
    header.src = src.0.to_be();
    header.dst = dst.0.to_be();

    header.checksum = checksum(&packet[..size_of::<IpHeader>()]).to_be();

    packet[size_of::<IpHeader>()..].copy_from_slice(data);

    let mut dev_clone = dev.clone();
    dev_clone.transmit(&packet)
}
```

**宛先に応じた送信処理:**

```rust
pub fn ip_output_route(dst: IpAddr, protocol: u8, payload: &[u8]) -> Result<()> {
    if dst.0 == IpAddr::LOOPBACK.0 {
        let dev = crate::net::device::net_device_by_name("lo").ok_or(Error::DeviceNotFound)?;
        return ip_output(&dev, protocol, IpAddr::LOOPBACK, dst, payload);
    }

    if let Some(route) = crate::net::route::lookup(dst) {
        let dev = net_device_by_name(route.dev).ok_or(Error::DeviceNotFound)?;
        let src = dev
            .interfaces
            .iter()
            .find(|i| (dst.0 & i.netmask.0) == (i.addr.0 & i.netmask.0))
            .map(|i| i.addr)
            .unwrap_or_else(|| {
                dev.interfaces
                    .first()
                    .map(|i| i.addr)
                    .unwrap_or(IpAddr::LOOPBACK)
            });

        let next_hop = route.gateway.unwrap_or(dst);
        let mac = crate::net::arp::resolve(dev.name(), next_hop, src, crate::param::TICK_HZ)
            .or_else(|_| Err(Error::Timeout))?;
        let mut dev_clone = dev.clone();
        let total_len = core::mem::size_of::<super::ip::IpHeader>() + payload.len();
        let mut ip_packet = alloc::vec![0u8; total_len];
        {
            let hdr = unsafe { &mut *(ip_packet.as_mut_ptr() as *mut super::ip::IpHeader) };
            hdr.version_ihl = 0x45;
            hdr.tos = 0;
            hdr.total_len = (total_len as u16).to_be();
            hdr.id = 0;
            hdr.flags_offset = 0;
            hdr.ttl = 64;
            hdr.protocol = protocol;
            hdr.checksum = 0;
            hdr.src = src.0.to_be();
            hdr.dst = dst.0.to_be();
            hdr.checksum =
                super::util::checksum(&ip_packet[..core::mem::size_of::<super::ip::IpHeader>()])
                    .to_be();
        }
        ip_packet[core::mem::size_of::<super::ip::IpHeader>()..].copy_from_slice(payload);
        return crate::net::ethernet::output(
            &mut dev_clone,
            mac,
            crate::net::ethernet::ETHERTYPE_IPV4,
            &ip_packet,
        );
    }

    Err(Error::NoSuchNode)
}
```

**IPアドレス文字列のパース:**

```rust
pub fn parse_ip_str(s: &str) -> Result<IpAddr> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(Error::InvalidAddress);
    }
    let a = parts[0].parse::<u8>().map_err(|_| Error::InvalidAddress)?;
    let b = parts[1].parse::<u8>().map_err(|_| Error::InvalidAddress)?;
    let c = parts[2].parse::<u8>().map_err(|_| Error::InvalidAddress)?;
    let d = parts[3].parse::<u8>().map_err(|_| Error::InvalidAddress)?;
    Ok(IpAddr::new(a, b, c, d))
}

pub fn ip_init() {
    crate::println!("[net] IP layer init");
    net_protocol_register(ProtocolType::IP, |dev, data| ip_input(dev, data));
}
```

### 3.7 ICMP

**ファイル:** `src/kernel/net/icmp.rs`

**ICMPタイプ:**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcmpType {
    EchoReply = 0,              // Echo Reply (ping応答)
    DestinationUnreachable = 3, // 宛先到達不能
    EchoRequest = 8,            // Echo Request (ping要求)
    TimeExceeded = 11,          // 時間超過
}
```

**ICMPヘッダー:**

```rust
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IcmpEcho {
    pub msg_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub id: u16,
    pub seq: u16,
}

impl IcmpEcho {
    pub const HEADER_SIZE: usize = size_of::<Self>();
}
```

**ICMP応答の種類:**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpReplyKind {
    Echo,
    Unreachable(u8),
}
```

**受信したICMP応答の保存用:**

```rust
#[derive(Debug, Clone)]
pub struct IcmpReply {
    pub src: IpAddr,
    pub id: u16,
    pub seq: u16,
    pub payload: Vec<u8>,
    pub kind: IcmpReplyKind,
    pub timestamp: usize,
}

static ICMP_REPLY_QUEUE: Mutex<VecDeque<IcmpReply>> = Mutex::new(VecDeque::new(), "icmp_queue");
static ICMP_REPLY_CV: Condvar = Condvar::new();
```

**ICMP受信処理:**

```rust
pub fn icmp_input(src: IpAddr, dst: IpAddr, data: &[u8]) -> Result<()> {
    if data.len() < IcmpEcho::HEADER_SIZE {
        return Err(Error::PacketTooShort);
    }
    if !verify_checksum(data) {
        return Err(Error::ChecksumError);
    }

    let echo = unsafe { &*(data.as_ptr() as *const IcmpEcho) };
    let id = u16::from_be(echo.id);
    let seq = u16::from_be(echo.seq);
    let payload = &data[IcmpEcho::HEADER_SIZE..];

    match echo.msg_type {
        t if t == IcmpType::EchoRequest as u8 => {
            crate::println!(
                "[icmp] Received Echo Request from {:?}, id={}, seq={}",
                src.to_bytes(),
                id,
                seq
            );
            icmp_echo_reply(dst, src, id, seq, payload)
        }
        t if t == IcmpType::EchoReply as u8 => {
            crate::println!(
                "[icmp] Received Echo Reply from {:?}, id={}, seq={}",
                src.to_bytes(),
                id,
                seq
            );
            icmp_notify_reply(src, id, seq, payload, IcmpReplyKind::Echo)
        }
        t if t == IcmpType::DestinationUnreachable as u8 => {
            let code = echo.code;

            if payload.len() < 28 {
                return Err(Error::PacketTooShort);
            }

            let inner_ip_hdr = &payload[..20];
            let inner_protocol = inner_ip_hdr[9];

            if inner_protocol != IpHeader::ICMP {
                return Err(Error::UnsupportedProtocol);
            }

            let inner_icmp = &payload[20..];
            if inner_icmp.len() < IcmpEcho::HEADER_SIZE {
                return Err(Error::UnsupportedProtocol);
            }

            let orig_id = u16::from_be_bytes([inner_icmp[4], inner_icmp[5]]);
            let orig_seq = u16::from_be_bytes([inner_icmp[6], inner_icmp[7]]);
            crate::println!(
                "[icmp] Destination Unreachable code={} for id={}, seq={}",
                code,
                orig_id,
                orig_seq
            );
            icmp_notify_reply(
                src,
                orig_id,
                orig_seq,
                payload,
                IcmpReplyKind::Unreachable(code),
            )
        }
        _ => Err(Error::UnsupportedProtocol),
    }
}
```

**Echo Reply送信:**

```rust
pub fn icmp_echo_reply(src: IpAddr, dst: IpAddr, id: u16, seq: u16, payload: &[u8]) -> Result<()> {
    let total_len = IcmpEcho::HEADER_SIZE + payload.len();
    let mut packet = vec![0u8; total_len];

    let echo = unsafe { &mut *(packet.as_mut_ptr() as *mut IcmpEcho) };
    echo.msg_type = IcmpType::EchoReply as u8;
    echo.code = 0;
    echo.checksum = 0;
    echo.id = id.to_be();
    echo.seq = seq.to_be();

    packet[IcmpEcho::HEADER_SIZE..].copy_from_slice(payload);
    echo.checksum = checksum(&packet).to_be();

    crate::println!(
        "[icmp] Sending Echo Reply to {:?}, id={}, seq={}",
        dst.to_bytes(),
        id,
        seq
    );

    let dev = net_device_by_name("lo").ok_or(Error::DeviceNotFound)?;
    ip_output(&dev, IpHeader::ICMP, src, dst, &packet)
}
```

**Echo Request送信:**

```rust
pub fn icmp_echo_request(dst: IpAddr, id: u16, seq: u16, payload: &[u8]) -> Result<()> {
    let total_len = IcmpEcho::HEADER_SIZE + payload.len();
    let mut packet = vec![0u8; total_len];

    let echo = unsafe { &mut *(packet.as_mut_ptr() as *mut IcmpEcho) };
    echo.msg_type = IcmpType::EchoRequest as u8;
    echo.code = 0;
    echo.checksum = 0;
    echo.id = id.to_be();
    echo.seq = seq.to_be();

    packet[IcmpEcho::HEADER_SIZE..].copy_from_slice(payload);
    echo.checksum = checksum(&packet).to_be();

    crate::println!(
        "[icmp] Sending Echo Request to {:?}, id={}, seq={}",
        dst.to_bytes(),
        id,
        seq
    );

    ip_output_route(dst, IpHeader::ICMP, &packet)
}
```

**応答をキューに追加:**

```rust
pub fn icmp_notify_reply(
    src: IpAddr,
    id: u16,
    seq: u16,
    payload: &[u8],
    kind: IcmpReplyKind,
) -> Result<()> {
    {
        let mut q = ICMP_REPLY_QUEUE.lock();
        let now = *crate::trap::TICKS.lock();
        q.push_back(IcmpReply {
            src,
            id,
            seq,
            payload: payload.to_vec(),
            kind,
            timestamp: now,
        });
    }
    ICMP_REPLY_CV.notify_all();
    Ok(())
}
```

**応答の受信待ち:**

```rust
pub fn icmp_recv_reply(id: u16, timeout_ms: u64) -> Result<IcmpReply> {
    let start = *crate::trap::TICKS.lock();
    let tick_ms = crate::param::TICK_MS as u64;
    let timeout_ticks = (timeout_ms + tick_ms - 1) / tick_ms;

    loop {
        crate::net::driver::virtio_net::poll_rx();

        if let Some(reply) = {
            let mut q = ICMP_REPLY_QUEUE.lock();
            if let Some(pos) = q.iter().position(|r| r.id == id) {
                Some(q.remove(pos).unwrap())
            } else {
                None
            }
        } {
            return Ok(reply);
        }

        let elapsed = *crate::trap::TICKS.lock() - start;
        if (elapsed as u64) >= timeout_ticks {
            return Err(Error::Timeout);
        }

        crate::proc::yielding();
    }
}
```

### 3.8 ループバックデバイス

**ファイル:** `src/kernel/net/driver/loopback.rs`

loopback: 自分自身への通信を処理するデバイス（127.0.0.1用）

```rust
const LOOPBACK_MTU: u16 = u16::MAX;

fn loopback_transmit(dev: &mut NetDevice, data: &[u8]) -> Result<()> {
    crate::println!("[loopback] transmit {} bytes", data.len());
    protocol::net_input_handler(dev, data)
}

fn loopback_open(dev: &mut NetDevice) -> Result<()> {
    crate::println!("[loopback] device opened");
    dev.set_flags(dev.flags() | NetDeviceFlags::UP | NetDeviceFlags::RUNNING);
    Ok(())
}

fn loopback_close(dev: &mut NetDevice) -> Result<()> {
    crate::println!("[loopback] device closed");
    dev.set_flags(dev.flags() & !NetDeviceFlags::RUNNING);
    Ok(())
}

pub fn loopback_init() -> Result<()> {
    let ops = NetDeviceOps {
        transmit: loopback_transmit,
        open: loopback_open,
        close: loopback_close,
    };

    let mut dev = NetDevice::new(
        "lo",
        NetDeviceType::Loopback,
        LOOPBACK_MTU,
        NetDeviceFlags::LOOPBACK | NetDeviceFlags::BROADCAST,
        0,
        0,
        [0; 6],
        ops,
    );
    dev.open()?;
    net_device_register(dev)?;
    crate::println!("[net] Loopback device initialized");
    Ok(())
}

pub fn loopback_setup() -> Result<()> {
    net_device_with_mut("lo", |dev| {
        let iface = NetInterface::new(IpAddr::LOOPBACK, IpAddr::new(255, 0, 0, 0));
        dev.add_interface(iface);
    })?;
    crate::println!("[net] Loopback interface configured: 127.0.0.1/8");
    Ok(())
}
```

### 3.9 virtio-netデバイスドライバ

**ファイル:** `src/kernel/net/driver/virtio_net.rs`

virtio-net: QEMU等の仮想化環境で提供される仮想ネットワークデバイス用のドライバ

**主要な定数:**

```rust
const VIRTIO_NET_F_MAC: u32 = 1 << 5;      // MACアドレス機能
const VIRTIO_NET_F_STATUS: u32 = 1 << 16;  // ステータス機能
const VIRTIO_NET_HDR_LEN: usize = 10;      // virtio-netヘッダー長
const NUM: usize = 32;                     // キューのエントリ数
```

**MMIOレジスタ定義:**

```rust
#[repr(usize)]
enum Mmio {
    MagicValue = 0x00,
    Version = 0x004,
    DeviceId = 0x008,
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
```

**virtqueue記述子構造:**

```rust
#[repr(C, align(16))]
struct VirtqDesc {
    addr: u64,     // バッファの物理アドレス
    len: u32,      // バッファサイズ
    flags: u16,    // NEXT, WRITEフラグ
    next: u16,     // 次の記述子のインデックス
}
const VIRTQ_DESC_F_NEXT: u16 = 1;   // 次の記述子が存在
const VIRTQ_DESC_F_WRITE: u16 = 2;  // デバイスが書き込み可能

#[repr(C, align(2))]
struct VirtqAvail {
    flags: u16,
    idx: u16,           // 次に追加する位置
    ring: [u16; NUM],   // 記述子インデックスのリング
    unused: u16,
}

#[repr(C)]
struct VirtqUsedElem {
    id: u32,    // 記述子ID
    len: u32,   // 使用したバッファサイズ
}

#[repr(C, align(4))]
struct VirtqUsed {
    flags: u16,
    idx: u16,                      // デバイスが次に書き込む位置
    ring: [VirtqUsedElem; NUM],    // 使用済み記述子のリング
}
```

**virtio-netヘッダー:**

```rust
#[repr(C, packed)]
struct VirtioNetHdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
}
```

**VirtioNet構造体:**

```rust
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
```

**デバイス初期化（mmio_init）:**

1. デバイス検証
2. ステータスネゴシエーション（ACKNOWLEDGE → DRIVER → FEATURES_OK → DRIVER_OK）
3. 機能ネゴシエーション（MACアドレス機能を要求）
4. RX/TXキューの設定
5. MACアドレスの読み取り
6. RXバッファの事前割り当て

```rust
fn mmio_init(&mut self) -> Result<()> {
    // デバイス検証
    if Mmio::MagicValue.read() != 0x7472_6976
        || Mmio::Version.read() != 2
        || Mmio::DeviceId.read() != 1
    {
        return Err(Error::DeviceNotFound);
    }

    // ステータスネゴシエーション
    let mut status: u32 = 0;
    unsafe { Mmio::Status.write(status) };
    status |= 0x1; // ACKNOWLEDGE
    unsafe { Mmio::Status.write(status) };
    status |= 0x2; // DRIVER
    unsafe { Mmio::Status.write(status) };

    // 機能ネゴシエーション
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

    // RXキュー設定
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

    // TXキュー設定
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

    // MACアドレス読み取り
    for i in 0..6 {
        self.mac[i] = unsafe {
            core::ptr::read_volatile((VIRTIO1 + Mmio::ConfigMac0 as usize + i) as *const u8)
        };
    }

    // RXバッファ事前割り当て
    for i in 0..NUM {
        self.alloc_rx_buf(i);
    }

    status |= 0x4; // DRIVER_OK
    unsafe { Mmio::Status.write(status) };
    Ok(())
}
```

**TX記述子の割り当て/解放:**

```rust
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
```

**RXバッファ割り当て:**

```rust
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
    unsafe { Mmio::QueueNotify.write(0) }; // rx queue
    for b in &mut self.rx_bufs[slot][..hdr_len] {
        *b = 0;
    }
}
```

**パケット送信:**

```rust
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
    unsafe { Mmio::QueueNotify.write(1) }; // tx queue
    Ok(())
}
```

**パケット受信（handle_used）:**

```rust
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
```

**デバイス登録:**

```rust
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

fn transmit(_dev: &mut NetDevice, data: &[u8]) -> Result<()> {
    let mut guard = NET.lock();
    guard.transmit(data)
}
```

**インターフェース設定:**

```rust
pub fn setup_iface() -> Result<()> {
    // host/gw: 192.0.2.1, guest: 192.0.2.2/24
    crate::net::interface::net_interface_setup(
        "eth0",
        IpAddr::new(192, 0, 2, 2),
        IpAddr::new(255, 255, 255, 0),
    )?;
    crate::net::route::add_route(crate::net::route::Route {
        dest: IpAddr::new(0, 0, 0, 0),
        mask: IpAddr::new(0, 0, 0, 0),
        gateway: Some(IpAddr::new(192, 0, 2, 1)),
        dev: "eth0",
    })?;
    Ok(())
}
```

**受信ポーリングと割り込みハンドラ:**

```rust
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
    // ack
    let intr_stat = Mmio::InterruptStatus.read();
    unsafe { Mmio::InterruptAck.write(intr_stat & 0x3) };
    poll_rx();
}
```

### 3.10 Ethernet層

**ファイル:** `src/kernel/net/ethernet.rs`

**Ethernetフレーム:**

```rust
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

pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
```

**受信処理:**

```rust
pub fn input(dev: &NetDevice, data: &[u8]) -> Result<()> {
    if data.len() < EthHeader::LEN {
        return Err(Error::PacketTooShort);
    }

    let hdr = unsafe { &*(data.as_ptr() as *const EthHeader) };
    let etype = ntoh16(hdr.ethertype);
    let payload = &data[EthHeader::LEN..];

    match etype {
        ETHERTYPE_ARP => crate::net::arp::input(dev, payload),
        ETHERTYPE_IPV4 => net_protocol_handler(dev, ProtocolType::IP, payload),
        _ => Err(Error::UnsupportedProtocol),
    }
}
```

**送信処理:**

```rust
pub fn output(dev: &mut NetDevice, dst_mac: [u8; 6], ethertype: u16, payload: &[u8]) -> Result<()> {
    if !dev.flags().contains(NetDeviceFlags::UP) {
        return Err(Error::NotConnected);
    }

    let mut frame = vec![0u8; EthHeader::LEN + payload.len()];
    {
        let hdr = unsafe { &mut *(frame.as_mut_ptr() as *mut EthHeader) };
        hdr.dst = dst_mac;
        hdr.src = dev.hw_addr;
        hdr.ethertype = ethertype.to_be();
    }
    frame[EthHeader::LEN..].copy_from_slice(payload);
    dev.transmit(&frame)
}
```

**プロトコル層の更新 (`src/kernel/net/protocol.rs`):**

```rust
    if dev.flags().contains(NetDeviceFlags::LOOPBACK) {
        return net_protocol_handler(dev, ProtocolType::IP, data);
    }

    if dev.dev_type == crate::net::device::NetDeviceType::Ethernet {
        return crate::net::ethernet::input(dev, data);
    }

    Err(Error::UnsupportedDevice)
```

### 3.11 ARP (Address Resolution Protocol)

**ファイル:** `src/kernel/net/arp.rs`

ARPはIPアドレスをMACアドレスに変換するプロトコル。

**定数定義:**

```rust
const ARP_HTYPE_ETHERNET: u16 = 1;
const ARP_PTYPE_IPV4: u16 = 0x0800;
const ARP_HLEN_ETH: u8 = 6;
const ARP_PLEN_IPV4: u8 = 4;
const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;
```

**ARPパケット構造体:**

```rust
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ArpPacket {
    htype: u16,   // Hardware Type (1=Ethernet)
    ptype: u16,   // Protocol Type (0x0800=IPv4)
    hlen: u8,     // Hardware Address Length (6)
    plen: u8,     // Protocol Address Length (4)
    oper: u16,    // Operation (1=Request, 2=Reply)
    sha: [u8; 6], // Sender Hardware Address
    spa: u32,     // Sender Protocol Address
    tha: [u8; 6], // Target Hardware Address
    tpa: u32,     // Target Protocol Address
}
```

**ARPキャッシュエントリ:**

```rust
#[derive(Clone, Copy, Debug)]
struct ArpEntry {
    ip: IpAddr,
    mac: [u8; 6],
    valid: bool,
}

static ARP_TABLE: Mutex<Vec<ArpEntry>> = Mutex::new(Vec::new(), "arp_table");
static ARP_CV: Condvar = Condvar::new();
```

**ARPキャッシュの検索:**

```rust
fn lookup(ip: IpAddr) -> Option<[u8; 6]> {
    let table = ARP_TABLE.lock();
    table
        .iter()
        .find(|e| e.valid && e.ip.0 == ip.0)
        .map(|e| e.mac)
}
```

**ARPキャッシュへの追加:**

```rust
fn insert(ip: IpAddr, mac: [u8; 6]) {
    {
        let mut table = ARP_TABLE.lock();
        if let Some(e) = table.iter_mut().find(|e| e.ip.0 == ip.0) {
            e.mac = mac;
            e.valid = true;
        } else {
            table.push(ArpEntry {
                ip,
                mac,
                valid: true,
            });
        }
    }
    crate::println!("[arp] insert {:?} -> {:02x?}", ip.to_bytes(), mac);
    ARP_CV.notify_all();
}
```

**ARP受信処理:**

```rust
pub fn input(dev: &NetDevice, data: &[u8]) -> Result<()> {
    if data.len() < core::mem::size_of::<ArpPacket>() {
        return Err(Error::PacketTooShort);
    }
    let pkt = unsafe { &*(data.as_ptr() as *const ArpPacket) };
    if ntoh16(pkt.htype) != ARP_HTYPE_ETHERNET
        || ntoh16(pkt.ptype) != ARP_PTYPE_IPV4
        || pkt.hlen != ARP_HLEN_ETH
        || pkt.plen != ARP_PLEN_IPV4
    {
        return Err(Error::UnsupportedProtocol);
    }
    let oper = ntoh16(pkt.oper);
    let sender_ip = IpAddr(u32::from_be(pkt.spa));
    let sender_mac = pkt.sha;
    let target_ip = IpAddr(u32::from_be(pkt.tpa));

    crate::println!(
        "[arp] oper={} sender={:?} target={:?}",
        oper,
        sender_ip.to_bytes(),
        target_ip.to_bytes()
    );

    match oper {
        ARP_OP_REPLY => {
            crate::println!("[arp] reply from {:?}", sender_ip.to_bytes());
            insert(sender_ip, sender_mac);
        }
        ARP_OP_REQUEST => {
            if let Some(iface) = dev.interfaces.iter().find(|i| i.addr.0 == target_ip.0) {
                send_reply(dev, sender_mac, sender_ip, iface.addr)?;
            }
        }
        _ => {}
    }
    Ok(())
}
```

**ARP Reply送信:**

```rust
fn send_reply(dev: &NetDevice, dst_mac: [u8; 6], dst_ip: IpAddr, src_ip: IpAddr) -> Result<()> {
    let mut buf = [0u8; core::mem::size_of::<ArpPacket>()];
    let pkt = unsafe { &mut *(buf.as_mut_ptr() as *mut ArpPacket) };
    pkt.htype = hton16(ARP_HTYPE_ETHERNET);
    pkt.ptype = hton16(ARP_PTYPE_IPV4);
    pkt.hlen = ARP_HLEN_ETH;
    pkt.plen = ARP_PLEN_IPV4;
    pkt.oper = hton16(ARP_OP_REPLY);
    pkt.sha = dev.hw_addr;
    pkt.spa = src_ip.0.to_be();
    pkt.tha = dst_mac;
    pkt.tpa = dst_ip.0.to_be();

    let mut dev_clone = dev.clone();
    eth_output(&mut dev_clone, dst_mac, ETHERTYPE_ARP, &buf)
}
```

**ARP Request送信:**

```rust
fn send_request(dev: &mut NetDevice, target_ip: IpAddr, sender_ip: IpAddr) -> Result<()> {
    let mut buf = [0u8; core::mem::size_of::<ArpPacket>()];
    let pkt = unsafe { &mut *(buf.as_mut_ptr() as *mut ArpPacket) };
    pkt.htype = hton16(ARP_HTYPE_ETHERNET);
    pkt.ptype = hton16(ARP_PTYPE_IPV4);
    pkt.hlen = ARP_HLEN_ETH;
    pkt.plen = ARP_PLEN_IPV4;
    pkt.oper = hton16(ARP_OP_REQUEST);
    pkt.sha = dev.hw_addr;
    pkt.spa = sender_ip.0.to_be();
    pkt.tha = [0; 6];
    pkt.tpa = target_ip.0.to_be();

    eth_output(dev, [0xFF; 6], ETHERTYPE_ARP, &buf)
}
```

**IPアドレスのMAC解決（キャッシュ確認 → Request送信 → Reply待機）:**

```rust
pub fn resolve(
    dev_name: &str,
    target_ip: IpAddr,
    sender_ip: IpAddr,
    timeout_ticks: usize,
) -> Result<[u8; 6]> {
    if let Some(mac) = lookup(target_ip) {
        crate::println!("[arp] cache hit {:?}", mac);
        return Ok(mac);
    }
    {
        let mut list = crate::net::device::NET_DEVICES.lock();
        let dev = list
            .iter_mut()
            .find(|d| d.name() == dev_name)
            .ok_or(Error::DeviceNotFound)?;
        if !dev.flags().contains(NetDeviceFlags::UP) {
            return Err(Error::NotConnected);
        }
        crate::println!(
            "[arp] send request who-has {:?} tell {:?}",
            target_ip.to_bytes(),
            sender_ip.to_bytes()
        );
        send_request(dev, target_ip, sender_ip)?;
    }

    let start = *crate::trap::TICKS.lock();
    loop {
        crate::net::driver::virtio_net::poll_rx();
        if let Some(mac) = lookup(target_ip) {
            crate::println!("[arp] resolved {:?} -> {:02x?}", target_ip.to_bytes(), mac);
            return Ok(mac);
        }
        let elapsed = *crate::trap::TICKS.lock() - start;
        if elapsed > timeout_ticks {
            crate::println!("[arp] timeout waiting reply");
            return Err(Error::Timeout);
        }
        crate::proc::yielding();
    }
}
```

### 3.12 ルーティングテーブル

**ファイル:** `src/kernel/net/route.rs`

```rust
#[derive(Clone, Copy)]
pub struct Route {
    pub dest: IpAddr,              // 宛先ネットワーク
    pub mask: IpAddr,              // ネットマスク
    pub gateway: Option<IpAddr>,   // ゲートウェイ（Noneなら直接配送）
    pub dev: &'static str,         // 使用するデバイス名
}

static mut ROUTES: [Option<Route>; 8] = [None; 8];

pub fn add_route(route: Route) -> Result<()> {
    unsafe {
        for slot in ROUTES.iter_mut() {
            if slot.is_none() {
                *slot = Some(route);
                return Ok(());
            }
        }
    }
    Err(Error::StorageFull)
}

pub fn lookup(dst: IpAddr) -> Option<Route> {
    unsafe {
        let mut best: Option<Route> = None;
        for r in ROUTES.iter().flatten() {
            if (dst.0 & r.mask.0) == (r.dest.0 & r.mask.0) {
                if best.map(|b| mask_len(r.mask) > mask_len(b.mask)).unwrap_or(true) {
                    best = Some(*r);
                }
            }
        }
        best
    }
}
```

### 3.13 システムコール

**ファイル:** `src/kernel/syscall.rs`

**システムコール番号を追加:**

```rust
#[derive(Copy, Clone, Debug)]
#[repr(usize)]
pub enum SysCalls {
    // 既存のシステムコール...
    IcmpEchoRequest = 24,
    IcmpRecvReply = 25,
    Clocktime = 26,
}
```

**システムコール実装:**

```rust
pub fn icmpechorequest() -> Result<usize> {
    unsafe {
        let mut sbinfo_dst: SBInfo = Default::default();
        let sbinfo_dst = SBInfo::from_arg(0, &mut sbinfo_dst)?;
        let mut dst_bytes = alloc::vec![0u8; sbinfo_dst.len];
        crate::proc::either_copyin(&mut dst_bytes[..], sbinfo_dst.ptr.into())?;
        let dst_str = core::str::from_utf8(&dst_bytes).map_err(|_| Error::InvalidAddress)?;
        let dst = crate::net::ip::parse_ip_str(dst_str)?;

        let id = argraw(1) as u16;
        let seq = argraw(2) as u16;

        let mut sbinfo_payload: SBInfo = Default::default();
        let sbinfo_payload = SBInfo::from_arg(3, &mut sbinfo_payload)?;
        let mut payload = alloc::vec![0u8; sbinfo_payload.len];
        crate::proc::either_copyin(&mut payload[..], sbinfo_payload.ptr.into())?;

        crate::net::icmp::icmp_echo_request(dst, id, seq, &payload)?;
        Ok(0)
    }
}

pub fn icmprecvreply() -> Result<usize> {
    unsafe {
        let id = argraw(0) as u16;
        let timeout_ms = argraw(1) as u64;

        let mut sbinfo: SBInfo = Default::default();
        let sbinfo = SBInfo::from_arg(2, &mut sbinfo)?;

        let reply = crate::net::icmp::icmp_recv_reply(id, timeout_ms)?;

        let copy_len = core::cmp::min(reply.payload.len(), sbinfo.len);
        crate::proc::either_copyout(sbinfo.ptr.into(), &reply.payload[..copy_len])?;
        Ok(copy_len)
    }
}

pub fn clocktime() -> Result<usize> {
    let ticks = *crate::trap::TICKS.lock();
    let tick_ms = crate::param::TICK_MS as usize;
    let us = ticks * tick_ms * 1000;
    Ok(us)
}
```

**システムコールテーブルに登録:**

```rust
impl SysCalls {
    pub const TABLE: [(Fn, &'static str); variant_count::<Self>()] = [
        // ...
        (Fn::I(Self::icmpechorequest), "(dst: &str, id: u16, seq: u16, payload: &[u8])"),
        (Fn::I(Self::icmprecvreply), "(id: u16, timeout_ms: u64, buf: &mut [u8])"),
        (Fn::I(Self::clocktime), "()"),
    ];
}
```

### 3.14 ユーザーライブラリ

**ファイル:** `src/user/lib/lib.rs`

**システムコールのラッパー:**

```rust
pub fn icmp_echo_request(dst: &str, id: u16, seq: u16, payload: &[u8]) -> sys::Result<()> {
    sys::icmpechorequest(dst.as_bytes(), id, seq, payload)?;
    Ok(())
}

pub fn icmp_recv_reply(id: u16, timeout_ms: u64, buf: &mut [u8]) -> sys::Result<usize> {
    let n = sys::icmprecvreply(id, timeout_ms, buf)?;
    Ok(n)
}
```

### 3.15 pingコマンド

**ファイル:** `src/user/bin/ping.rs`

```rust
#![no_std]
extern crate alloc;

use ulib::sys::Error;
use ulib::{env, icmp_echo_request, icmp_recv_reply, print, println, sys};

fn main() {
    let mut args = env::args();
    let _prog = args.next();
    let Some(dst) = args.next() else {
        println!("usage: ping <ip address>");
        return;
    };

    let id = (sys::getpid().unwrap_or(0) & 0xFFFF) as u16;
    println!("PING {} ({}): 56 data bytes", dst, dst);

    for seq in 0..3 {
        let mut payload = [0u8; 56];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (0x20 + (i % 64)) as u8;
        }

        let start_us = sys::clocktime().unwrap_or(0) as u64;
        if let Err(e) = icmp_echo_request(dst, id, seq as u16, &payload) {
            println!("failed to send request: {:?}", e);
            continue;
        }

        let mut buf = [0u8; 256];
        match icmp_recv_reply(id, 3000, &mut buf) {
            Ok(n) => {
                let end_us = sys::clocktime().unwrap_or(0) as u64;
                let elapsed_us = end_us.saturating_sub(start_us);
                let elapsed_ms = elapsed_us / 1000;
                let rem_us = elapsed_us % 1000;

                println!(
                    "{} bytes from {}: icmp_seq={} ttl=64 time={}.{:03} ms",
                    n + 8,  // ICMPヘッダー8バイト + ペイロード
                    dst,
                    seq,
                    elapsed_ms,
                    rem_us
                );
            }
            Err(Error::Timeout) => {
                println!("Request timeout for icmp_seq {}", seq);
            }
            Err(e) => {
                println!("recv error: {:?}", e);
            }
        }

        sys::sleep(100).ok();
    }
}
```

### 3.16 初期化処理

**ファイル:** `src/kernel/net.rs`

```rust
pub fn init() {
    crate::println!("[kernel] Network stack init");

    ip::ip_init();

    driver::loopback::loopback_init().expect("loopback init failed");
    driver::loopback::loopback_setup().expect("loopback setup failed");

    driver::virtio_net::init().expect("virtio-net init failed");
    driver::virtio_net::setup_iface().expect("virtio-net iface failed");

    println!("[kernel] Network stack initialized");
}
```

**カーネルメインから呼び出し (`src/kernel/main.rs`):**

```rust
pub fn main() {
    // ... 既存の初期化処理 ...

    crate::net::init();

    // ... 残りの処理 ...
}
```
