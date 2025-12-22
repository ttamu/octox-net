# nslookup

## 目次

- [nslookup](#nslookup)
  - [目次](#目次)
  - [1. 期待される動作](#1-期待される動作)
  - [2. システムアーキテクチャ](#2-システムアーキテクチャ)
    - [2.1 コンポーネント構成](#21-コンポーネント構成)
    - [2.2 ディレクトリ構造](#22-ディレクトリ構造)
    - [2.3 データフロー](#23-データフロー)
      - [2.3.1 DNS クエリ送信時のデータフロー](#231-dns-クエリ送信時のデータフロー)
      - [2.3.2 DNS レスポンス受信時のデータフロー](#232-dns-レスポンス受信時のデータフロー)
      - [2.3.3 パケット構造の変化](#233-パケット構造の変化)
        - [2.3.3.1 送信時](#2331-送信時)
        - [2.3.3.2 受信時](#2332-受信時)
  - [3. 実装](#3-実装)
    - [3.1 エラー型の拡張](#31-エラー型の拡張)
    - [3.2 IP層の拡張](#32-ip層の拡張)
    - [3.3 UDPプロトコル](#33-udpプロトコル)
    - [3.4 DNSプロトコル](#34-dnsプロトコル)
    - [3.5 システムコール](#35-システムコール)
    - [3.6 ユーザーライブラリ](#36-ユーザーライブラリ)
    - [3.7 nslookupコマンド](#37-nslookupコマンド)
    - [3.8 初期化処理](#38-初期化処理)

## 1. 期待される動作

nslookupコマンドを実行すると、以下のように出力される。

```bash
$ nslookup example.com
Resolving: example.com

Name:    example.com
Address: 104.18.27.120
```

## 2. システムアーキテクチャ

### 2.1 コンポーネント構成

```text
┌─────────────────────────────────────────────────────────┐
│                  User Space (ユーザー空間)                │
├─────────────────────────────────────────────────────────┤
│  nslookup コマンド (src/user/bin/nslookup.rs)            │
│   ↓ システムコール                                        │
├─────────────────────────────────────────────────────────┤
│                  Kernel Space (カーネル空間)              │
├─────────────────────────────────────────────────────────┤
│  System Call Layer (syscall.rs)                         │
│   - dns_resolve()  DNS解決システムコール                   │
│          ↓                        ↑                     │
├─────────────────────────────────────────────────────────┤
│  Application Layer (DNS)                                │
│   - dns.rs          DNSクエリの生成/DNSレスポンスの解析     │
│          ↓                        ↑                     │
├─────────────────────────────────────────────────────────┤
│  Transport Layer (UDP)                                  │
│   - udp.rs          UDPパケットの送受信                    │
│          ↓                        ↑                     │
├─────────────────────────────────────────────────────────┤
│  Network Layer (IP)                                     │
│   - ip.rs           IPパケットの生成/解析/ルーティング       │
│          ↓                        ↑                     │
├─────────────────────────────────────────────────────────┤
│  Link Layer (Ethernet/ARP)                              │
│   - ethernet.rs     Ethernetフレーム処理                  │
│   - arp.rs          IPアドレス→MACアドレス解決             │
│          ↓                        ↑                     │
├─────────────────────────────────────────────────────────┤
│  Device Layer                                           │
│   - virtio_net.rs   NIC (外部通信用)                      │
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
│   │   ├── udp.rs          UDPプロトコルの実装
│   │   ├── dns.rs          DNSプロトコルの実装
│   │   ├── ethernet.rs     Ethernetフレーム処理
│   │   ├── arp.rs          ARP処理
│   │   ├── route.rs        ルーティングテーブル
│   │   ├── util.rs         チェックサム計算など
│   │   ├── driver.rs       ドライバモジュール
│   │   └── driver/
│   │       └── virtio_net.rs  virtio-netドライバ
│   ├── syscall.rs          システムコール実装
│   └── error.rs            エラー型定義
└── user/
    ├── bin/
    │   └── nslookup.rs     nslookupコマンド実装
    └── lib/
        └── lib.rs          ユーザーライブラリ
```

### 2.3 データフロー

#### 2.3.1 DNS クエリ送信時のデータフロー

```text
┌─────────────────────────────────────────────────────────────┐
│ User Space: nslookup コマンド                                │
│  1. dns_resolve("example.com")                              │
└────────────────────┬────────────────────────────────────────┘
                     │ システムコール (SYS_DNS_RESOLVE)
┌────────────────────▼────────────────────────────────────────┐
│ Kernel: syscall.rs                                          │
│  2. dns_resolve()                                           │
│     - ドメイン名を取得                                         │
│     - ユーザー空間からデータをコピー                            │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ DNS: dns.rs                                                 │
│  3. dns_resolve(domain)                                     │
│     - UDP PCBを割り当て                                       │
│     - エフェメラルポートにバインド                              │
│     - DNSクエリパケットを構築                                  │
│       Transaction ID設定                                     │
│       Flags: 再帰要求                                        │
│       Question: ドメイン名, Type=A, Class=IN                 │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ UDP: udp.rs                                                 │
│  4. udp_sendto(sockfd, 8.8.8.8:53, query)                   │
│     - UDPヘッダーを作成                                       │
│       Src Port: エフェメラルポート                             │
│       Dst Port: 53                                          │
│       Length, Checksum設定                                  │
│     - Pseudo Headerでチェックサム計算                         │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ IP Layer: ip.rs                                             │
│  5. ip_output_route(8.8.8.8, UDP, udp_packet)               │
│     - ルーティングテーブル検索                                  │
│     - IPヘッダーを作成                                        │
│       Version=4, Protocol=17(UDP), TTL=64                   │
│       Src/Dst IP設定                                         │
│     - IPチェックサムを計算                                     │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ Ethernet Layer: ethernet.rs                                 │
│  6. ARP解決 (IP→MAC)                                         │
│  7. Ethernetヘッダー追加                                      │
│     Dst MAC, Src MAC, Type=0x0800                           │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ Device: virtio_net.rs                                       │
│  8. transmit(ethernet_frame)                                │
│     - virtioキューに追加                                      │
│     - QEMUに送信通知                                          │
└─────────────────────────────────────────────────────────────┘
```

#### 2.3.2 DNS レスポンス受信時のデータフロー

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
┌────────────────────▼────────────────────────────────────────┐
│ Ethernet Layer: ethernet.rs                                 │
│  2. input(dev, frame)                                       │
│     - Ethernetヘッダーをパース                                 │
│     - EtherType判定 (0x0800=IP)                              │
└────────────────────┬────────────────────────────────────────┘
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
│     - Protocol判定 (17=UDP)                                  │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ UDP: udp.rs                                                 │
│  5. udp_input(src, dst, data)                               │
│     - UDPヘッダーをパース                                      │
│     - チェックサム検証                                         │
│     - ポート番号で宛先PCBを検索                                │
│     - 受信キューに追加                                         │
└────────────────────┬────────────────────────────────────────┘
                     │ (udp_recvfrom がポーリング中)
┌────────────────────▼────────────────────────────────────────┐
│ DNS: dns.rs                                                 │
│  6. udp_recvfrom(sockfd, buf)                               │
│     - 受信キューからデータを取得                                │
│  7. parse_dns_response(data)                                │
│     - DNSヘッダーをパース                                      │
│     - Question セクションをスキップ                            │
│     - Answer セクションから A レコードを抽出                   │
│     - IPv4アドレスを返す                                      │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ Kernel: syscall.rs                                          │
│  8. dns_resolve() が成功                                     │
│     - ユーザー空間にIPアドレスをコピー                          │
└────────────────────┬────────────────────────────────────────┘
                     │ システムコールリターン
┌────────────────────▼────────────────────────────────────────┐
│ User Space: nslookup コマンド                                │
│  9. dns_resolve() が成功                                     │
│     - IPアドレスを表示                                        │
└─────────────────────────────────────────────────────────────┘
```

#### 2.3.3 パケット構造の変化

##### 2.3.3.1 送信時

```text
[アプリケーション層 - DNS]
  ┌──────────────┬──────────────┐
  │ DNS Header   │ Question     │
  │  (12 bytes)  │ (variable)   │
  └──────────────┴──────────────┘
    ↓
[UDPプロトコル] udp_sendto()
  ┌──────────────┬──────────────┬──────────────┐
  │ UDP Header   │ DNS Header   │ Question     │
  │  (8 bytes)   │  (12 bytes)  │ (variable)   │
  └──────────────┴──────────────┴──────────────┘
    ↓
[IP層] ip_output()
  ┌──────────────┬──────────────┬──────────────┬──────────────┐
  │  IP Header   │ UDP Header   │ DNS Header   │ Question     │
  │  (20 bytes)  │  (8 bytes)   │  (12 bytes)  │ (variable)   │
  └──────────────┴──────────────┴──────────────┴──────────────┘
    ↓
[Ethernet層] ethernet::output()
  ┌─────────────┬──────────────┬──────────────┬──────────────┬──────────────┐
  │ Eth Header  │  IP Header   │ UDP Header   │ DNS Header   │ Question     │
  │  (14 bytes) │  (20 bytes)  │  (8 bytes)   │  (12 bytes)  │ (variable)   │
  └─────────────┴──────────────┴──────────────┴──────────────┴──────────────┘
    ↓
[物理層] → ネットワークへ送信
```

##### 2.3.3.2 受信時

```text
[物理層] ← ネットワークから受信
  ┌─────────────┬──────────────┬──────────────┬──────────────┬──────────────┐
  │ Eth Header  │  IP Header   │ UDP Header   │ DNS Header   │ Answers      │
  │  (14 bytes) │  (20 bytes)  │  (8 bytes)   │  (12 bytes)  │ (variable)   │
  └─────────────┴──────────────┴──────────────┴──────────────┴──────────────┘
    ↓
[Ethernet層] ethernet::input() Ethernetヘッダーを除去
  ┌──────────────┬──────────────┬──────────────┬──────────────┐
  │  IP Header   │ UDP Header   │ DNS Header   │ Answers      │
  │  (20 bytes)  │  (8 bytes)   │  (12 bytes)  │ (variable)   │
  └──────────────┴──────────────┴──────────────┴──────────────┘
    ↓
[IP層] ip_input() IPヘッダーを除去
  ┌──────────────┬──────────────┬──────────────┐
  │ UDP Header   │ DNS Header   │ Answers      │
  │  (8 bytes)   │  (12 bytes)  │ (variable)   │
  └──────────────┴──────────────┴──────────────┘
    ↓
[UDPプロトコル] udp_input() UDPヘッダーを除去
  ┌──────────────┬──────────────┐
  │ DNS Header   │ Answers      │
  │  (12 bytes)  │ (variable)   │
  └──────────────┴──────────────┘
    ↓
[DNSプロトコル] parse_dns_response() DNSレスポンスをパース
  IPv4 Address (4 bytes)
    ↓
[アプリケーション層]
  IPv4 Address (4 bytes)
```

## 3. 実装

### 3.1 エラー型の拡張

**ファイル:** `src/kernel/error.rs`

**UDP/DNS関連のエラーを追加:**

```rust
#[repr(isize)]
#[derive(PartialEq, Debug)]
pub enum Error {
    // 既存のエラー...
    WouldBlock = -9,
    NoPcbAvailable = -43,
    InvalidPcbIndex = -44,
    InvalidPcbState = -45,
    PortInUse = -46,
    NoPortAvailable = -47,
    InvalidLength = -48,
    NoMatchingPcb = -49,
}
```

**`as_str()`メソッドに追加:**

```rust
impl Error {
    pub fn as_str(&self) -> &'static str {
        use Error::*;
        match *self {
            // 既存のエラー...
            WouldBlock => "operation would block",
            NoPcbAvailable => "no PCB available",
            InvalidPcbIndex => "invalid PCB index",
            InvalidPcbState => "invalid PCB state",
            PortInUse => "port in use",
            NoPortAvailable => "no port available",
            InvalidLength => "invalid length",
            NoMatchingPcb => "no matching PCB",
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
            -9 => WouldBlock,
            -43 => NoPcbAvailable,
            -44 => InvalidPcbIndex,
            -45 => InvalidPcbState,
            -46 => PortInUse,
            -47 => NoPortAvailable,
            -48 => InvalidLength,
            -49 => NoMatchingPcb,
            _ => Uncategorized,
        }
    }
}
```

### 3.2 IP層の拡張

**ファイル:** `src/kernel/net/ip.rs`

**UDPプロトコルのサポート追加:**

IPヘッダーにUDPプロトコル番号を追加:

```rust
impl IpHeader {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
}
```

**IP受信処理でUDPをディスパッチ:**

```rust
pub fn ip_input(_dev: &NetDevice, data: &[u8]) -> Result<()> {
    // ... IPヘッダーのパース処理 ...

    let payload = &data[hlen..total_len];
    match header.protocol {
        IpHeader::ICMP => icmp::icmp_input(src, dst, payload),
        IpHeader::UDP => udp::udp_input(src, dst, payload),
        _ => Err(Error::UnsupportedProtocol),
    }
}
```

### 3.3 UDPプロトコル

**ファイル:** `src/kernel/net/udp.rs`

**定数定義:**

```rust
/// UDP Protocol number (for IP header)
pub const UDP_PROTOCOL: u8 = IpHeader::UDP;

/// UDP source port range (ephemeral ports)
const UDP_SOURCE_PORT_MIN: u16 = 49152;
const UDP_SOURCE_PORT_MAX: u16 = 65535;

/// Maximum number of UDP PCBs
const UDP_PCB_SIZE: usize = 16;
```

**UDPヘッダー構造体 (RFC 768):**

```rust
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}
```

**Pseudo Header (チェックサム計算用):**

```rust
#[repr(C, packed)]
struct PseudoHeader {
    src: u32,
    dst: u32,
    zero: u8,
    protocol: u8,
    length: u16,
}
```

**UDPエンドポイント:**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpEndpoint {
    pub addr: IpAddr,
    pub port: u16,
}

impl UdpEndpoint {
    pub const fn new(addr: IpAddr, port: u16) -> Self {
        Self { addr, port }
    }

    pub const fn any(port: u16) -> Self {
        Self {
            addr: IpAddr(0),
            port,
        }
    }
}
```

**UDP PCB (Protocol Control Block):**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpState {
    Free,
    Open,
    Closing,
}

#[derive(Debug, Clone)]
struct UdpPacket {
    foreign: UdpEndpoint,
    data: Vec<u8>,
}

struct UdpPcb {
    state: UdpState,
    local: UdpEndpoint,
    recv_queue: VecDeque<UdpPacket>,
}

impl UdpPcb {
    const fn new() -> Self {
        Self {
            state: UdpState::Free,
            local: UdpEndpoint::new(IpAddr(0), 0),
            recv_queue: VecDeque::new(),
        }
    }

    fn is_free(&self) -> bool {
        self.state == UdpState::Free
    }

    fn is_match(&self, dst: IpAddr, dst_port: u16) -> bool {
        if self.state != UdpState::Open {
            return false;
        }
        if self.local.port != dst_port {
            return false;
        }
        self.local.addr.0 == 0 || self.local.addr.0 == dst.0
    }
}
```

**グローバルPCBテーブル:**

```rust
static UDP_PCBS: Mutex<[UdpPcb; UDP_PCB_SIZE]> =
    Mutex::new([const { UdpPcb::new() }; UDP_PCB_SIZE], "udp_pcbs");

static NEXT_EPHEMERAL_PORT: Mutex<u16> = Mutex::new(UDP_SOURCE_PORT_MIN, "udp_port");
```

**PCBの割り当て:**

```rust
pub fn udp_pcb_alloc() -> Result<usize> {
    let mut pcbs = UDP_PCBS.lock();
    for (i, pcb) in pcbs.iter_mut().enumerate() {
        if pcb.state == UdpState::Free {
            pcb.state = UdpState::Open;
            pcb.recv_queue.clear();
            return Ok(i);
        }
    }
    Err(Error::NoPcbAvailable)
}

pub fn udp_pcb_release(index: usize) -> Result<()> {
    let mut pcbs = UDP_PCBS.lock();
    if index >= UDP_PCB_SIZE {
        return Err(Error::InvalidPcbIndex);
    }
    let pcb = &mut pcbs[index];
    if pcb.state == UdpState::Free {
        return Err(Error::InvalidPcbIndex);
    }
    pcb.state = UdpState::Free;
    pcb.recv_queue.clear();
    Ok(())
}
```

**PCBのバインド:**

```rust
pub fn udp_bind(index: usize, mut local: UdpEndpoint) -> Result<()> {
    let mut pcbs = UDP_PCBS.lock();
    if index >= UDP_PCB_SIZE {
        return Err(Error::InvalidPcbIndex);
    }
    if pcbs[index].state != UdpState::Open {
        return Err(Error::InvalidPcbState);
    }

    if local.port != 0 {
        for (i, other) in pcbs.iter().enumerate() {
            if i != index
                && other.state == UdpState::Open
                && other.local.port == local.port
                && (other.local.addr.0 == 0
                    || local.addr.0 == 0
                    || other.local.addr.0 == local.addr.0)
            {
                return Err(Error::PortInUse);
            }
        }
    } else {
        let mut next_port = NEXT_EPHEMERAL_PORT.lock();
        for _ in 0..(UDP_SOURCE_PORT_MAX - UDP_SOURCE_PORT_MIN + 1) {
            let port = *next_port;
            *next_port += 1;
            if *next_port > UDP_SOURCE_PORT_MAX {
                *next_port = UDP_SOURCE_PORT_MIN;
            }

            let mut available = true;
            for (i, other) in pcbs.iter().enumerate() {
                if i != index && other.state == UdpState::Open && other.local.port == port {
                    available = false;
                    break;
                }
            }

            if available {
                local.port = port;
                break;
            }
        }

        if local.port == 0 {
            return Err(Error::NoPortAvailable);
        }
    }

    pcbs[index].local = local;
    Ok(())
}
```

**UDPチェックサム計算:**

```rust
fn udp_checksum(src: IpAddr, dst: IpAddr, data: &[u8]) -> u16 {
    let mut buf = Vec::new();

    let pseudo = PseudoHeader {
        src: hton32(src.0),
        dst: hton32(dst.0),
        zero: 0,
        protocol: UDP_PROTOCOL,
        length: hton16(data.len() as u16),
    };
    let pseudo_bytes = unsafe {
        core::slice::from_raw_parts(&pseudo as *const _ as *const u8, size_of::<PseudoHeader>())
    };
    buf.extend_from_slice(pseudo_bytes);
    buf.extend_from_slice(data);

    checksum(&buf)
}

fn verify_udp_checksum(src: IpAddr, dst: IpAddr, data: &[u8]) -> bool {
    let header = unsafe { &*(data.as_ptr() as *const UdpHeader) };
    if header.checksum == 0 {
        return true;
    }

    let csum = udp_checksum(src, dst, data);
    csum == 0xFFFF || csum == 0
}
```

**送信元アドレスの選択:**

```rust
fn select_src_addr(dst: IpAddr) -> Result<IpAddr> {
    if dst.0 == IpAddr::LOOPBACK.0 {
        return Ok(IpAddr::LOOPBACK);
    }
    if let Some(route) = route::lookup(dst) {
        if let Some(dev) = net_device_by_name(route.dev) {
            if let Some(iface) = dev
                .interfaces
                .iter()
                .find(|i| (dst.0 & i.netmask.0) == (i.addr.0 & i.netmask.0))
            {
                return Ok(iface.addr);
            }
            if let Some(iface) = dev.interfaces.first() {
                return Ok(iface.addr);
            }
        }
    }
    Err(Error::NoSuchNode)
}
```

**UDP受信処理:**

```rust
pub fn udp_input(src: IpAddr, dst: IpAddr, data: &[u8]) -> Result<()> {
    if data.len() < size_of::<UdpHeader>() {
        return Err(Error::PacketTooShort);
    }

    let header = unsafe { &*(data.as_ptr() as *const UdpHeader) };
    let src_port = ntoh16(header.src_port);
    let dst_port = ntoh16(header.dst_port);
    let length = ntoh16(header.length) as usize;

    if length < size_of::<UdpHeader>() || length > data.len() {
        return Err(Error::InvalidLength);
    }

    crate::println!(
        "[udp] received: {}:{} -> {}:{}, {} bytes",
        src.to_bytes()[0],
        src_port,
        dst.to_bytes()[0],
        dst_port,
        length
    );

    if !verify_udp_checksum(src, dst, &data[..length]) {
        return Err(Error::ChecksumError);
    }

    let mut pcbs = UDP_PCBS.lock();

    for pcb in pcbs.iter_mut() {
        if pcb.state == UdpState::Open {
            if pcb.local.port != dst_port {
                continue;
            }
            if pcb.local.addr.0 != 0 && pcb.local.addr.0 != dst.0 {
                continue;
            }

            let payload = &data[size_of::<UdpHeader>()..length];
            let packet = UdpPacket {
                foreign: UdpEndpoint::new(src, src_port),
                data: payload.to_vec(),
            };
            pcb.recv_queue.push_back(packet);
            return Ok(());
        }
    }

    Err(Error::NoMatchingPcb)
}
```

**UDP送信処理:**

```rust
pub fn udp_output(src: UdpEndpoint, dst: UdpEndpoint, data: &[u8]) -> Result<()> {
    let total_len = size_of::<UdpHeader>() + data.len();
    if total_len > 65535 {
        return Err(Error::PacketTooLarge);
    }

    let mut packet = alloc::vec![0u8; total_len];
    let header = unsafe { &mut *(packet.as_mut_ptr() as *mut UdpHeader) };

    header.src_port = hton16(src.port);
    header.dst_port = hton16(dst.port);
    header.length = hton16(total_len as u16);
    header.checksum = 0;

    packet[size_of::<UdpHeader>()..].copy_from_slice(data);

    let src_ip = if src.addr.0 != 0 {
        src.addr
    } else {
        select_src_addr(dst.addr)?
    };
    let csum = udp_checksum(src_ip, dst.addr, &packet);
    header.checksum = if csum == 0 { 0xFFFF } else { hton16(csum) };

    crate::println!(
        "[udp] sending: {}:{} -> {}:{}, {} bytes",
        src.addr.to_bytes()[0],
        src.port,
        dst.addr.to_bytes()[0],
        dst.port,
        total_len
    );

    ip_output_route(dst.addr, UDP_PROTOCOL, &packet)
}

pub fn udp_sendto(index: usize, dst: UdpEndpoint, data: &[u8]) -> Result<()> {
    let pcbs = UDP_PCBS.lock();
    if index >= UDP_PCB_SIZE {
        return Err(Error::InvalidPcbIndex);
    }
    let pcb = &pcbs[index];
    if pcb.state != UdpState::Open {
        return Err(Error::InvalidPcbState);
    }

    let src = pcb.local;
    drop(pcbs);

    udp_output(src, dst, data)
}

pub fn udp_recvfrom(index: usize, buf: &mut [u8]) -> Result<(usize, UdpEndpoint)> {
    let mut pcbs = UDP_PCBS.lock();
    if index >= UDP_PCB_SIZE {
        return Err(Error::InvalidPcbIndex);
    }
    let pcb = &mut pcbs[index];
    if pcb.state != UdpState::Open {
        return Err(Error::InvalidPcbState);
    }

    let Some(packet) = pcb.recv_queue.pop_front() else {
        return Err(Error::WouldBlock);
    };

    let len = packet.data.len().min(buf.len());
    buf[..len].copy_from_slice(&packet.data[..len]);
    Ok((len, packet.foreign))
}
```

### 3.4 DNSプロトコル

**ファイル:** `src/kernel/net/dns.rs`

**定数定義:**

```rust
/// DNS question type
const DNS_TYPE_A: u16 = 1; // IPv4 address
const DNS_CLASS_IN: u16 = 1; // Internet class

/// デフォルトのDNSサーバー (Google Public DNS)
const DNS_SERVER: IpAddr = IpAddr(0x0808_0808); // 8.8.8.8
const DNS_PORT: u16 = 53;
```

**DNSヘッダー構造体 (RFC 1035):**

```rust
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct DnsHeader {
    id: u16,      // Transaction ID
    flags: u16,   // Flags
    qdcount: u16, // Question count
    ancount: u16, // Answer count
    nscount: u16, // Authority record count
    arcount: u16, // Additional record count
}

impl DnsHeader {
    fn new_query(id: u16) -> Self {
        Self {
            id: id.to_be(),
            flags: 0x0100u16.to_be(),
            qdcount: 1u16.to_be(),
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }
}
```

**ドメイン名のエンコード:**

```rust
fn encode_domain_name(domain: &str, buf: &mut Vec<u8>) {
    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
}
```

**ドメイン名のデコード (DNS圧縮対応):**

```rust
fn decode_domain_name(
    data: &[u8],
    mut offset: usize,
    _original_data: &[u8],
) -> Result<(String, usize)> {
    let mut name = String::new();
    let mut jumped = false;
    let mut jump_offset = 0;
    let mut iterations = 0;
    const MAX_ITERATIONS: usize = 127;

    loop {
        iterations += 1;
        if iterations > MAX_ITERATIONS {
            return Err(Error::InvalidLength);
        }

        if offset >= data.len() {
            return Err(Error::PacketTooShort);
        }

        let len = data[offset];

        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return Err(Error::PacketTooShort);
            }

            if !jumped {
                jump_offset = offset + 2;
            }

            let pointer = (((len & 0x3F) as usize) << 8) | (data[offset + 1] as usize);
            offset = pointer;
            jumped = true;
            continue;
        }

        offset += 1;

        if len == 0 {
            break;
        }

        if !name.is_empty() {
            name.push('.');
        }

        if offset + len as usize > data.len() {
            return Err(Error::PacketTooShort);
        }

        for i in 0..len as usize {
            name.push(data[offset + i] as char);
        }

        offset += len as usize;
    }

    Ok((name, if jumped { jump_offset } else { offset }))
}
```

**DNSクエリパケットの構築:**

```rust
fn build_dns_query(domain: &str, id: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    let header = DnsHeader::new_query(id);
    let header_bytes = unsafe {
        core::slice::from_raw_parts(
            &header as *const _ as *const u8,
            core::mem::size_of::<DnsHeader>(),
        )
    };
    packet.extend_from_slice(header_bytes);
    encode_domain_name(domain, &mut packet);
    packet.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

    packet
}
```

**DNSレスポンスの解析:**

```rust
fn parse_dns_response(data: &[u8]) -> Result<IpAddr> {
    if data.len() < core::mem::size_of::<DnsHeader>() {
        return Err(Error::PacketTooShort);
    }

    let header = unsafe { &*(data.as_ptr() as *const DnsHeader) };
    let ancount = u16::from_be(header.ancount);

    crate::println!(
        "[dns] Response: id={:04x}, flags={:04x}, questions={}, answers={}",
        u16::from_be(header.id),
        u16::from_be(header.flags),
        u16::from_be(header.qdcount),
        ancount
    );

    if ancount == 0 {
        return Err(Error::NotFound);
    }

    let mut offset = core::mem::size_of::<DnsHeader>();

    let qdcount = u16::from_be(header.qdcount);
    for _ in 0..qdcount {
        loop {
            if offset >= data.len() {
                return Err(Error::PacketTooShort);
            }

            let len = data[offset];

            if len & 0xC0 == 0xC0 {
                offset += 2;
                break;
            }

            offset += 1;

            if len == 0 {
                break;
            }

            offset += len as usize;
        }

        offset += 4;
    }

    for i in 0..ancount {
        if offset >= data.len() {
            return Err(Error::PacketTooShort);
        }

        loop {
            if offset >= data.len() {
                return Err(Error::PacketTooShort);
            }

            let len = data[offset];

            if len & 0xC0 == 0xC0 {
                offset += 2;
                break;
            }

            offset += 1;

            if len == 0 {
                break;
            }

            offset += len as usize;
        }

        if offset + 10 > data.len() {
            return Err(Error::PacketTooShort);
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]);

        offset += 10;

        crate::println!(
            "[dns] Answer {}: type={}, class={}, ttl={}, rdlen={}",
            i + 1,
            rtype,
            rclass,
            ttl,
            rdlength
        );

        if rtype == DNS_TYPE_A && rclass == DNS_CLASS_IN && rdlength == 4 {
            if offset + 4 > data.len() {
                return Err(Error::PacketTooShort);
            }

            let addr = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);

            return Ok(IpAddr(addr));
        }

        offset += rdlength as usize;
    }

    Err(Error::NotFound)
}
```

**DNS解決処理:**

```rust
pub fn dns_resolve(domain: &str) -> Result<IpAddr> {
    crate::println!("[dns] Resolving: {}", domain);
    crate::println!("[dns] Querying upstream DNS server...");
    let sockfd = udp::udp_pcb_alloc()?;
    let local = UdpEndpoint::any(0);
    udp::udp_bind(sockfd, local)?;

    let query_id = 0x1234; // TODO: ランダムIDを使用
    let query = build_dns_query(domain, query_id);

    crate::println!(
        "[dns] Sending query to {}.{}.{}.{}:53 ({} bytes)",
        (DNS_SERVER.0 >> 24) & 0xFF,
        (DNS_SERVER.0 >> 16) & 0xFF,
        (DNS_SERVER.0 >> 8) & 0xFF,
        DNS_SERVER.0 & 0xFF,
        query.len()
    );

    let dns_endpoint = UdpEndpoint::new(DNS_SERVER, DNS_PORT);
    udp::udp_sendto(sockfd, dns_endpoint, &query)?;

    let mut buf = alloc::vec![0u8; 512];
    let max_attempts = 100;
    for attempt in 0..max_attempts {
        crate::net::driver::virtio_net::poll_rx();

        match udp::udp_recvfrom(sockfd, &mut buf) {
            Ok((len, src)) => {
                crate::println!(
                    "[dns] Received {} bytes from {}:{} (attempt {})",
                    len,
                    src.addr.to_bytes()[0],
                    src.port,
                    attempt + 1
                );

                match parse_dns_response(&buf[..len]) {
                    Ok(addr) => {
                        udp::udp_pcb_release(sockfd)?;
                        crate::println!(
                            "[dns] Resolved {} to {}.{}.{}.{}",
                            domain,
                            (addr.0 >> 24) & 0xFF,
                            (addr.0 >> 16) & 0xFF,
                            (addr.0 >> 8) & 0xFF,
                            addr.0 & 0xFF
                        );
                        return Ok(addr);
                    }
                    Err(e) => {
                        crate::println!("[dns] Failed to parse response: {:?}", e);
                    }
                }
            }
            Err(Error::WouldBlock) => {
                yielding();
            }
            Err(e) => {
                udp::udp_pcb_release(sockfd)?;
                return Err(e);
            }
        }
    }

    udp::udp_pcb_release(sockfd)?;
    Err(Error::Timeout)
}
```

### 3.5 システムコール

**ファイル:** `src/kernel/syscall.rs`

**システムコール番号を追加:**

```rust
#[derive(Copy, Clone, Debug)]
#[repr(usize)]
pub enum SysCalls {
    // 既存のシステムコール...
    UdpOpen = 27,
    UdpBind = 28,
    UdpSendto = 29,
    UdpRecvfrom = 30,
    UdpClose = 31,
    DnsResolve = 32,
}
```

**DNS解決システムコール:**

```rust
pub fn dns_resolve() -> Result<usize> {
    unsafe {
        let mut sbinfo: SBInfo = Default::default();
        let sbinfo = SBInfo::from_arg(0, &mut sbinfo)?;
        let addr_ptr: UVAddr = argraw(1).into();

        let mut buf = alloc::vec![0u8; sbinfo.len];
        crate::proc::either_copyin(&mut buf[..], sbinfo.ptr.into())?;
        let domain = core::str::from_utf8(&buf).or(Err(Utf8Error))?;

        let addr = dns::dns_resolve(domain)?;

        crate::proc::either_copyout(addr_ptr.into(), &addr.0.to_ne_bytes())?;

        Ok(0)
    }
}
```

**システムコールテーブルに登録:**

```rust
impl SysCalls {
    pub const TABLE: [(Fn, &'static str); variant_count::<Self>()] = [
        (Fn::I(Self::udp_open), "()"),
        (Fn::I(Self::udp_bind), "(sockfd: usize, addr: u32, port: u16)"),
        (Fn::I(Self::udp_sendto), "(sockfd: usize, dst_addr: u32, dst_port: u16, buf: &[u8])"),
        (Fn::I(Self::udp_recvfrom), "(sockfd: usize, buf: &mut [u8], src_addr: &mut u32, src_port: &mut u16)"),
        (Fn::U(Self::udp_close), "(sockfd: usize)"),
        (Fn::I(Self::dns_resolve), "(domain: &str, addr_out: &mut u32)"),
    ];
}
```

**UDPシステムコール:**

```rust
pub fn udp_open() -> Result<usize> {
    use crate::net::udp;
    udp::udp_pcb_alloc()
}

pub fn udp_bind() -> Result<()> {
    use crate::net::ip::IpAddr;
    use crate::net::udp::{self, UdpEndpoint};
    let sockfd = argraw(0);
    let addr = argraw(1) as u32;
    let port = argraw(2) as u16;
    let endpoint = UdpEndpoint::new(IpAddr(addr), port);
    udp::udp_bind(sockfd, endpoint)
}

pub fn udp_sendto() -> Result<usize> {
    use crate::net::ip::IpAddr;
    use crate::net::udp::{self, UdpEndpoint};
    let sockfd = argraw(0);
    let mut sbinfo: SBInfo = Default::default();
    let sbinfo = SBInfo::from_arg(1, &mut sbinfo)?;
    let dst_addr = argraw(2) as u32;
    let dst_port = argraw(3) as u16;

    let mut buf = alloc::vec![0u8; sbinfo.len];
    crate::proc::either_copyin(&mut buf[..], sbinfo.ptr.into())?;

    let dst = UdpEndpoint::new(IpAddr(dst_addr), dst_port);
    udp::udp_sendto(sockfd, dst, &buf)?;
    Ok(sbinfo.len)
}

pub fn udp_recvfrom() -> Result<usize> {
    use crate::net::udp;
    let sockfd = argraw(0);
    let mut sbinfo: SBInfo = Default::default();
    let sbinfo = SBInfo::from_arg(1, &mut sbinfo)?;
    let src_addr_ptr: UVAddr = argraw(2).into();
    let src_port_ptr: UVAddr = argraw(3).into();

    let mut buf = alloc::vec![0u8; sbinfo.len];
    let (len, src) = udp::udp_recvfrom(sockfd, &mut buf)?;

    crate::proc::either_copyout(sbinfo.ptr.into(), &buf[..len])?;
    crate::proc::either_copyout(src_addr_ptr.into(), &src.addr.0.to_ne_bytes())?;
    crate::proc::either_copyout(src_port_ptr.into(), &src.port.to_ne_bytes())?;

    Ok(len)
}

pub fn udp_close() -> Result<()> {
    use crate::net::udp;
    let sockfd = argraw(0);
    udp::udp_pcb_release(sockfd)
}
```

### 3.6 ユーザーライブラリ

**ファイル:** `src/user/lib/lib.rs`

**DNS解決のラッパー関数:**

```rust
pub fn dns_resolve(domain: &str) -> sys::Result<u32> {
    let mut addr: u32 = 0;
    sys::dnsresolve(domain, &mut addr)?;
    Ok(addr)
}
```

### 3.7 nslookupコマンド

**ファイル:** `src/user/bin/nslookup.rs`

```rust
#![no_std]
extern crate alloc;

use ulib::{dns_resolve, env, print, println};

fn main() {
    let mut args = env::args();
    let _prog = args.next();

    let Some(domain) = args.next() else {
        println!("Usage: nslookup <domain>");
        println!("Examples:");
        println!("  nslookup example.com");
        println!("  nslookup google.com");
        println!("  nslookup github.com");
        return;
    };

    println!("Resolving: {}", domain);

    let addr = match dns_resolve(domain) {
        Ok(a) => a,
        Err(e) => {
            println!("DNS resolution failed: {:?}", e);
            return;
        }
    };

    let a = (addr >> 24) & 0xFF;
    let b = (addr >> 16) & 0xFF;
    let c = (addr >> 8) & 0xFF;
    let d = addr & 0xFF;

    println!("");
    println!("Name:    {}", domain);
    println!("Address: {}.{}.{}.{}", a, b, c, d);
}
```

### 3.8 初期化処理

**ファイル:** `src/kernel/net.rs`

```rust
pub fn init() {
    crate::println!("[kernel] Network stack init");

    ip::ip_init();

    driver::loopback::loopback_init().expect("loopback init failed");
    driver::loopback::loopback_setup().expect("loopback setup failed");

    driver::virtio_net::init().expect("virtio-net init failed");
    driver::virtio_net::setup_iface().expect("virtio-net iface failed");

    crate::println!("[kernel] Network stack initialized");
}
```

**カーネルメインから呼び出し (`src/kernel/main.rs`):**

```rust
pub fn main() {
    crate::net::init();
}
```
