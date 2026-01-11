# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

octox-net is a Rust-based RISC-V operating system kernel with TCP/IP networking stack, based on [octox](https://github.com/o8vm/octox). It runs on QEMU with virtio-net and virtio-blk devices.

## Build and Run

```bash
# Build the kernel
make build

# Run in QEMU
make run
```

Target: `riscv64gc-unknown-none-elf`

The QEMU runner configuration is in `.cargo/config.toml` and includes:

- 4 CPUs, 524M RAM
- virtio-blk for filesystem (target/fs.img)
- virtio-net with user networking (192.0.2.0/24)

## Architecture

### Workspace Structure

- `src/kernel/` - Kernel library (libkernel) and main binary
  - `net/` - Network stack implementation
  - Core OS modules: proc, vm, fs, syscall, trap, etc.
- `src/user/` - User space programs and libraries
  - `bin/` - User commands (cat, grep, ping, nslookup, etc.)
  - `lib/` - User libraries
- `src/mkfs/` - Filesystem creation tool

### Network Stack (src/kernel/net/)

Layered architecture inspired by smoltcp:

```text
Application (syscalls)
    ↓
Socket layer (future TCP implementation)
    ↓
Protocol layer: UDP, ICMP, DNS
    ↓
IP layer (routing, fragmentation)
    ↓
Link layer: Ethernet, ARP
    ↓
Device layer: NetDevice abstraction
    ↓
Drivers: virtio-net, loopback
```

Key modules:

- `device.rs` - NetDevice abstraction (flags, ops, interfaces)
- `driver/` - loopback and virtio_net drivers
- `ethernet.rs`, `arp.rs` - Link layer
- `ip.rs`, `route.rs` - Network layer
- `icmp.rs`, `udp.rs` - Transport protocols
- `dns.rs` - DNS resolver
- `interface.rs` - Network interface management

Network initialization happens in `net::init()` which sets up loopback and virtio-net devices.

### Reference Implementations

External TCP/IP implementations for reference (not in this repo):

- **smoltcp** (`operating-system/smoltcp`) - Rust TCP/IP stack, primary architectural reference
- **microps** (`operating-system/microps`) - C implementation

See `docs/octox-tcp-implementation-plan.md` for detailed TCP implementation design based on smoltcp patterns.

## Important Details

- **no_std environment**: Kernel uses `#![no_std]` with custom allocator
- **Synchronization**: Uses custom spinlock, sleeplock, semaphore primitives
- **Memory**: Buddy allocator for kernel memory
- **Syscalls**: Defined in `syscall.rs` with network syscalls for ping, nslookup
