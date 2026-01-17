#!/bin/bash -e

KERNEL_ELF="$1"

qemu-system-riscv64 \
    -machine virt \
    -bios none \
    -m 524M \
    -smp 4 \
    -nographic \
    -serial mon:stdio \
    -kernel "${KERNEL_ELF}"
