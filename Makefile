.PHONY: build run test

PROJECT_ROOT := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
TEST_RUNNER := $(PROJECT_ROOT)/scripts/test_runner.sh

build:
	cargo build --target riscv64gc-unknown-none-elf

run:
	cargo run --target riscv64gc-unknown-none-elf

test:
	CARGO_TARGET_RISCV64GC_UNKNOWN_NONE_ELF_RUNNER='$(TEST_RUNNER)' \
		cargo test -p libkernel --lib --target riscv64gc-unknown-none-elf
