.PHONY: build run

build: 
	cargo build --target riscv64gc-unknown-none-elf

run:
	cargo run --target riscv64gc-unknown-none-elf
