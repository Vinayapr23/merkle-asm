.PHONY: cu build test

cu:
	@echo "asm"
	@RUST_LOG=error RUST_TEST_THREADS=1 cargo test -- --nocapture 2>&1 | grep -ioE "(initialize|insert|verify) CU: [0-9]+"

build:
	sbpf build

test:
	cargo test
