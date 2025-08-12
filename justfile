# Simple tasks (requires `just`)

default:
	@just --list

setup:
	@echo "Run: nix develop"

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets -- -D warnings

build:
	cargo build --release

run:
	cargo run --release
