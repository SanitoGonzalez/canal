FROM rust:1.82-bookworm AS base

RUN apt-get update && \
    apt-get install -y \
    linux-headers-generic

# Aya setup
RUN rustup toolchain install nightly --component rust-src
RUN cargo install bpf-linker

WORKDIR /app
COPY . .