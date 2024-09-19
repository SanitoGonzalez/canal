FROM ubuntu:24.04 AS base

RUN apt update && \
    apt install -y \
    gcc-multilib \
    linux-headers-$(uname -r) \
    pkg-config \
    libelf-dev \
    libxdp-dev \
    libcap-dev \
    xdp-tools \
    cmake \
    llvm \
    clang

WORKDIR /app
COPY . .

CMD ["sleep", "infinity"]