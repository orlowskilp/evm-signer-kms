ARG BUILD_TARGET=x86_64-unknown-linux-gnu
ARG BUILD_DIR=/tmp/build

# Build stage executed in Arch Linux.
# Note that Arch Linux officially only supports x86_64.
ARG BUILD_PLATFORM=linux/amd64
FROM --platform=${BUILD_PLATFORM} archlinux:latest AS builder

# Reimport the build arguments.
ARG BUILD_TARGET
ARG BUILD_DIR

# Install dependencies and clean up the cache.
RUN pacman -Suy --noconfirm \
    make \
    gcc \
    aarch64-linux-gnu-gcc \
    musl \
    musl-aarch64
# Install rust with the specified toolchain and target.
ENV CARGO_BUILD_TARGET=${BUILD_TARGET}
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --target ${CARGO_BUILD_TARGET} --profile minimal

# Set up the environment with all the supported targets
ENV PATH=$PATH:/root/.cargo/bin \
    CC_X86_64_UNKNOWN_LINUX_GNU=gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=gcc \
    CC_X86_64_UNKNOWN_LINUX_MUSL=musl-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=gcc \
    CC_AARCH64_UNKNOWN_LINUX_gnu=aarch64-linux-gnu-gcc \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_AARCH64_UNKNOWN_LINUX_MUSL=aarch64-linux-musl-gcc \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc

WORKDIR ${BUILD_DIR}
COPY . .

RUN make build
# You will want to add another stage which copies the binary to a smaller image like Alpine or Debian slim.
