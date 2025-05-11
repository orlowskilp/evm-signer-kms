#!/bin/bash

# Easy way to ensure devcontainer can talk to Docker daemon on the host after binding
DOCKER_SOCK=/var/run/docker.sock
sudo chmod 777 ${DOCKER_SOCK}

# Install Rust toolchains from `rust-toolchain.toml` file
rustup toolchain install