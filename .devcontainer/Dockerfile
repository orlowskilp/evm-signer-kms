# Version is provided in devcontainer.json
FROM archlinux:latest

# These are meant to be provided in devcontainer.json
ARG USERNAME

# These are the default values for the build arguments. Don't edit
# unless you know what you're doing.
ARG HOME_DIR=/home/${USERNAME}
ARG RUST_INSTALLER=install-rust.sh

# Install dependencies and clean up the cache
RUN pacman -Suy --noconfirm \
    aws-cli \
    pkg-config \
    git \
    gcc \
    musl \
    make \
    jq \
    docker \
    docker-compose \
    sudo && \
    rm /var/cache/pacman/pkg/*

# Create a non-root user set it up and roll over to it
RUN useradd -ms /bin/bash ${USERNAME} && \
    usermod -aG docker ${USERNAME} && \
    echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
USER ${USERNAME}
WORKDIR ${HOME_DIR}

# Install Rust and some useful tools
ENV PATH=$PATH:${HOME_DIR}/.cargo/bin
RUN curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh -s -- -y && \
    cargo install \
        cargo-llvm-cov \
        dprint && \
    rustup component add \
        rust-analysis \
        rust-analyzer
