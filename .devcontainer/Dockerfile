# Version is provided in devcontainer.json
ARG VERSION
FROM archlinux:${VERSION}

# These are meant to be provided in devcontainer.json
ARG USERNAME
ARG ARCH

# These are the default values for the build arguments. Don't edit
# unless you know what you're doing.
ARG CARGO_BIN=/root/.cargo/bin/
ARG HOME_DIR=/home/${USERNAME}
ARG RUST_INSTALLER=install-rust.sh
ARG RUST_TOOLCHAIN=stable-${ARCH}-unknown-linux-gnu
ARG MUSL_TOOLCHAIN=${ARCH}-unknown-linux-musl

# Install dependencies and clean up the cache
RUN pacman -Suy --noconfirm \
    aws-cli \
    git \
    gcc \
    musl \
    make \
    sudo && \
    rm /var/cache/pacman/pkg/*
# Create a non-root user and add it to all the groups necessary
RUN useradd -ms /bin/bash ${USERNAME}
# Install Rust and some useful tools
RUN curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh -s -- -y && \
    ${CARGO_BIN}/rustup target install ${MUSL_TOOLCHAIN} && \
    ${CARGO_BIN}/rustup component add rust-analysis --toolchain ${RUST_TOOLCHAIN} && \
    ${CARGO_BIN}/rustup component add rust-src --toolchain ${RUST_TOOLCHAIN} && \
    ${CARGO_BIN}/rustup component add rust-analyzer --toolchain ${RUST_TOOLCHAIN} && \
    ${CARGO_BIN}/rustup component add llvm-tools-preview --toolchain ${RUST_TOOLCHAIN} && \
    ${CARGO_BIN}/cargo install cargo-llvm-cov
# Move the Rust installation to the non-root user's home directory
# Note to myself: There has to be a better way to do this
RUN mv ~/.cargo /home/${USERNAME} && \
    chown -R ${USERNAME}:${USERNAME} ${HOME_DIR}/.cargo && \
    mv ~/.rustup /home/${USERNAME} && \
    chown -R ${USERNAME}:${USERNAME} ${HOME_DIR}/.rustup && \
    mv ~/.profile /home/${USERNAME} && \
    chown -R ${USERNAME}:${USERNAME} ${HOME_DIR}/.profile && \
    echo "PATH=$PATH:~/.cargo/bin" >> ${HOME_DIR}/.bash_profile && \
    echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER ${USERNAME}
WORKDIR ${HOME_DIR}