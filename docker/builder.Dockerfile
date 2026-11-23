FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

# bookworm keeps the glibc floor at 2.36. The posix variant of mingw is the one Rust's windows-gnu
# target needs; the default win32 variant lacks the threading primitives std uses.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl build-essential pkg-config zip dpkg-dev \
        libxkbcommon-dev libwayland-dev libx11-dev libxcursor-dev libxrandr-dev libxi-dev libgl1-mesa-dev \
        gcc-mingw-w64-x86-64-posix binutils-mingw-w64-x86-64 \
    && update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix \
    && rm -rf /var/lib/apt/lists/*

# The release toolchain is pinned here; RUSTUP_TOOLCHAIN overrides the repository's rust-toolchain.toml.
ARG RUST_VERSION=1.99.1
ENV RUSTUP_HOME=/usr/local/rustup PATH=/usr/local/cargo/bin:$PATH RUSTUP_TOOLCHAIN=$RUST_VERSION
RUN curl -fsSL https://sh.rustup.rs | CARGO_HOME=/usr/local/cargo sh -s -- -y --profile minimal --default-toolchain "$RUST_VERSION" \
    && rustup target add x86_64-pc-windows-gnu \
    && CARGO_HOME=/tmp/cargo cargo install cargo-deb --version 3.8.0 --locked --root /usr/local \
    && rm -rf /tmp/cargo && chmod -R a+rX /usr/local/rustup

# A named volume mounted here starts world-writable, so the container can run as any host user.
RUN mkdir -m 1777 /cache
ENV CARGO_HOME=/cache/cargo CARGO_TARGET_DIR=/cache/target HOME=/cache
WORKDIR /src
