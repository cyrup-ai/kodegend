# Multi-stage Dockerfile for incremental testing
# Test stages independently to catch failures early:
#   docker build --target=base-packages     (30 seconds)
#   docker build --target=rust-toolchain    (5 minutes)
#   docker build --target=bundler-builder   (10 minutes - includes bundler build)
#   docker build .                          (full build)

# ============================================================================
# Stage 1: base-packages
# Quick test: package installation
# Test with: docker build --target=base-packages -t kodegen-test-base .
# ============================================================================
FROM rust AS base-packages

# Cache-busting argument - change this when updating system dependencies
# Format: YYYY-MM-DD to track when dependencies were last updated
ARG DEPS_VERSION=2025-12-08
RUN echo "Building with dependencies version: ${DEPS_VERSION}"

# Install system dependencies for building all platforms
RUN apt-get update && apt-get install -y \
    # Build essentials
    build-essential \
    pkg-config \
    libssl-dev \
    git \
    curl \
    wget \
    unzip \
    # Cross-platform build tools (required for aws-lc-sys Windows builds)
    cmake \
    nasm \
    # NSIS native Linux compiler for Windows installers
    nsis \
    # Windows cross-compilation toolchain (for building Windows binaries on Linux)
    gcc-mingw-w64-x86-64 \
    g++-mingw-w64-x86-64 \
    # Linux package tools
    rpm \
    fakeroot \
    dpkg-dev \
    # AppImage dependencies
    file \
    desktop-file-utils \
    fuse \
    libfuse2 \
    squashfs-tools \
    # D-Bus development libraries (required by kodegen_native_notify via zbus)
    libdbus-1-dev \
    # General utilities
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Verify base packages installed correctly
RUN makensis -VERSION && cmake --version && nasm --version

# ============================================================================
# Stage 2: user-setup
# Create build user with proper permissions
# ============================================================================
FROM base-packages AS user-setup

# Create build user matching typical host UID/GID
ARG USER_UID=1000
ARG USER_GID=1000

RUN groupadd --gid $USER_GID builder \
    && useradd --uid $USER_UID --gid $USER_GID -m builder \
    && apt-get update \
    && apt-get install -y sudo \
    && echo builder ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/builder \
    && chmod 0440 /etc/sudoers.d/builder \
    && rm -rf /var/lib/apt/lists/*

# Switch to build user
USER builder
ENV HOME=/home/builder
ENV CARGO_HOME=$HOME/.cargo
ENV PATH=$HOME/.cargo/bin:$PATH

# ============================================================================
# Stage 3: rust-toolchain
# Install Rust toolchain and components as builder user
# Test with: docker build --target=rust-toolchain -t kodegen-test-rust .
# ============================================================================
FROM user-setup AS rust-toolchain

# Install Rust as builder user (no root needed)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly \
    && . $HOME/.cargo/env \
    && rustup component add rustfmt clippy \
    && rustup target add \
        x86_64-apple-darwin \
        wasm32-unknown-unknown \
        x86_64-unknown-linux-gnu \
        aarch64-unknown-linux-gnu \
        x86_64-pc-windows-msvc \
        x86_64-pc-windows-gnu \
        aarch64-pc-windows-msvc

# Verify Rust installation
RUN rustc --version && cargo --version

# ============================================================================
# Stage 4: bundler-builder
# Build and install bundler binary as builder user
# ============================================================================
FROM rust-toolchain AS bundler-builder

# Configure git for cargo install
RUN git config --global user.email "builder@kodegen.ai" \
    && git config --global user.name "Kodegen Builder"

# Install bundler from GitHub main branch (always latest)
# Cache bust 2025-01-07: Removed --version CLI parameter
RUN cargo install \
    --git https://github.com/cyrup-ai/kodegen-bundler-bundle \
    --branch main \
    --bin kodegen_bundler_bundle \
    kodegen_bundler_bundle

# Create shared cargo home in /tmp with sticky bit for multi-user access
# Container runs with --user ${host_uid}:${host_gid}, we need a truly shared cache
RUN mkdir -p /tmp/cargo && chmod 1777 /tmp/cargo

# Verify bundler installation
RUN kodegen_bundler_bundle --version || kodegen_bundler_bundle --help

# ============================================================================
# Stage 5: full-builder (default)
# Complete build environment ready for compilation with pre-built bundler
# ============================================================================
FROM bundler-builder AS full-builder

ENV CARGO_HOME=$HOME/.cargo
ENV PATH=$HOME/.cargo/bin:$PATH

# Create cache directory for NSIS downloads
RUN mkdir -p $HOME/.cache/cyrup

# Create cache directory for cargo target with builder ownership
USER root
RUN mkdir -p /cache/target && chown -R builder:builder /cache
USER builder

# Set working directory for runtime
WORKDIR /workspace

# Final verification of all tools including pre-built bundler
RUN rustc --version && \
    cargo --version && \
    makensis -VERSION && \
    kodegen_bundler_bundle --help

# Build instructions:
# - Stage testing: docker build --target=<stage> -t kodegen-test-<stage> .
# - Full image: docker build -t kodegen-release-builder .
# - With cache: docker build --pull -t kodegen-release-builder .
