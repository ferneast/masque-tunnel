# Stage 1: build. quiche / tokio-quiche compile BoringSSL from source, so a
# C/C++ toolchain and CMake are required. The binary links glibc dynamically.
FROM rust:1-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

# --locked: build exactly the committed Cargo.lock for reproducibility.
RUN cargo build --release --locked && cp target/release/masque-tunnel /masque-tunnel

# Stage 2: minimal glibc runtime. BoringSSL is statically linked into the
# binary, so only glibc + libgcc are needed at runtime — not a static binary,
# so `scratch` no longer works.
FROM debian:bookworm-slim

COPY --from=builder /masque-tunnel /usr/local/bin/masque-tunnel

EXPOSE 443/udp

# CONNECT-IP needs a TUN device: run with
#   --cap-add NET_ADMIN --device /dev/net/tun
ENTRYPOINT ["/usr/local/bin/masque-tunnel"]
