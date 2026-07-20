#!/bin/bash
# Build MasqueTunnel.xcframework (device + simulator) from the Rust staticlib,
# for embedding the CONNECT-IP client in an iOS/tvOS NEPacketTunnelProvider.
set -euo pipefail
cd "$(dirname "$0")"

LIB=libmasque_tunnel.a
OUT=MasqueTunnel.xcframework
HEADERS=build/Headers

rm -rf "$OUT" build
mkdir -p "$HEADERS"

# Header: prefer cbindgen (keeps it in sync with src/ffi.rs); otherwise use the
# checked-in copy.
if command -v cbindgen >/dev/null 2>&1; then
  echo "==> cbindgen header"
  cbindgen --config cbindgen.toml --output "$HEADERS/masque_tunnel.h" .
else
  echo "==> cbindgen not found; using include/masque_tunnel.h"
  cp include/masque_tunnel.h "$HEADERS/masque_tunnel.h"
fi

# Module map so Swift can `import MasqueTunnel`.
cat > "$HEADERS/module.modulemap" <<'EOF'
module MasqueTunnel {
    header "masque_tunnel.h"
    export *
}
EOF

echo "==> device (aarch64-apple-ios)"
cargo build --release --lib --target aarch64-apple-ios

echo "==> simulator (aarch64-apple-ios-sim + x86_64-apple-ios)"
cargo build --release --lib --target aarch64-apple-ios-sim
cargo build --release --lib --target x86_64-apple-ios
mkdir -p build/sim
lipo -create \
  "target/aarch64-apple-ios-sim/release/$LIB" \
  "target/x86_64-apple-ios/release/$LIB" \
  -output "build/sim/$LIB"

echo "==> create-xcframework"
xcodebuild -create-xcframework \
  -library "target/aarch64-apple-ios/release/$LIB" -headers "$HEADERS" \
  -library "build/sim/$LIB" -headers "$HEADERS" \
  -output "$OUT"

echo "done: $OUT"
