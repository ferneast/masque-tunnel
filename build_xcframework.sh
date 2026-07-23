#!/bin/sh
# Builds masque.xcframework — the CONNECT-IP client static library + masque_ffi.h
# for iOS / tvOS / macOS (device + simulator slices).
#
# Output: ./masque.xcframework (copy into the consuming app, e.g.
# xlarva/thirdparty/masque.xcframework).
#
# tvOS is a tier-3 Rust target and needs nightly + -Zbuild-std.
set -e

CARGO_CMD=$(which cargo)
RUSTUP_CMD=$(which rustup)
echo "pwd: ${PWD}"

export MACOSX_DEPLOYMENT_TARGET=14.0
export IPHONEOS_DEPLOYMENT_TARGET=17.0
export TVOS_DEPLOYMENT_TARGET=17.0

${RUSTUP_CMD} target add aarch64-apple-ios
${RUSTUP_CMD} target add aarch64-apple-ios-sim
${RUSTUP_CMD} target add x86_64-apple-ios
${RUSTUP_CMD} target add aarch64-apple-darwin
${RUSTUP_CMD} target add x86_64-apple-darwin
${RUSTUP_CMD} component add rust-src --toolchain nightly

${CARGO_CMD} build --target=aarch64-apple-ios --lib -r
${CARGO_CMD} build --target=x86_64-apple-ios --lib -r
${CARGO_CMD} build --target=aarch64-apple-ios-sim --lib -r

${CARGO_CMD} build --target=aarch64-apple-darwin --lib -r
${CARGO_CMD} build --target=x86_64-apple-darwin --lib -r

${CARGO_CMD} +nightly build -Zbuild-std=panic_abort,std --target=aarch64-apple-tvos --lib -r
${CARGO_CMD} +nightly build -Zbuild-std=panic_abort,std --target=aarch64-apple-tvos-sim --lib -r
${CARGO_CMD} +nightly build -Zbuild-std=panic_abort,std --target=x86_64-apple-tvos --lib -r

LIB=libmasque_tunnel.a

rm -rf libmasque_ios_Simulator.a libmasque_Mac.a libmasque_tvos_Simulator.a masque.xcframework

lipo -create "target/aarch64-apple-ios-sim/release/${LIB}" "target/x86_64-apple-ios/release/${LIB}" -o libmasque_ios_Simulator.a
lipo -create "target/aarch64-apple-darwin/release/${LIB}" "target/x86_64-apple-darwin/release/${LIB}" -o libmasque_Mac.a
lipo -create "target/aarch64-apple-tvos-sim/release/${LIB}" "target/x86_64-apple-tvos/release/${LIB}" -o libmasque_tvos_Simulator.a

xcodebuild -create-xcframework \
    -library libmasque_Mac.a -headers include \
    -library libmasque_ios_Simulator.a -headers include \
    -library "target/aarch64-apple-ios/release/${LIB}" -headers include \
    -library "target/aarch64-apple-tvos/release/${LIB}" -headers include \
    -library libmasque_tvos_Simulator.a -headers include \
    -output masque.xcframework

rm -rf libmasque_ios_Simulator.a libmasque_Mac.a libmasque_tvos_Simulator.a

echo "Done: ${PWD}/masque.xcframework"
