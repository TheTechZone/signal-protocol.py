#!/bin/bash
set -ex

RUST_TOOLCHAIN=$(cat /io/rust-toolchain)
# We specify a particular rustup version and a SHA256 hash for
# `rustup-init.sh`, computed ourselves and hardcoded here.
RUSTUP_LATEST_VERSION=1.26.0
OUR_RUSTUP_INIT_SHA="be3535b3033ff5e0ecc4d589a35d3656f681332f860c5fd6684859970165ddcc"

curl --proto '=https' --tlsv1.3 -sSf -O \
  https://raw.githubusercontent.com/rust-lang/rustup/${RUSTUP_LATEST_VERSION}/rustup-init.sh
# Verify checksum of rustup script.
echo "${OUR_RUSTUP_INIT_SHA} rustup-init.sh" | sha256sum --check -
# Run rustup.
sh rustup-init.sh --default-toolchain ${RUST_TOOLCHAIN} -y
export PATH="${HOME}/.cargo/bin:${PATH}"

cd /io

for PYBIN in /opt/python/cp{36,37,38,39}*/bin; do
    rm -f /io/build/lib.*
    "${PYBIN}/pip" install -U setuptools wheel setuptools-rust
    "${PYBIN}/python" setup.py bdist_wheel
done

for whl in dist/*.whl; do
    auditwheel repair "$whl" -w dist/
done
