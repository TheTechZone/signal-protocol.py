#!/bin/bash
set -ex

RUST_TOOLCHAIN=$(cat /io/rust-toolchain)
# We specify a particular rustup version and a SHA256 hash for
# `rustup-init.sh`, computed ourselves and hardcoded here.
RUSTUP_LATEST_VERSION=1.27.1
OUR_RUSTUP_INIT_SHA="32a680a84cf76014915b3f8aa44e3e40731f3af92cd45eb0fcc6264fd257c428"

curl --proto '=https' --tlsv1.3 -sSf -O \
  https://raw.githubusercontent.com/rust-lang/rustup/${RUSTUP_LATEST_VERSION}/rustup-init.sh
# Verify checksum of rustup script.
echo "${OUR_RUSTUP_INIT_SHA} rustup-init.sh" | sha256sum --check -
# Run rustup.
sh rustup-init.sh --default-toolchain ${RUST_TOOLCHAIN} -y
export PATH="${HOME}/.cargo/bin:${PATH}"

cd /io

for PYBIN in /opt/python/cp{36,37,38,39,310,311,312}*/bin; do
    "${PYBIN}/pip" install -U maturin[patchelf]
    "${PYBIN}/maturin" build --release --strip --interpreter "${PYBIN}/python"
done

# Use the most recent Python version to repair wheels
LATEST_PYBIN=$(ls -d /opt/python/cp3* | sort -V | tail -n1)/bin
for whl in target/wheels/*.whl; do
    "${LATEST_PYBIN}/python" -m auditwheel repair "$whl" -w dist/
done
