#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Linux host networking keeps authenticated plaintext confined to loopback.
export PREFIXD_RUSTBGPD_TEST_TOKEN="${PREFIXD_RUSTBGPD_TEST_TOKEN:-$(python3 -c 'import secrets; print(secrets.token_hex(32))')}"
cargo test --locked --features bgp-rustbgpd,test-utils --test integration_rustbgpd -- --ignored --test-threads=1 --nocapture
