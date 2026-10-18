#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Owned fixtures use Linux loopback and immutable GoBGP 4.10.0; no lab endpoints.
# PREFIXD_TEST_CPUSET optionally restricts containers on shared hosts.
mkdir -p target/qualification
cargo test --locked --features test-utils --test integration_gobgp --test integration_e2e -- --ignored --test-threads=1 --nocapture 2>&1 | tee target/qualification/gobgp.log
