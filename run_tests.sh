#!/usr/bin/env bash
# Formatting, lints and the test suites. Pass --docker to also run the
# end-to-end suites (Keycloak 26.8.0 and headless Chrome via Docker).
set -euo pipefail
cd "$(dirname "$0")"

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test

if [[ "${1:-}" == "--docker" ]]; then
  cargo test --no-fail-fast \
    --test keycloak_2026_e2e_test \
    --test integration_test \
    --test jdoe_login_test \
    --test agent_integration_test \
    --test headless_compliance_test \
    -- --ignored --test-threads=1
fi
