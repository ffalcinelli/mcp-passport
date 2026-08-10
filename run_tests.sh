#!/bin/bash
cargo test --lib
cargo test --test jdoe_login_test
cargo test --test headless_compliance_test
