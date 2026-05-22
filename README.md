# r2ps-client

[![CI](https://github.com/sirosfoundation/r2ps-client/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/r2ps-client/actions/workflows/ci.yml)
[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](LICENSE)

Rust client library for the R2PS (Remote PAKE-Protected Signing) protocol — a
fallback signing mechanism for mobile wallet deployments where FIDO2 rawSign is
unavailable.

## Features

- **JWS** (ES256) — sign, verify, and peek headers via [josekit](https://crates.io/crates/josekit)
- **JWE** — ECDH-ES+A256KW (device mode) and dir+A256GCM (user/session mode)
- **PAKE** — pluggable OPAQUE client trait for PIN-based authentication
- **HSM service types** — `hsm_ec_keygen`, `hsm_list_keys`, `hsm_ecdsa`, `hsm_ecdh`
- **CLI** — optional `r2ps-cli` binary for basic operations against an R2PS endpoint

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
r2ps-client = { git = "https://github.com/sirosfoundation/r2ps-client" }
```

### Library

```rust
use r2ps_client::{R2psClient, Transport, PakeClient};

// Implement Transport and PakeClient for your environment,
// then use R2psClient to register, authenticate, and call HSM services.
```

### CLI

```bash
cargo install --git https://github.com/sirosfoundation/r2ps-client --features cli

r2ps-cli --help
```

Available commands:

| Command     | Description                                      |
|-------------|--------------------------------------------------|
| `register`  | Register a new PIN with the server               |
| `auth`      | Authenticate and establish a PAKE session         |
| `keygen`    | Generate a remote EC key pair                     |
| `list-keys` | List remote HSM keys                              |
| `sign`      | Sign a hash using a remote key                    |
| `ecdh`      | Perform ECDH key agreement using a remote key     |
| `health`    | Probe server health                               |

## Development

```bash
# Run tests
cargo test

# Build CLI
cargo build --features cli

# Check formatting & lints
cargo fmt --all -- --check
cargo clippy --all-features -- -D warnings
```

## License

BSD-2-Clause — see [LICENSE](LICENSE) for details.

Copyright © 2026 SIROS Foundation.
