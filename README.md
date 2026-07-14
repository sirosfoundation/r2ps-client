# r2ps-client

[![CI](https://github.com/sirosfoundation/r2ps-client/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/r2ps-client/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/r2ps-client/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/r2ps-client)
[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](LICENSE)

Rust client library for the R2PS (Remote PAKE-Protected Services) protocol — a
secure remote cryptographic operations mechanism for mobile wallet deployments
with OPAQUE (RFC 9807) authentication and JWS-signed request/response envelopes.

Provides both **WSCD client operations** (remote key generation, ECDSA signing,
ECDH agreement) and **WSCA client operations** (Wallet Key Attestation and
Wallet Instance Attestation requests per ETSI TS 119 476-3 / CS-04).

## Specification

The authoritative R2PS protocol specifications are maintained in the
[go-r2ps-service](https://github.com/sirosfoundation/go-r2ps-service) repository
under [docs/specs/](https://github.com/sirosfoundation/go-r2ps-service/tree/main/docs/specs).

## Features

- **JWS** (ES256) — sign, verify, and peek headers via [josekit](https://crates.io/crates/josekit)
- **JWE** — ECDH-ES/A256GCM (1FA mode) and dir/A256GCM (2FA mode)
- **PAKE** — pluggable OPAQUE client trait for 2FA authentication
- **WSCD service types** — `p256_generate` (1FA), `sign_ecdsa` (2FA), `agree_ecdh` (2FA), `hsm_list_keys` (2FA)
- **WSCA service types** — `eudiw_wka_etsi` (1FA), `eudiw_wia_etsi` (1FA) with typed request/response structs
- **RawSign trait** — abstraction matching FIDO2 rawSign extension, backed by R2PS remote signing
- **1FA/2FA dispatch** — `call_service()` for 2FA types (session required), `call_service_1fa()` for 1FA types
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
// then use R2psClient to register, authenticate, and call services.

// WSCD operations (2FA — session required):
// client.call_service("sign_ecdsa", &data)?;
// client.call_service("agree_ecdh", &data)?;

// WSCD operations (1FA — no session):
// client.call_service_1fa("p256_generate", &data)?;

// WSCA operations (1FA — typed convenience methods):
// client.wka_attest(&["key-0"], "draft-008")?;
// client.wia_attest(&["key-0"], "draft-008")?;
```

### CLI

```bash
cargo install --git https://github.com/sirosfoundation/r2ps-client --features cli

r2ps-cli --help
```

Available commands:

| Command     | Description                                      |
|-------------|--------------------------------------------------|
| `register`  | Register 2FA credentials with the server          |
| `auth`      | Authenticate and establish a 2FA session           |
| `keygen`    | Generate a remote P-256 key pair                   |
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
