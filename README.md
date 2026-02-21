# Competitive Message Routing (CMR)
[![Rust CI](https://github.com/turtle261/competitive-message-router/actions/workflows/rust.yml/badge.svg)](https://github.com/turtle261/competitive-message-router/actions/workflows/rust.yml)
[![Security](https://github.com/turtle261/competitive-message-router/actions/workflows/security.yml/badge.svg)](https://github.com/turtle261/competitive-message-router/actions/workflows/security.yml)
[![CodeQL](https://github.com/turtle261/competitive-message-router/actions/workflows/codeql.yml/badge.svg)](https://github.com/turtle261/competitive-message-router/actions/workflows/codeql.yml)

This project implements the CMR protocol defined in `agi2.html` as a Rust workspace, including the Appendix A wire format and the Section 3.2 routing strategy.

- `crates/cmr-core`: strict protocol parser/encoder, router logic, policy, key exchange.
- `crates/cmr-peer`: network peer daemon (HTTP, HTTPS, UDP listeners; HTTP/HTTPS/SMTP/UDP/SSH outbound).
- `crates/cmr-compressor`: isolated compressor worker that uses [infotheory](https://github.com/turtle261/infotheory) for CMR compression-distance metrics and intrinsic-dependence spam mitigations.

## Security-Critical Design

- Compressors are separated into a dedicated worker process (`cmr-compressor`).
- Router process only holds protocol/network logic and talks to worker over bounded IPC.
- Default policy is strict (`SecurityLevel::Strict`) with:
  - CRLF-strict parsing and timestamp ordering checks.
  - pairwise signature verification (`HMAC-SHA256(header+body, key)`) with constant-time digest compare.
  - sliding-window flood/rate controls (peer and global windows).
  - intrinsic-dependence spam filtering (via `infotheory`).
  - executable payload blocking and reputation-based admission.
  - bounded HTTP-handshake payload storage (entry/size caps + TTL).
  - strict callback validation for HTTP-handshake reply fetches (requester host/IP must resolve to and match remote peer IP).
  - SSH destination path is command-sanitized (single safe token only) to prevent command injection.

## Implemented CMR Pieces

- Message format (signature/header/body) and strict validation.
- Router behavior: accept/reject, cache, exact Section 3.2 compression-difference routing (`D(X, Y) = C(XY)-C(X)+C(YX)-C(Y)`), threshold-based multi-match forwarding across matched headers (A3/3.3), compensatory `Z_j` replies, and per-hop re-signing.
- Transports:
  - Server: HTTP, HTTPS, UDP.
  - Client: HTTP, HTTPS, SMTP, UDP, SSH.
  - HTTP handshake (`request`/`reply`) including one-time payload store.
  - UDP service-tag framing (`udp://host:port/service`) enforced on send/receive.
  - SMTP payloads are sent as `application/octet-stream` with base64 transfer encoding.
- Key exchange control messages:
  - Automatic first-contact key-exchange initiation for unknown peers (RSA or DH, policy-selectable).
  - RSA request/reply.
  - Diffie-Hellman request/reply.
  - Clear key exchange (only accepted over secure transport).
  - RSA/DH shared secrets are normalized with HKDF-SHA256 before use as pairwise keys.

## Install (crates.io)

Install the peer daemon and compressor worker:

```bash
cargo install cmr-peer cmr-compressor
```

If `cmr-peer` is not found after install, add Cargo's bin directory to `PATH`:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

## Quick Start

1. Generate a config template:

```bash
cmr-peer init-config --config cmr-peer.toml
```

2. Edit `cmr-peer.toml`:
- set `local_address` to this peer's externally reachable address.
- set listener bind/path values in `[listen.http]`/`[listen.https]`/`[listen.udp]`.
- keep `[compressor].command = "cmr-compressor"` unless you need a custom path.

3. Run the peer:

```bash
cmr-peer run --config cmr-peer.toml
```

4. Optional local smoke test:

```bash
cmr-peer self-test --config cmr-peer.toml --spawn-runtime true
```

5. Optional SSH forced-command mode (ingest one message from stdin):

```bash
cmr-peer receive-stdin --config cmr-peer.toml --transport ssh
```

## Build From Source

```bash
cargo build --workspace --release
```

## Test

```bash
cargo test --workspace --locked
```

Test coverage now includes:

- `crates/cmr-core/tests/core_tests.rs`:
  - protocol parsing/validation edge cases,
  - signature modes and verification,
  - key-exchange parsing and control flows,
  - router security policy decisions (spam, flood, reputation/signature gates),
  - forwarding behavior and re-signing guarantees.
- `crates/cmr-compressor/tests/worker_ipc.rs`:
  - compressor worker process IPC end-to-end and metric responses.
- `crates/cmr-peer/tests/config_transport.rs`:
  - config parsing,
  - multipart/plain payload extraction,
  - handshake store semantics,
  - UDP transport send/receive,
  - HTTP forwarding end-to-end (router -> transport -> HTTP receiver).
- `crates/cmr-peer/tests/docker_smtp.rs`:
  - dockerized MailHog integration to verify SMTP preserves arbitrary binary payload bytes.

## Dependency and Advisory Hygiene

Commands used to keep dependency graph and security state clean:

```bash
cargo update --verbose
~/.cargo/bin/cargo +nightly udeps --all-targets --all-features
~/.cargo/bin/cargo +nightly miri test -p cmr-core --lib
cargo audit
cargo deny check advisories bans licenses sources --config deny.toml
```

CI runs a full platform matrix (Linux GNU + musl, macOS, Windows, FreeBSD/OpenBSD/NetBSD on x86_64 + ARM64), with workspace tests on each target, plus dedicated Linux Docker SMTP integration, nightly `udeps`, nightly `miri`, security audit/deny, and CodeQL.

## Run From Source

```bash
cargo run -p cmr-peer -- init-config --config cmr-peer.toml
cargo run -p cmr-peer -- run --config cmr-peer.toml
cargo run -p cmr-peer -- self-test --config cmr-peer.toml --spawn-runtime true
```

### Optional TUI

Build with the `tui` feature and launch with no subcommand:

```bash
cargo run -p cmr-peer --features tui
```

The terminal dashboard provides high-level controls:

- start/stop runtime
- create/reload config template
- execute local HTTP self-test
- live event log

## Notes

- SMTP inbound is typically handled by your MTA and piped to `receive-stdin`.
- For HTTPS listener, provide PEM cert/key paths in config.
- Use pairwise unique shared keys per peer.
- Mahoney's V2.2 paper seemingly includes an error suggesting insecure raw SHA256 usage. We do not implement that error. We use `HMAC-SHA256` for message authentication (not raw `SHA256(key || message)`), and `HKDF-SHA256` to derive keys from RSA/DH shared secrets.
