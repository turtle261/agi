# Competitive Message Routing (CMR)
[![Rust CI](https://github.com/turtle261/agi/actions/workflows/rust.yml/badge.svg)](https://github.com/turtle261/agi/actions/workflows/rust.yml)
[![Security](https://github.com/turtle261/agi/actions/workflows/security.yml/badge.svg)](https://github.com/turtle261/agi/actions/workflows/security.yml)
[![CodeQL](https://github.com/turtle261/agi/actions/workflows/codeql.yml/badge.svg)](https://github.com/turtle261/agi/actions/workflows/codeql.yml)

This project implements the CMR protocol defined in `agi2.html` (Appendix A) as a Rust workspace:

- `crates/cmr-core`: strict protocol parser/encoder, router logic, policy, key exchange.
- `crates/cmr-peer`: network peer daemon (HTTP, HTTPS, UDP listeners; HTTP/HTTPS/SMTP/UDP/SSH outbound).
- `crates/cmr-compressor`: isolated compressor worker that uses `infotheory` from GitHub (`github` branch), with `backend-rosa` + `backend-zpaq` enabled and `backend-rwkv` disabled by default.

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
  - strict callback validation for HTTP-handshake reply fetches (literal IP host must match remote peer IP).
  - SSH destination path is command-sanitized (single safe token only) to prevent command injection.

## Implemented CMR Pieces

- Message format (signature/header/body) and strict validation.
- Router behavior: accept/reject, cache, matching, forwarding, per-hop re-signing.
- Transports:
  - Server: HTTP, HTTPS, UDP.
  - Client: HTTP, HTTPS, SMTP, UDP, SSH.
  - HTTP handshake (`request`/`reply`) including one-time payload store.
  - UDP service-tag framing (`udp://host:port/service`) enforced on send/receive.
  - SMTP payloads are sent as `application/octet-stream` with base64 transfer encoding.
- Key exchange control messages:
  - RSA request/reply.
  - Diffie-Hellman request/reply.
  - Clear key exchange (only accepted over secure transport).
  - RSA/DH shared secrets are normalized with HKDF-SHA256 before use as pairwise keys.

## Build

```bash
cargo build --workspace --release
```

## Test

```bash
cargo test --workspace
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

## Run Peer

Single entrypoint:

```bash
cargo run -p cmr-peer -- init-config --config cmr-peer.toml
cargo run -p cmr-peer -- run --config cmr-peer.toml
```

Optional: local end-to-end smoke test (starts runtime, probes ingest path, exits):

```bash
cargo run -p cmr-peer -- self-test --config cmr-peer.toml --spawn-runtime true
```

Optional SSH forced-command mode (ingest one message from stdin):

```bash
cargo run -p cmr-peer -- receive-stdin --config cmr-peer.toml --transport ssh
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
- We use HKDF-SHA256. Mahoneys V2.2 Paper seemingly includes an error, suggesting an insecure raw SHA256 usage. We do not implmement that error.
