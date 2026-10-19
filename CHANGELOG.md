# Changelog

All notable changes to the `proto` repository will be recorded here.

## Unreleased

- Reject repeated password, public-key, certificate, keyboard-interactive, and none-probe calls
  after full authentication with the typed local `AlreadyAuthenticated` error. A bounded real
  SSH regression verifies all five calls and continued channel use on the same connection.
- Expanded the disposable OpenSSH check to cover raw Ed25519, P-256, RSA-SHA2-256/512 keys and
  all four user-certificate variants, with wrong-password, unauthorized-key, wrong-principal,
  local CA-pin, and server-untrusted CA failures. The shared example bounds SSH steps and
  requires exact output and a successful exit status. CI runs the expanded fixture alongside
  existing SFTP and route checks; the wider interoperability matrix remains incomplete.
- Preserved multi-factor authentication continuation with method-neutral rejection errors,
  partial-success state, and the engine-recognized remaining methods in peer order. Channel and
  remote-forwarding operations now reject locally before full authentication. Fixed RSA SHA-2
  certificate request aliases while binding the exact certificate and selected hash. Real SSH
  tests cover same-connection OTP/password continuation, wrong factors, premature operations,
  both RSA hashes, and hash/certificate substitution rejection. Adding `remaining_methods` to
  `ClientError::AuthenticationRejected` is a pre-Stable source API change.
- Updated russh to 0.64.1 in both dependency graphs, adopting enforced incoming/idle rekey,
  corrected RSA-SHA2 certificate probes, and the upstream agent constraint-allocation fix.
  Rust 1.99.0 is now pinned and the minimum supported version. The bounded native Pageant
  transport patch remains required. Added independent per-Host incoming payload thresholds,
  removed the superseded idle timer and handle lock, and retained real-session coverage of
  counter resets, idle exchanges, delayed authentication, exact channel data, and teardown.
  Connection drop also closes the transport when channel handles survive; explicit disconnect
  retains graceful shutdown with a bounded fallback for blocked output.
- Made `ClientConfig::with_inactivity_timeout` return a typed result and reject zero or
  unrepresentable enabled durations, preventing an engine deadline-reset panic. Rekey durations
  must also fit a deadline. Public real-SSH tests cover activity resets and silent-peer expiry.
- Fixed intermittent Windows strict-KEX fixture teardown failures. A relay `ConnectionAborted`
  is expected only after the injected packet was delivered and the client's strict rejection or
  non-strict control success was confirmed; other relay failures retain stage diagnostics.
- Made `ClientConfig::with_keepalive` return a typed result and reject enabled zero intervals,
  non-expiring missed-reply counts, and unrepresentable deadlines before the engine can spin,
  grow its probe queue indefinitely, or panic. Probes remain disabled by default. Real SSH relay
  tests cover responsive peers, silent-peer expiry, explicit disablement, and per-Host isolation.
- Unified the control-plane and shared Rust problem-details types, requiring the same eight
  validated error fields in JSON, CBOR, OpenAPI, and TypeScript. Unknown response fields and valid
  future error codes remain accepted. The OpenAPI generator now emits the TypeScript problem
  declaration and checks generated output drift in CI.
- Added a strict-KEX interoperability harness to the disposable OpenSSH algorithm check. It
  verifies a pinned-key authenticated command, rejection of injected `SSH_MSG_IGNORE` before and
  after the server's first KEXINIT, and acceptance by a non-strict in-process control. The relay
  checks the exact KEX algorithm name-list and bounds both directions and disconnects; the wider
  interoperability matrix remains open.
- Updated rustls to 0.23.46 in the SSH crate and both Cargo lockfiles, addressing
  RUSTSEC-2026-0346 through RUSTSEC-2026-0349 without suppressing the advisory checks.
- Normalize expired SOCKS5 and HTTP CONNECT handshake socket deadlines to `TimedOut` on Unix,
  where blocking socket timeouts surface as `WouldBlock`; direct public transport tests cover both
  proxy protocols and the concrete SSH route retains its typed timeout error.
- Added `AsyncGatewayTransport` and `ClientConnection::connect_via_gateway_stream` to write and
  flush the bounded K-6 client hello over an already negotiated async TLS/ALPN stream before SSH
  starts. TLS/ALPN setup and live edge interoperability remain caller-owned and unverified.
- Aligned the standalone fuzz workspace with the local MSRV-compatible Pageant patch so all five
  nightly fuzz targets resolve the same agent adapter and build on Windows as well as Linux CI.
- Added concrete `russh` integration for server-opened `auth-agent@openssh.com` channels. The
  `ForwardedChannelKind::Agent` wrapper and `ForwardedChannel::serve_agent` reassemble fragmented
  channel data, apply the fail-closed per-signature forwarding policy, and return bounded agent
  responses. An in-process russh round trip covers the lifecycle; external OpenSSH/Pageant
  interoperability and broader channel scheduling remain unverified.
- Added `GatewayTransport`, which validates and writes exactly one bounded K-6 client-hello frame
  over an established byte transport before exposing it to the SSH engine. Partial writes, invalid
  hello values, zero-length writes, and transport delegation are covered; TLS/ALPN negotiation and
  live gateway interoperability remain outside this adapter.
- Added the bounded K-4 shared-vault epoch-retirement response codec with deterministic CBOR,
  a published vector, and zero-epoch failure coverage; the authenticated route and retirement
  storage remain owned by `server`.
- Added the native Windows legacy Pageant `WM_COPYDATA` agent channel. It derives the documented
  current-thread mapping name, raises the mapping limit to 262,144 bytes, validates response
  lengths before reading, and exposes `connect_native_pageant_agent` while preserving the
  transport-neutral agent API.
- Added concrete session-channel environment and signal requests with bounded UTF-8 validation,
  RFC 4254 signal mapping, and an in-process `russh` server round-trip test.
- Registered K-4 `sync.quota_exceeded` and `sync.rate_limited` problem codes with deterministic
  CBOR vectors for cardinality and per-device write-rate failures (D-64).
- Added bounded K-4 shared-vault member-addition request and response codecs with exact epoch-wrap
  coverage, strict UUIDv7/order/count/body validation, deterministic vectors, and failure-path
  tests.
- Added bounded K-4 shared-vault epoch-publication request and response codecs with sorted
  per-member opaque wraps, strict UUIDv7 and size validation, deterministic vectors, and
  malformed, duplicate, ordering, and body-limit failure paths.
- Added the bounded K-4 shared-vault key-retrieval response codec for ascending epoch wraps,
  deterministic vectors, additive response extensions, and malformed, ordering, count, and body
  limit failure paths. The authenticated route and durable lookup remain owned by `server`.
- Added the K-4 shared-vault creation request and response codecs with bounded opaque key wraps,
  strict UUIDv7 and initial-state validation, published deterministic vectors, and failure-path
  coverage. The authenticated storage and HTTP route remain owned by `server`.
- Added reproducible Prost-generated Rust bindings and a published `FileDescriptorSet` for the
  internal gateway and host-agent protobuf contracts, plus deterministic TypeScript message,
  enum, oneof, and service metadata bindings at `@scoplen/api/proto`; drift checks and generated
  message and descriptor validation cover both languages. Runtime mTLS gRPC services remain open.
- Added the bounded K-6 gateway client-hello codec: a four-byte big-endian length followed by a
  deterministic CBOR map containing compact-JWS `ticket` and `dpop_proof` values. The codec rejects
  malformed or non-canonical maps, unknown fields, invalid JWS shapes, truncation, trailing bytes,
  and oversized unauthenticated frames, with published known-answer vectors.
- Added the authored OpenAPI 3.1 control-plane contract for every resource family in K-5,
  generated Rust envelopes and bounds-checked query types, and the `@scoplen/api` TypeScript
  package surface. The document includes DPoP authentication, ETags, idempotency, pagination,
  RFC 9457 errors, binary KRL and recording responses, and WebSocket session monitoring.
- Added the canonical K-5 Cedar entity/action schema and built-in Owner, Administrator, Security
  auditor, Approver, and Member policy source, with contract marker coverage in `scoplen-api`.
- Added the K-6 internal protobuf source contracts for `spl.gateway.v1.Control` and
  `spl.agent.v1.Agent`, including bounded registration, heartbeat, streamed policy/KRL/membership,
  session, audit, enrollment, host-certificate, principal, and sshd-configuration messages.
- Added the Rust workspace baseline and shared known-answer vector loader (roadmap S1).
- Added the deterministic K-1 object model: strict CBOR, UUIDv7/HLC clocks, typed envelopes,
  tombstones, limits, merge algebra, and orphan detection (roadmap S2).
- Completed the Phase 1 schema-version gate, boundary coverage for model limits, and executable
  CBOR and merge known-answer vectors (roadmap S2).
- Added the S3 primitive boundary: redacted zeroizing secrets, system randomness,
  XChaCha20-Poly1305, HKDF-SHA-256, and the specified Argon2id derivation.
- Added P-256 and Ed25519 signing wrappers and HPKE base-mode wrapping for device and account
  recipients, with malformed-input and authentication failure tests.
- Published executable K-2 known-answer vectors for primitives, signatures, HPKE opening, key
  wrapping, signed certificates and envelopes, recovery, Shamir, escrow, and safety numbers.
- Added K-7 client algorithm preferences with explicit per-Host legacy selection and host
  certificate preference, role-specific transport offers, deterministic algorithm negotiation, and
  a strict-KEX state machine with KEXINIT-first admission, KEX-family checks, sequence bounds, and
  NEWKEYS sequence resets.
- Added the engine-independent K-7 publickey boundary for Ed25519 and P-256 signers, RFC 4252
  session-bound probes and signed requests, bounded OpenSSH user and host certificate validation,
  and host-key trust callbacks. The concrete SSH transport, remaining authentication methods,
  channels, SFTP, and interoperability work remain open.
- Added the engine-independent K-7 FIDO2 security-key boundary with resident-key discovery,
  `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com` public-key and signature
  codecs, RFC 4252 session binding, application scoping, authenticator flags and counters, and
  malformed-input and requirement failure tests.
- Integrated the bounded SOCKS5 and HTTP CONNECT transports with the concrete async SSH client,
  including real in-process SSH round trips and typed proxy rejection, authentication-downgrade,
  and timeout failure paths.
- Added the bounded K-7 SSH agent request-identities and sign request/response codecs, a
  transport-neutral agent client, and server dispatch with opaque failure mapping and loopback
  and malformed-frame tests. Platform channels, forwarding, and the remaining agent protocol
  operations remain open.
- Added the bounded blocking agent stream channel with fragmented-read handling and platform
  constructors for Unix-domain sockets and Windows named pipes, including pre-write request
  validation and oversized-response tests. Pageant compatibility and forwarding remain open.
- Added a bounded Pageant named-pipe agent adapter on Windows, reusing the standard agent framing
  and covering fragmented responses, malformed frames, and oversized responses.
- Added the bounded legacy Pageant `WM_COPYDATA` discovery adapter with the documented
  `PageantRequest%08x` mapping name, strict ASCII/NUL descriptor checks, bounded mapping framing,
  and injectable platform backend tests. Native Win32 window and mapping calls remain owned by
  the consumer platform layer; the safe protocol crate does not claim that runtime integration.
- Added bounded agent management requests for removing all identities and locking or unlocking
  an agent, with opaque failure mapping and passphrase limits.
- Added bounded smart-card provider load and removal requests with PIN redaction, flag preservation,
  opaque failure mapping, and client/server store hooks.
- Added bounded `SSH_AGENTC_EXTENSION` requests with opaque success and extension-failure responses,
  client and server hooks, and malformed, oversize, and debug-redaction coverage.
- Added bounded RFC 4254 channel-open, channel-data, lifecycle, session-request, agent-forwarding,
  direct/forwarded TCP and streamlocal, and global forwarding codecs with strict field limits and
  malformed-input tests.
- Added bounded blocking agent-server serving that validates fragmented request frames, dispatches
  multiple requests until clean peer close, and refuses oversized input before allocation.
- Added exact-key remove-identity requests with bounded public-key blobs, client helpers, server
  dispatch, and failure-path coverage.
- Added the `agent_decoder` cargo-fuzz target and wired every current decoder target into the Linux
  CI fuzz-build job.
- Redacted signed data and lock or unlock passphrases from `AgentMessage` debug output, with a
  regression test for the public logging surface.
- Added a fail-closed per-profile forwarding policy and authorizer hook that gates every forwarded
  signature before server dispatch, including framed-stream serving and allow or deny tests.
- Added a bounded forwarded-agent channel adapter that reassembles fragmented and multi-frame
  channel data, splits responses at the channel limit, rejects management and extension requests,
  and distinguishes clean close from truncation.
- Added the engine-independent `AuthAgentChannel` boundary for `auth-agent@openssh.com`: bounded
  open confirmation and packet limits, channel-number validation, policy-protected request
  dispatch, response fragmentation, and typed clean or truncated close outcomes. Concrete SSH
  engine scheduling and interoperability remain open.
- Added bounded RFC 4252 `none`, `password` and password-change, and keyboard-interactive request,
  prompt, and response codecs; password and response bytes use zeroizing secret storage and
  malformed, NUL, truncation, and size failure paths are covered.
- Added RSA software signers with strict `rsa-sha2-256` and `rsa-sha2-512` selection, SSH `ssh-rsa`
  public-key blobs, certificate subject binding, and hash-substitution and malformed-key failures.
- Added a bounded SFTP v3 packet boundary for INIT/VERSION negotiation, core file requests and
  responses, binary-safe handles and extension data, malformed-input rejection, and pipelined
  request correlation.
- Added the OpenSSH `limits@openssh.com` SFTP extension request and response codec with bounded
  extension payloads and malformed-length rejection.
- Added bounded SFTP client request builders for open, read, write, close, and limits requests;
  invalid requests release their reserved ids instead of consuming pipeline capacity.
- Added bounded SFTP directory and path packets for opendir, readdir, remove, mkdir, rmdir, and
  realpath, including `NAME` entry responses and client builders with request-correlation tests.
- Added bounded SFTP metadata and symbolic-link packets for setstat, fsetstat, readlink, and
  symlink, with client builders and malformed and invalid-value coverage.
- Added the stable HTTP error-code registry and RFC 9457 problem details with JSON and deterministic
  CBOR codecs, including malformed-input tests and a published CBOR vector.
- Extended the stable error-code registry for authenticated sync HTTP adapters with
  `auth.authentication_required`, `sync.invalid_request`, and `sync.storage_unavailable`.
- Added strict K-3 challenge, signed-device request, and token response JSON codecs with canonical
  nonce, UUIDv7, timestamp, signature, token-type, lifetime, and failure-path validation, plus
  published authentication vectors.
- Corrected K-3 token response validation to accept any positive encoded lifetime while retaining
  the 600-second and 30-day writer defaults, with a variable-lifetime vector and failure tests.
- Added deterministic K-4 sync session request and response codecs, validation of limits and vault
  identifiers, forward-compatible vault kinds, and published session vectors.
- Added the K-3 QR pairing payload, strict parser, and constant-time verification of relayed
  device keys against a published known-answer vector.
- Added the K-3 typed-code CPace Ristretto255/SHA-512 exchange with fixed transcript context,
  Crockford code parsing, zeroizing session material, constant-time confirmations, and a
  nonce-checked XChaCha20-Poly1305 payload channel, with a published known-answer vector.
- Added K-4 change-feed query and response codecs with canonical pagination parameters, strict
  ordering and cursor validation, failure-path coverage, and published deterministic CBOR vectors.
- Added K-4 write-batch and assignment codecs with atomic-batch limits, acknowledgement request and
  response codecs, objects snapshot pages, bounded versions history pages, strict failure paths,
  published deterministic CBOR vectors, and the cursor-ahead and object-not-found error codes.
- Added content-free K-4 WebSocket notification codecs for vault advancement, pending rotation, and
  device revocation, with strict event validation, extension tolerance, failure-path tests, and
  published deterministic CBOR vectors.
- Added K-4 account key-bundle GET and PUT codecs with opaque artifact limits, sorted device wraps
  and certificate lists, signed canonical-CBOR input helpers, replay revision validation, failure
  paths, and published deterministic CBOR vectors.
- Accepted `null` in optional scalar fields as a clear that merges by its clock and reads as absent
  (D-57), with a published merge vector; required fields still reject `null`.
