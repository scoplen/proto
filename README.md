# proto

Shared Rust contracts and protocol libraries for Scoplen.

Scoplen is a Plystra project. This repository is the shared foundation for the client and server
workstreams; it does not contain the desktop client or the server process. Its crates are licensed
under Apache-2.0.

## Status

Maturity: Exploration. Maintenance: Active. The repository baseline (roadmap gate S1), K-1 object
model (S2), and K-2 cryptographic gate (S3) are complete. The model includes deterministic CBOR, schema-version
handling, per-object limits, merge properties, and executable known-answer vectors. Protocol,
cryptographic, and wire behavior is added only from the canonical specifications in `scoplen-docs`;
the S3 primitive boundary now includes zeroizing secret containers, operating-system randomness,
XChaCha20-Poly1305, HKDF-SHA-256, Argon2id, P-256 and Ed25519 signatures, and HPKE key wrapping
for device and account recipients. The published K-2 known-answer set is exercised through the
`scoplen-crypto` public API, including account/request-bound escrow share contexts and the
administrator recovery verification code, CPace pairing exchange, and canonical QR pairing bindings.
The `scoplen-ssh` crate exposes K-7's ordered algorithm policy, role-specific offers, strict key
exchange state, a bounded direct TCP byte transport, and engine-independent authentication
boundaries. `TcpTransport` limits host resolution, uses bounded RFC 8305 style staggered Happy
Eyeballs attempts under one total connect timeout, and enables `TCP_NODELAY`; its synchronous
boundary cancels and joins all async attempts before returning. `Socks5Transport` and `HttpConnectTransport` add bounded no-auth SOCKS5 and HTTP
CONNECT proxy composition with handshake-only socket timeouts. SOCKS5 username/password and HTTP
CONNECT Basic proxy authentication are bounded and keep passwords out of transport state. The
transports do not perform SSH negotiation or authentication. `ProxyCommandTransport` provides
bounded direct child-process stdin/stdout composition without shell interpolation and reaps the
child on shutdown or drop.
`ClientConnection::connect` uses async resolution and family-interleaved Happy Eyeballs dialing
with a ten-second DNS-plus-TCP deadline, followed by a separate ten-second SSH handshake deadline.
`connect_with_timeout` sets the same positive duration for each stage. Direct setup enforces the
255-byte host and sixteen-raw-address bounds, returns typed transport or SSH handshake timeout
errors, and closes pending dials or the engine-owned socket on cancellation. The synchronous
system DNS resolver remains outside the cancellation guarantee.
`ClientConnection::connect_via_socks5` and `connect_via_http_connect` compose the existing bounded
proxy handshakes with the concrete async SSH client, preserving proxy rejection and timeout errors.
`ClientConnection::connect_via_proxy_command` composes a directly spawned, bounded desktop
ProxyCommand with the same async SSH handoff; command arguments are passed without shell
interpolation. Callers supply an SSH handshake timeout, and timeout or cancellation terminates
and reaps the child.
`GatewayTransport` composes the bounded K-6 client-hello frame over an established byte transport,
handling partial writes and typed failures before the SSH engine consumes the stream.
`GatewayTlsClientConfig` builds a TLS 1.3 client with deployment or OS roots and the required
`spl-gw/1` ALPN, and `connect_and_handshake` performs certificate verification, strict ALPN
checking, and the client hello before the SSH version exchange. `ClientConnection::connect_via_gateway`
now composes bounded edge TCP dialing, TLS, the K-6 prelude, and the SSH handshake; the stream-level
`AsyncGatewayTransport` and `connect_via_gateway_stream` remain available when a caller owns the TLS
stream. The direct route applies a bounded timeout to the gateway handshake and maps a stalled edge
to a typed failure.
Software Ed25519, P-256, and RSA/SHA-2 signers, FIDO2 security-key signer integration,
RFC 4252 `none`, password and keyboard-interactive codecs, certificate validation, and
host-verification callbacks are available. The concrete client
exposes a `none` probe that reports the server's remaining methods, and handles bounded
keyboard-interactive challenge rounds with prompt and response validation before sending answers
to the SSH engine. It also authenticates with validated OpenSSH user certificates through the
shared signer boundary, checking the requested principal and subject key before dispatch. RSA
certificates retain their legacy blob type while selecting the requested SHA-2 certificate
algorithm; signing binds the complete certificate and selected hash. Authentication rejection
reports `partial_success` and `remaining_methods` in server order, omitting unknown engine methods.
Callers can complete another factor on the same connection. Until full authentication succeeds,
channel opens and remote-forwarding operations return `NotAuthenticated` locally. Real SSH tests
cover OTP followed by password, wrong factors, premature channel/forwarding operations, and both
RSA certificate hashes. Once authenticated, all five authentication and probe entrypoints return
`AlreadyAuthenticated` locally, preventing a second authentication call from waiting indefinitely;
channels remain usable on the same connection. Concrete password-change support remains incomplete. Agent support
includes bounded Unix-socket and Windows named-pipe streams, Pageant named-pipe compatibility,
identity and signing requests, an `AgentSshSigner` that binds agent signatures to the concrete
public-key authentication session, add/remove/lock/smart-card management, opaque extensions, and
fail-closed forwarding policy.
Bounded RFC 4254 channel codecs cover session and forwarding requests. The engine-independent
`AuthAgentChannel` composes the `auth-agent@openssh.com` channel lifecycle with bounded agent
framing, per-signature forwarding authorization, peer packet limits, and clean/truncated close
outcomes.

Legacy Pageant `WM_COPYDATA` has a bounded, fail-closed protocol adapter with deterministic
mapping names and an injectable platform backend. On Windows, `connect_native_pageant_agent`
uses the native Win32 transport through the pinned Pageant adapter; the safe protocol boundary
still validates every request and response before returning it.

A bounded SFTP v3 packet boundary covers negotiation, core file, directory/path, and metadata
requests and responses, bounded
request correlation, and the OpenSSH `limits@openssh.com`, `posix-rename@openssh.com`,
`statvfs@openssh.com`, `fstatvfs@openssh.com`, `hardlink@openssh.com`, `fsync@openssh.com`,
`lsetstat@openssh.com`, `expand-path@openssh.com`, and `copy-data` extensions, with binary-safe
handles and extension data. A concrete `russh` adapter now owns TCP or caller-supplied stream
handshakes, validates raw keys and host certificates before invoking the trust callback, supports
password authentication, and exposes opaque session and `direct-tcpip` channels with PTY, shell,
exec, window-change, bounded data, EOF, close, and peer-event operations. `ClientConfig` carries
the per-Host `HostAlgorithmPolicy` into russh's ordered concrete offers, appending explicitly
enabled legacy algorithms only when supported by the selected engine. A `ClientChannelStream`
can carry a target handshake through a jump host with
`ClientConnection::connect_via_direct_tcpip`; repeating the operation composes arbitrary jump
depth while retaining each parent connection. One connection multiplexes session and forwarding
channels with a configurable simultaneous-channel cap; channel or stream drop releases a slot.
`ClientConfig::with_rekey_limits` configures outgoing SSH payload-byte and elapsed-time limits per
Host; `with_rekey_read_limit` configures the incoming payload threshold independently. Byte limits
are between one byte and one GiB, inclusive; the engine defaults remain one GiB in either direction
and one hour. Counters exclude packet lengths, padding, and authentication tags. The released
`russh` 0.64.1 engine initiates rekey after either threshold or the elapsed deadline, including
while authenticated connections are idle. Completed exchanges reset counters and the deadline;
the event loop owns the timer and stops on disconnect, transport failure, or connection drop.
Retained channel handles and streams cannot keep a dropped connection alive. Explicit disconnect
allows one second for graceful protocol shutdown, then closes the transport if output is blocked.
Automatic rekey waits until authentication completes, including a pending keyboard-interactive
prompt, then handles an expired elapsed limit without waiting for channel traffic. Full
OpenSSH cipher-dependent default compatibility remains open.
Rekey durations must fit an event-loop deadline. `ClientConfig::with_inactivity_timeout` also
returns a typed result, rejects zero or unrepresentable enabled durations, and accepts `None` to
disable the timeout. Received traffic resets the configured inactivity timer.
`ClientConfig::with_keepalive` configures encrypted `keepalive@openssh.com` probes per Host and
returns a typed configuration result. Probes are disabled by default, with a missed-reply count
of three. Enabled intervals must be positive and representable as an event-loop deadline, and
the count must be greater than zero and less than `usize::MAX`. `None` disables probes regardless
of the count. Responsive peers preserve the channel; a silent peer expires the configured
connection. This does not implement the separate `ping@openssh.com` extension.
The adapter keeps the engine types out of the public API. A bounded SOCKS4a/SOCKS5 dynamic
listener now composes the handshake with `direct-tcpip`, including cancellation, concurrency
limits, bidirectional forwarding, EOF/close propagation, and protocol failure mapping.
Cancellation interrupts stalled channel sends and bounds the best-effort close wait, so listener
shutdown is not held open by a peer that stops accepting data. Pageant interoperability still
requires a Windows Pageant installation and remains outside the hosted CI
matrix. `SftpChannel`
now composes the bounded v3 handshake and packet framing over an accepted SSH `session` channel
with bounded subsystem failure and truncation mapping; `SftpSession` adds bounded pipelining and
request correlation, negotiates `limits@openssh.com`, caps transfer chunks to the peer's packet,
read, and write limits, and supports resume-by-offset uploads/downloads with progress callbacks
on that channel. Pipelined downloads fill short-read gaps before advancing contiguous progress;
an early EOF for a caller-specified end offset and an empty data response fail instead of
silently returning a partial file.
An interrupted or failed exchange that loses request correlation invalidates only its SFTP
session. The failing call retains its original typed error; later operations return
`SessionUnusable` until the caller opens a new SFTP channel on the same authenticated SSH
connection. Local validation and fully correlated file-status rejections leave the session usable.
The concrete adapter also forwards bounded environment and signal requests and accepts
server-opened `auth-agent@openssh.com` channels. `ForwardedChannel::serve_agent` reassembles
russh channel fragments, applies the fail-closed forwarding policy, and returns bounded agent
responses; an in-process russh round trip covers the concrete lifecycle. External OpenSSH and
Pageant interoperability, live gateway interoperability, and broader channel scheduling remain
unverified. The agent-backed signer also completes the concrete public-key authentication flow
against the in-process russh server; platform agent interoperability remains unverified.
The `openssh_interop` example provides a disposable external-server smoke test when
one host trust pin and one authentication source are supplied. Set either
`SCOPLEN_OPENSSH_HOST_KEY` to the server's OpenSSH public-key line or
`SCOPLEN_OPENSSH_HOST_CA_KEY` to a CA public-key file, and select
`SCOPLEN_OPENSSH_PASSWORD`, `SCOPLEN_OPENSSH_RSA_KEY`,
`SCOPLEN_OPENSSH_ED25519_KEY`, or `SCOPLEN_OPENSSH_P256_KEY`. The key variables contain paths to
unencrypted OpenSSH private keys and are mutually exclusive. The optional
`SCOPLEN_OPENSSH_RSA_HASH=256|512` selects the RSA-SHA2 signature algorithm (default 512).
Optional host, port, and username variables select the test server. It verifies the selected host
trust pin, authentication, exact command output, and exit status zero. Password,
both RSA-SHA2 variants, Ed25519, and P-256 passed against disposable Linux OpenSSH containers;
wrong credentials and a wrong host key were rejected. The broader interoperability matrix remains
open.
`pwsh ./scripts/ssh-algorithm-interop.ps1` starts disposable OpenSSH listeners constrained to
Curve25519/AES-CTR, ML-KEM/ChaCha20, and one legacy-only set. The `algorithm_interop` example
verifies a pinned host key, authenticated command, exact output, and exit status for both modern
sets, handshake rejection by the default policy on the legacy set, a working command after per-Host
legacy opt-in, and rejection by another default Host. Pass
`-LegacyCipher 3des-cbc` to constrain the legacy listener to 3DES instead of AES-CBC.
The concrete engine includes 3DES support, but offers it only when that Host explicitly enables
`3des-cbc` through `HostAlgorithmPolicy::with_legacy`. CI checks both constrained ciphers. The
remaining algorithm and platform interoperability matrix is incomplete.
The same script runs `strict_kex_interop`: a pinned-key, password-authenticated OpenSSH command
succeeds, then a local relay inserts a valid `SSH_MSG_IGNORE` before and after the server's first
KEXINIT in separate connections. The strict client rejects both before host-key verification, while a server that does
not advertise strict KEX accepts the same packets. This covers one initial exchange and the
selected modern algorithms. The same script runs `rekey_interop` against three dedicated OpenSSH
listeners. Client and server 32 KiB payload thresholds separately trigger authenticated rekey;
a one GiB control must not rekey. Each case verifies 128 KiB of exact binary data echoed over one
session channel and a successful exit status. OpenSSH DEBUG3 logs must show post-authentication
KEXINIT and NEWKEYS in both directions, with the first KEXINIT received by the server for a
client-initiated exchange and sent by it for a server-initiated exchange. The control log must
contain neither message after authentication. This observes OpenSSH's decrypted protocol logs,
not encrypted packet sequence numbers; rekey strictness and the wider server, platform, and
algorithm matrix remain open.
With a disposable OpenSSH server, `cargo run -p scoplen-ssh --example proxy_command_interop`
exercises a real SSH handshake through a child process's standard streams. Set
`SCOPLEN_OPENSSH_HOST_KEY` to the server's public-key line and `SCOPLEN_OPENSSH_PASSWORD` to the
test account password; optional `SCOPLEN_OPENSSH_HOST`, `SCOPLEN_OPENSSH_PORT`, and
`SCOPLEN_OPENSSH_USER` select the endpoint. The example checks the pinned host key, password
authentication, command output and exit status, wrong-pin rejection, a missing or failed child,
and handshake timeout with child cleanup. It passed from Windows against a disposable Linux
OpenSSH container; Unix hosts and other server implementations remain unverified for this route.
`cargo run -p scoplen-ssh --example jump_chain_interop` verifies two nested `direct-tcpip`
handshakes through an authenticated OpenSSH server with TCP forwarding enabled. Set the same host
key, password, host, port, and user variables, plus `SCOPLEN_OPENSSH_JUMP_TARGET_PORT` to the
server's SSH port as seen from inside the server. It checks the host pin and password at every
hop, session commands on each connection, wrong-pin and closed-target rejection, and parent
connection reuse after the failures. The disposable OpenSSH script below runs this example.
`pwsh ./scripts/openssh-interop.ps1` provisions a disposable Alpine 3.21 OpenSSH server and runs
the direct SFTP/forwarding, ProxyCommand, SOCKS, and nested-jump examples. It also tests raw keys
and user certificates with Ed25519, P-256, RSA-SHA2-256, and RSA-SHA2-512. A software-generated
authenticator fixture tests raw `sk-ssh-ed25519@openssh.com` and
`sk-ecdsa-sha2-nistp256@openssh.com` authentication, including rejection of signatures from the
wrong key, application, or session payload. The same fixture tests user certificates over both
security-key types, with full certificate binding, wrong subject or application, principal,
validity, CA pin, server CA trust, and KRL serial and key-ID rejection paths. Rejection checks cover
wrong passwords, unauthorized keys, wrong certificate principals, wrong local CA pins, and
locally valid certificates from a server-untrusted CA. A separate trusted CA signs three Ed25519
certificates over one key: a KRL rejects one by serial and one by key ID, while an unrevoked
certificate and the same raw public key still authenticate and run the exact command with exit
status zero. OpenSSH enforces the KRL; the client does not load or parse it. The Linux CI workflow
runs the same script on each change; disposable keys and the container are removed afterward.
`UserCertificate::parse_and_validate` checks the embedded CA signature, certificate role,
principal, validity, and critical options. The caller still decides whether to trust that CA;
the interoperability example compares it with an explicitly pinned CA public key before calling
`authenticate_certificate`. OpenSSH enforces its configured `TrustedUserCAKeys` and KRL; the
client does not parse the KRL. This fixture does not establish physical-token, libfido2,
Windows WebAuthn, other server versions or platforms, agent-backed certificate, or broader
certificate-revocation coverage.
To run `security_key_interop auth ed25519` or `security_key_interop auth p256` independently,
set `SCOPLEN_OPENSSH_HOST_KEY` to the server's OpenSSH host public-key line and set
`SCOPLEN_OPENSSH_PORT` and `SCOPLEN_OPENSSH_USER`. For certificate authentication, also set
`SCOPLEN_OPENSSH_USER_CERT` to the OpenSSH user-certificate file and
`SCOPLEN_OPENSSH_USER_CA_KEY` to the pinned CA public-key file.
For host-certificate mode, the concrete adapter checks the certificate signature, host principal,
validity, and critical options before the callback checks the CA pin. A disposable
`linuxserver/openssh-server` container with an Ed25519 `HostCertificate` accepted that path and
rejected an unrelated CA pin. Other host-certificate algorithms and servers remain unverified.
The same example also passed against Dropbear 2025.88 from an Alpine 3.23 disposable container:
install `dropbear`, create a `scoplen` user with a single authorized Ed25519 key, generate an
Ed25519 host key with `dropbearkey`, run Dropbear on port 2222, pin its public key, and set
`SCOPLEN_OPENSSH_ED25519_KEY` to the authorized private-key path. A second private key was
rejected. Dropbear SFTP, forwarding, certificates, and other authentication paths remain unverified.
`pwsh ./scripts/dropbear-interop.ps1` now runs the same session-command example against disposable
Dropbear 2024.86 in Alpine 3.21 with password authentication, then checks wrong-password and
wrong-host-key rejection. The CI workflow runs this test on Linux; the container is stopped after
the run.
The example also passed against OpenSSH 9.7p1 from a disposable Alpine 3.20 container with
Ed25519 and RSA-SHA2-256/512 public-key authentication and a session command; an unauthorized
RSA key was rejected. The container uses `openssh-server`, an unlocked `scoplen` test account,
authorized test public keys, and generated host keys. This adds one older OpenSSH release to the
interop evidence; the remaining version and platform matrix is open.
For a user certificate, also set `SCOPLEN_OPENSSH_USER_CERT` to its OpenSSH certificate
file and `SCOPLEN_OPENSSH_USER_CA_KEY` to the pinned CA public-key file. The example checks the
certificate signature, principal, validity, critical options, and CA pin before sending it.
A disposable `linuxserver/openssh-server` container with `TrustedUserCAKeys` configured accepted
the certificate; a certificate from another CA was rejected by OpenSSH. The automated Alpine
fixture covers Ed25519, P-256, and both RSA-SHA2 variants, plus server-side KRL rejection of
serial- and key-ID-revoked Ed25519 certificates. Other certificate revocation forms, algorithms,
platforms, and server versions remain unverified.
Set `SCOPLEN_OPENSSH_SFTP=1` for the same example against a disposable server to additionally
exercise SFTP v3 on the authenticated connection. This verifies advertised OpenSSH transfer
limits, a missing-file response with released request state, `statvfs@openssh.com` filesystem
statistics and missing-path rejection, pipelined upload in two parts, resumed download with
progress and byte comparison, `fsync@openssh.com` and `fstatvfs@openssh.com` on the open upload
handle, rejection of both requests after closing that handle without retaining request state,
standard SFTP v3 `FSTAT` reporting the uploaded file's exact size on the open handle and rejecting
the closed handle without retaining request state, standard `FSETSTAT` growing and restoring its
size on the open handle and rejecting the closed handle without changing the file, and
`hardlink@openssh.com` success with identical
linked bytes, missing-source and existing-destination
rejection, plus `posix-rename@openssh.com` missing-source rejection, a rename preserving file bytes,
replacement of an existing destination with different contents, `expand-path@openssh.com` returning
an absolute path to the existing file with matching bytes and an absolute path for a missing file
(whose subsequent open fails), and `copy-data` between open handles with source and destination
offsets, byte comparison, invalid-source and closed-destination rejection, request-slot release,
and cleanup of the unique remote paths. It also verifies `lsetstat@openssh.com` on a file and a
symbolic link: the link's changed timestamp is visible through `LSTAT` while `STAT` shows the
target's timestamp unchanged. A missing path is rejected, request slots are released, and the
temporary link is removed.
The link setup follows OpenSSH's reversed `SYMLINK` wire order relative to the SFTP v3 draft.
It also checks `READLINK` returns the exact target bytes, rejects a missing link and the removed
link, and releases each request slot. The authenticated in-process server exercises the SFTP v3
draft's `SYMLINK` argument order; the external OpenSSH run exercises its reversed wire order.
The same run verifies `REALPATH` resolves the current directory and normalizes both an existing
file's `./` path and a missing final component to the expected absolute bytes. Resolving through a
regular file fails, and every request slot is released; the authenticated in-process server covers
those success and failure responses too.
The standard SFTP v3 `RENAME` request separately checks missing-source rejection, refusal to
replace an existing file, byte-preserving moves in both directions, request-slot release, and
cleanup. The authenticated in-process server covers the same lifecycle.
The same SFTP run creates a unique directory and file, reads directory entries until EOF, rejects
a missing directory, a nonempty directory removal, and a read from a closed directory handle,
then removes both paths and checks that the directory is gone. Each response releases its request
slot.
The earlier SFTP paths passed against a disposable `linuxserver/openssh-server` container; the
directory lifecycle also passed against disposable Alpine OpenSSH 9.9p2. Other SFTP operations,
server implementations, and platforms remain unverified.
Set `SCOPLEN_OPENSSH_FORWARD=1` to verify an RFC 4254 `direct-tcpip` channel to the disposable
server's own SSH listener at `127.0.0.1:2222`, then a refused connection to port 1 and a fresh
session open. The `linuxserver/openssh-server` image disables TCP forwarding by default; this
smoke test passed after setting `AllowTcpForwarding yes` in the disposable container's
`/config/sshd/sshd_config` and reloading its SSH listener. Other forwarding directions,
targets, servers, and platforms remain unverified.
With the same disposable server and forwarding setting, run
`cargo run -p scoplen-ssh --example dynamic_socks_interop` using the host-key and password
environment variables above. The example binds a local dynamic listener and verifies concurrent
SOCKS5 and SOCKS4a routes to the server's SSH listener, refusal and closure for a closed target,
a fresh forwarded connection and session command on the same authenticated SSH connection, and
listener cancellation releasing its local port. It passed from Windows against a disposable Linux
OpenSSH container; other host platforms, destinations, and server implementations remain
unverified for this route. The disposable OpenSSH CI script above also runs this example.
The `scoplen-api` crate exposes the K-3 error-code registry, RFC 9457 problem details, and device
challenge, signed-device request, native/browser refresh request, and token response JSON codecs,
plus K-4 session, change-feed,
write-batch, bounded conflict problem, acknowledgement, snapshot, version-history, content-free
notification, notification WebSocket opening context, first-message authentication and ready
acknowledgement, account key-bundle, shared-vault creation, key retrieval, epoch-publication,
member-addition, and epoch-retirement response codecs. The K-3 messages use JSON and the K-4
messages use deterministic CBOR. K-6 now includes the bounded gateway client-hello
frame (`ticket` and `dpop_proof`) with a published vector and failure-path coverage. OpenAPI
resources now have an authored OpenAPI 3.1 document at `crates/scoplen-api/openapi/v1.yaml`,
generated Rust envelope/query types, and the local `@scoplen/api` TypeScript package surface.
The control-plane and shared `ProblemDetails` Rust paths use the same validated eight-field
JSON/CBOR error type. The OpenAPI schema and generated TypeScript declaration require `type`,
`title`, `status`, `detail`, `instance`, `code`, `changed`, and `retryable`; decoders accept unknown
response fields and syntactically valid future error codes.
The K-3 authentication boundary now validates strict, bounded challenge and signed-device JSON
requests, canonical HTTPS origins, and the exact domain-separated P-256 signature input. The
native refresh body requires one opaque token (at most 2,048 UTF-8 bytes); the browser body is
exactly `{}` with its HttpOnly refresh cookie supplied by the browser. Both JSON bodies are capped
at 4,096 encoded bytes. The browser response omits and rejects any `refresh_token` field while
retaining unrelated response extensions. OpenAPI and generated TypeScript types describe all three
authentication paths, including the DPoP-only refresh operation and distinct browser response.
Callers pass the returned bytes to the fallible K-2 `DeviceSigner::sign` boundary and propagate
signer failures, including hardware-device failures.
Challenge storage, credential verification, and token issuance are server responsibilities; this
library does not implement a production authentication service. DPoP proof verification, Origin
and cookie handling, atomic refresh rotation, and reuse detection remain server responsibilities.
`AuthTokenResponse` redacts both opaque tokens in debug output while retaining token type and
lifetimes for diagnostics.
`SyncNotificationAuth` also redacts its token and proof in debug output. Its deterministic CBOR
codec enforces the 4 KiB token, 8 KiB proof, and 16 KiB complete-message bounds and compact-JWS
lexical form; it does not verify a JWT, DPoP claims, device state, proof replay, or the WebSocket
lifecycle. Notification context and ready readers accept unknown response extensions but reject
fields from other known notification message types.
Challenge timestamps use the K-3 pre-Stable UTC profile: uppercase `T` and `Z`, optional fractional
seconds, and seconds from `00` through `59` without leap-second labels.
The internal `spl.gateway.v1.Control` and `spl.agent.v1.Agent` protobuf source contracts are
also checked in under `crates/scoplen-api/proto`. The built-in Cedar schema and role policies are
parsed and strictly validated in the API crate's tests. The API crate now generates bounded Rust
message bindings and publishes the internal descriptor set, plus deterministic TypeScript message,
oneof, enum, and service metadata bindings at `@scoplen/api/proto`. `ControlService` and
`AgentService` provide bounded concrete implementations for the internal gateway and host-agent
RPCs, with cursor-based event streams, liveness responses, audit/configuration counters, and
registration/enrollment responses. `server_tls_config` requires client certificates signed by the
configured CA, while `client_tls_config` configures the matching CA, client identity, and bounded
server name; an in-process test proves an authenticated client succeeds and a client without an
identity is rejected. The services are deliberately in-memory wiring primitives; durable policy,
identity, and audit storage remain owned by the server application.

## Repository shape

The Cargo workspace contains `scoplen-ssh`, `scoplen-model`, `scoplen-crypto`, `scoplen-api`, and
`scoplen-test-vectors`. K-1 vectors are in `vectors/baseline.json`; K-2 cryptographic vectors are
in `vectors/crypto.json`. The published K-3 auth and API problem, sync session, change-feed, and
remaining K-4 message vectors are in `vectors/api-auth.json`, `vectors/api-problem.json`,
`vectors/sync-session.json`, `vectors/sync-changes.json`, `vectors/sync-messages.json`,
`vectors/sync-notifications.json`, `vectors/sync-notification-auth.json`, `vectors/sync-keys.json`,
`vectors/sync-vaults.json`, `vectors/sync-vault-keys.json`, `vectors/sync-vault-epochs.json`,
`vectors/sync-vault-members.json`, and `vectors/gateway.json`. The shared loader is usable by both
workstreams.

## Development

Rust 1.99.0 is pinned in `rust-toolchain.toml` and is the minimum supported version, aligned with
the other implementation repositories. The Pageant dependency remains patched locally for its
bounded native WM_COPYDATA mapping and current-thread query names required by K-7.

```text
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
node crates/scoplen-api/openapi/generate.mjs --check
```

The OpenAPI generator checks the authored error and authentication schemas and detects drift in
the generated path list and TypeScript declarations. Run it without `--check` to regenerate those sections;
the Rust CI matrix runs the drift check on every supported desktop runner.

For a paired same-host comparison with OpenSSH under the two required S4 ciphers, run
`pwsh ./scripts/ssh-throughput.ps1`. Each cipher fails the command when its measured median
throughput is below 80% of OpenSSH's on this host. The setup, measurement method, local results,
and release-evidence limits are in [docs/ssh-throughput.md](docs/ssh-throughput.md).

For diagnostic one-byte SSH echo latency comparisons against direct `russh` and a disposable
OpenSSH server/client pair, run `pwsh ./scripts/ssh-keystroke-latency.ps1`. The local engine
comparison runs with `cargo run --locked --release -p scoplen-ssh --example keystroke_latency`.
The methods and limits are in [docs/ssh-keystroke-latency.md](docs/ssh-keystroke-latency.md).

The tracked `fuzz/corpus/<target>/seed-*` files provide small synthetic valid and malformed
inputs for all seven parser targets. Valid model and certificate inputs come from the published
known-answer vectors in `vectors/baseline.json` and `vectors/crypto.json`; SSH, SFTP, and agent
frames follow the public codec tests. The `sync_notification` target checks context, credentials,
acknowledgements, and events through their public codecs and requires accepted messages to
survive a canonical encode/decode round trip. Its seeds include the published notification
vectors, truncated credentials, a zero sequence, and contexts exactly at and above the 16 KiB
bound. The Linux change check replays every target's corpus, and
the daily five-minute fuzz run starts from the same seeds. On Linux, replay one target with nightly
Rust and `cargo-fuzz` using `cargo +nightly fuzz run sftp_decoder fuzz/corpus/sftp_decoder -- -runs=0`.
Fuzz-discovered mutations remain ignored; review, minimize, and name useful regression inputs
before tracking them as new seeds. The scheduled run's results and performance targets remain
separate Gate S4 acceptance work.

The `ssh_protocol` target also exercises security-key public keys and both signature-body
algorithms, requiring accepted inputs to round-trip, and parses and validates SSH user/host
certificates at a fixed clock and principal. Its identity seeds use the software-generated
security-key interoperability identities and a disposable OpenSSH Ed25519 CA; signature-body
seeds test syntax rather than prove a hardware signature. Malformed flags and truncated bodies
are included. No production private keys or token credentials are part of the corpus.

The local Cargo patch file used for cross-repository development is intentionally ignored. Do not
publish crates, tags, or packages from an agent checkout.

## Security

Report vulnerabilities privately to `scoplen-security@plystra.com`; see [SECURITY.md](SECURITY.md).
Do not put secrets or private infrastructure details in issues, examples, vectors, or logs.

## License

The source code is Apache-2.0. See [LICENSE](LICENSE).
