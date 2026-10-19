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
Route field 8 carries a separate proxy username, paired with the password Credential reference for
SOCKS5 and HTTP CONNECT routes. The shared model validates its scalar text shape, pairing, route
kind, and printable ASCII bounds, with exact canonical and clear/merge vectors. HTTP CONNECT
checks both Basic fields before dialing: each is 1-255 printable ASCII bytes, and the username
cannot contain `:`. SOCKS5 retains its bounded byte-string credential profile. The proxy
handshakes currently use plain TCP and send configured credentials without transport encryption.
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
Software Ed25519, ECDSA P-256/P-384/P-521, and RSA/SHA-2 signers, FIDO2 security-key signer
integration, RFC 4252 `none`, password and keyboard-interactive codecs, certificate validation, and
host-verification callbacks are available. The concrete client
exposes a `none` probe that reports the server's remaining methods, and handles bounded
keyboard-interactive challenge rounds with prompt and response validation before sending answers
to the SSH engine. It also authenticates with validated OpenSSH user certificates through the
shared signer boundary, checking the requested principal and subject key before dispatch. RSA
certificates retain their legacy blob type while selecting the requested SHA-2 certificate
algorithm; signing binds the complete certificate and selected hash. `EcdsaSshSigner` selects the
NIST curve from an imported OpenSSH private key, while `P256SshSigner` remains available for
Scoplen's P-256 key type. Authentication rejection reports `partial_success` and
`remaining_methods` in server order, omitting unknown engine methods.
`ClientConnection::server_rsa_sha2_selection` reads the server's `server-sig-algs` once per
connection and reports SHA-512, SHA-256, an advertised SHA-1-only RSA choice, or an undetermined
choice. It never selects SHA-1 or sends an authentication probe. The complete query has a
two-second deadline; success, timeout, engine failure, and cancellation are terminal cached
outcomes. Callers may explicitly try an existing SHA-2 signer when the result is undetermined.
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
Generic extensions use RFC 9987 request 27 and named response 29 with raw opaque contents,
including an empty `query` body. Client responses must echo the requested extension name;
empty success 6 is also accepted. Unknown local extensions return failure 5 and failed supported
extensions return failure 28. Forwarded extensions remain refused with ordinary failure without
terminating a healthy channel; session-bind and destination constraints are not implemented.
Framed agent streams, including Pageant named pipes, become unusable after a write, flush, read,
or response-frame failure. The failing exchange returns its original error; later exchanges return
`ChannelUnusable` without I/O. Callers must reconnect before retrying. Local request rejection and
a complete agent `Failure` response leave the stream usable. This does not add a blocking-I/O
deadline or cancellation guarantee.
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
the endpoint name as the default host-certificate principal and reads Unix time when a presented
certificate is verified, including when a configuration is reused after a delay. If the clock
cannot supply Unix time, validation returns `ClientError::HostKeyClock`. An explicit
`HostKeyPolicy::new(principal, now)` retains its caller-supplied fixed validation time. Invalid
certificates are rejected before the trust callback or authentication. `ClientConfig` also carries
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
The public `StrictKeyExchange` helper enforces strict first-packet and non-KEX admission only
through each direction's initial `NEWKEYS`. During later rekeys, ordinary transport packets may
interleave with KEX controls, including after one direction completes; the first KEX control in
each direction still has to be `KEXINIT`. Strict negotiation resets each direction's sequence
immediately after every `NEWKEYS`, while non-strict exchanges keep advancing. The helper's public
state-machine tests do not establish behavior of the separate encrypted `russh` engine.
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
`SftpSession::upload_from` reads exactly a declared byte length from an async reader at its current
position and writes at a caller-selected remote offset. It never seeks or reads beyond that length;
the byte-slice `upload` entry point shares its bounded pipeline and contiguous progress behavior.
Both in-flight writes and acknowledged writes waiting for an earlier response occupy pipeline
slots. Premature source EOF and source I/O failures preserve their I/O error and isolate the SFTP
session while the parent SSH connection remains usable.
An interrupted or failed exchange that loses request correlation invalidates only its SFTP
session. The failing call retains its original typed error; later operations return
`SessionUnusable` until the caller opens a new SFTP channel on the same authenticated SSH
connection. Local validation and fully correlated file-status rejections leave the session usable.
An in-process SSH peer that stops replenishing one channel's write window exercises cancellation
while `send_request` is still writing: the pending request slot is cleared, the affected SFTP
session becomes unusable, and another SSH session and fresh SFTP channel remain usable on the
parent connection. An independent peer-induced outbound write I/O error remains unverified;
the locked `russh` stream reports a broken write queue when the connection itself ends.
The concrete adapter also forwards bounded environment and signal requests and accepts
server-opened `auth-agent@openssh.com` channels only while a live session on the connection has
explicitly requested agent forwarding. A locally failed or canceled send and session close or drop
revoke that permission; channel EOF alone retains it. A server failure reply is surfaced to the
caller but cannot be correlated with a specific outstanding channel request.
`ForwardedChannel::serve_agent` reassembles russh channel fragments, rechecks the live opt-in,
applies the fail-closed forwarding policy to
identity queries and signatures, and returns bounded agent responses; in-process russh round trips
cover unsolicited opens, revocation, and the concrete lifecycle. The agent-backed signer
also completes the concrete public-key authentication flow
against the in-process russh server. `pwsh ./scripts/ssh-agent-interop.ps1` starts a disposable
OpenSSH server and a real `ssh-agent` in one Alpine container. The `openssh_agent_interop` example
selects an exact raw identity, signs through the agent protocol, and completes pinned-host-key
raw-key and pinned-user-CA certificate authentication with exact command output and exit status
zero. The fixture rejects a missing agent identity, wrong certificate subject or principal, wrong
local CA pin, and a certificate from a CA the server does not trust, then repeats both valid paths
after each rejection. Only public keys and certificates leave the container; the private key stays
inside the disposable container and signatures come from its agent. `socat` bridges the container's
Unix agent socket to a loopback-published TCP port for the cross-platform test runner. This
verifies real OpenSSH agent messages and signing. `pwsh ./scripts/ssh-agent-unix-interop.ps1`
builds the same example with the pinned Rust toolchain in a disposable Linux container, runs it
through the public `connect_unix_agent` connector against the agent socket, and repeats the raw,
certificate, rejection, and healthy-reconnection cases. The container publishes no ports and
mounts the source read-only; its keys, socket, and build outputs are discarded. The fixture's
per-case process timeout bounds a stalled test; it does not add a cancellation deadline to the
production synchronous agent API. `pwsh ./scripts/ssh-agent-forwarded-interop.ps1` builds a
separate disposable Linux fixture with two loopback-only OpenSSH servers and a real source
`ssh-agent`. The public client requests forwarding on the first hop; a server-opened agent channel
is served through `ForwardedChannel::serve_agent` and `AgentServer`. The remote OpenSSH client
authenticates to the second server using the source agent's private key and checks exact command
output and exit zero. Disabled and denied per-signature policies reject authentication without
reaching the source agent's signing operation; a forwarded standard remove-all request receives
failure, and an identity query on the same channel plus subsequent valid connections prove the
source key remains usable. The source key and build artifacts stay inside the disposable
container; its repository mount is read-only, and it publishes no ports. Each case has a process
deadline; this does not establish a production cancellation bound for the synchronous agent API.
Windows named-pipe and Pageant connectors, live
gateway interoperability, and the wider OpenSSH matrix remain unverified.

`pwsh ./scripts/ssh-remote-forwarding-interop.ps1` runs the native public client against a
disposable Alpine OpenSSH server. It checks direct Unix-socket forwarding, remote TCP port
allocation, and remote Unix-socket forwarding with exact binary bytes and EOF in both directions.
It verifies server-opened channel metadata, cancellation refusing later connections, Unix-socket
listener reuse, missing-target rejection, and explicit server policy denying all three paths.
Session commands still return exact output and exit zero after forwarding failures. The fixture
publishes SSH only on loopback, retains its private host key inside the container, and removes
its container and sockets after the run. The SSH client does not require local Unix-socket
support; these are sockets on the remote Linux host. Other server and platform combinations
remain part of the broader matrix.

The `openssh_interop` example provides a disposable external-server smoke test when
one host trust pin and one authentication source are supplied. Set either
`SCOPLEN_OPENSSH_HOST_KEY` to the server's OpenSSH public-key line or
`SCOPLEN_OPENSSH_HOST_CA_KEY` to a CA public-key file, and select
`SCOPLEN_OPENSSH_PASSWORD`, `SCOPLEN_OPENSSH_RSA_KEY`,
`SCOPLEN_OPENSSH_ED25519_KEY`, `SCOPLEN_OPENSSH_P256_KEY`, or
`SCOPLEN_OPENSSH_ECDSA_KEY`. The last selects P-256, P-384, or P-521 from the imported key. The
key variables contain paths to unencrypted OpenSSH private keys and are mutually exclusive. The optional
`SCOPLEN_OPENSSH_RSA_HASH=256|512` selects the RSA-SHA2 signature algorithm (default 512).
Optional host, port, and username variables select the test server. It verifies the selected host
trust pin, authentication, exact command output, and exit status zero. Password,
both RSA-SHA2 variants, Ed25519, and ECDSA P-256/P-384/P-521 passed against a disposable Linux
OpenSSH container; wrong credentials and a wrong host key were rejected. The broader interoperability matrix remains
open.
`pwsh ./scripts/ssh-rsa-selection-interop.ps1` starts three disposable OpenSSH listeners with
`PubkeyAcceptedAlgorithms` constrained to RSA-SHA2-256, both RSA SHA-2 variants, and legacy
`ssh-rsa`. The `rsa_selection_interop` example verifies the advertised choice on each listener,
then completes RSA public-key authentication and an exact command on the two SHA-2 listeners.
The SHA-1-only case is discovery-only; it does not opt into SHA-1 authentication. The script
removes the disposable container and key file on exit.
`pwsh ./scripts/ssh-host-certificate-interop.ps1` starts disposable OpenSSH listeners for P-384
and P-521 raw host keys and host certificates, including listeners that offer both identities on
the same connection. For each curve it verifies exact authenticated command output and exit status
zero for a pinned raw key, a trusted valid certificate, and the default client's certificate
selection when both are offered. It rejects wrong CA, wrong principal, and expired certificates
with typed errors in both certificate-only and mixed cases, without falling back to the raw key,
then completes a new valid connection after each rejection. The script removes its container on
exit; this is one external OpenSSH fixture, not the complete host-key interoperability matrix.
`pwsh ./scripts/ssh-algorithm-interop.ps1` starts disposable OpenSSH listeners constrained to
Curve25519/AES-CTR, ML-KEM/ChaCha20, and one legacy-only set. The `algorithm_interop` example
verifies a pinned host key, authenticated command, exact output, and exit status for both modern
sets, handshake rejection by the default policy on the legacy set, a working command after per-Host
legacy opt-in, and rejection by another default Host. Pass
`-LegacyCipher 3des-cbc` to constrain the legacy listener to 3DES instead of AES-CBC.
The concrete engine includes 3DES support, but offers it only when that Host explicitly enables
`3des-cbc` through `HostAlgorithmPolicy::with_legacy`. CI checks both constrained ciphers. The
remaining algorithm and platform interoperability matrix is incomplete.
`HostAlgorithmPolicy::prefer_default` can promote one default algorithm for one Host without
removing other defaults or enabling legacy names. `pwsh ./scripts/ssh-modern-algorithm-interop.ps1`
uses 15 disposable, server-constrained OpenSSH listeners to exercise every modern KEX and cipher
implemented by the current concrete engine, both SHA-2 ETM MACs under AES-CTR, and `none` and
delayed `zlib@openssh.com` compression. Each case checks the host-key pin, password authentication,
64 KiB of exact binary command output, exit status zero, and the negotiated algorithms in OpenSSH
DEBUG3 logs in both directions. A wrong host-key pin fails, and a separate default Host continues
to negotiate `none` against a server that also offers delayed compression. `sntrup761x25519-sha512`
and `umac-128-etm@openssh.com` remain unsupported by the current concrete engine; this fixture
does not establish the full server or platform interoperability matrix.
`ssh-algorithm-interop.ps1` also runs `strict_kex_interop`: a pinned-key, password-authenticated OpenSSH command
succeeds, then a local relay inserts a valid `SSH_MSG_IGNORE` before and after the server's first
KEXINIT in separate connections. The strict client rejects both before host-key verification, while a server that does
not advertise strict KEX accepts the same packets. This covers one initial exchange and the
selected modern algorithms. The same script runs `rekey_interop` against three dedicated OpenSSH
listeners for each of AES256-CTR, ChaCha20-Poly1305, and AES256-GCM. DEBUG3 logs verify the exact
cipher and MAC negotiated in both directions. Client and server 32 KiB payload thresholds
separately trigger authenticated rekey;
a one GiB control must not rekey. Each case verifies 128 KiB of exact binary data echoed over one
session channel and a successful exit status. OpenSSH DEBUG3 logs must show post-authentication
KEXINIT and NEWKEYS in both directions, with the first KEXINIT received by the server for a
client-initiated exchange and sent by it for a server-initiated exchange. The control log must
contain neither message after authentication. The same logs must show strict KEX negotiated before
authentication and pair every initial and post-authentication NEWKEYS in both directions with a
nonzero send/read sequence-number reset. The exact authenticated echo after repeated exchanges
checks that the client and OpenSSH remain synchronized; the client's internal sequence counters
are not logged directly. Cipher-dependent OpenSSH defaults and the wider server, platform, and
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
`pwsh ./scripts/openssh-interop.ps1` provisions a disposable Alpine 3.21 OpenSSH 9.9p2 server;
`pwsh ./scripts/openssh-interop.ps1 -ServerVersion 10.6p1` runs the same checks against the
current OpenSSH 10.6p1 package from Alpine edge. Both paths check the installed package and SSH
banner before connecting, then run the direct SFTP/forwarding, ProxyCommand, SOCKS, and nested-jump
examples. The fixture also tests raw keys and user certificates with Ed25519, ECDSA
P-256/P-384/P-521, RSA-SHA2-256, and RSA-SHA2-512. A
software-generated authenticator fixture tests raw `sk-ssh-ed25519@openssh.com` and
`sk-ecdsa-sha2-nistp256@openssh.com` authentication, including rejection of signatures from the
wrong key, application, or session payload. The same fixture tests user certificates over both
security-key types, with full certificate binding, wrong subject or application, principal,
validity, CA pin, server CA trust, and KRL serial and key-ID rejection paths. Rejection checks cover
wrong passwords, unauthorized keys including P-384/P-521, wrong P-384/P-521 certificate subjects
and principals, wrong local CA pins, and locally valid certificates from a server-untrusted CA. A
separate trusted CA signs three Ed25519
certificates over one key: a KRL rejects one by serial and one by key ID, while an unrevoked
certificate and the same raw public key still authenticate and run the exact command with exit
status zero. OpenSSH enforces the KRL; the client does not load or parse it. The Linux CI workflow
runs the same script on each change; disposable keys and the container are removed afterward.
`UserCertificate::parse_and_validate` checks the embedded CA signature, certificate role,
principal, validity, and critical options. The caller still decides whether to trust that CA;
the interoperability example compares it with an explicitly pinned CA public key before calling
`authenticate_certificate`. OpenSSH enforces its configured `TrustedUserCAKeys` and KRL; the
client does not parse the KRL. This fixture does not establish physical-token, libfido2,
Windows WebAuthn, other server implementations or platforms, agent-backed certificate, or broader
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
`pwsh ./scripts/openssh-8-interop.ps1` runs the same public client example against the pinned
OpenSSH 8.8p1 package in a disposable Alpine 3.15 container. It checks the installed package and
SSH banner, then verifies password, Ed25519, and RSA-SHA2-256/512 authentication, exact command
output and exit status, and rejection of a wrong password, unauthorized Ed25519 and RSA keys, and
an unrelated host key. Docker publishes only a random loopback port; the container and temporary
test identities are removed afterward. This Windows-hosted Linux-server run adds the 8.x major
release but does not cover its SFTP, certificates, forwarding, other algorithms, OpenSSH for
Windows, or the current OpenSSH release.
For a user certificate, also set `SCOPLEN_OPENSSH_USER_CERT` to its OpenSSH certificate
file and `SCOPLEN_OPENSSH_USER_CA_KEY` to the pinned CA public-key file. The example checks the
certificate signature, principal, validity, critical options, and CA pin before sending it.
A disposable `linuxserver/openssh-server` container with `TrustedUserCAKeys` configured accepted
the certificate; a certificate from another CA was rejected by OpenSSH. The automated Alpine
fixture covers Ed25519, ECDSA P-256/P-384/P-521, and both RSA-SHA2 variants, plus server-side KRL
rejection of serial- and key-ID-revoked Ed25519 certificates. Other certificate revocation forms, algorithms,
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
The transfer uses 100,000 bytes cycling through every byte value. Four pipelined writes to a
read-only handle must return a remote status failure and leave that SFTP session unusable. A
fresh SFTP channel reads the unchanged file, and an independent SSH session still opens on the
same authenticated connection.
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
messages use deterministic CBOR. K-5/K-6 includes bounded gateway-ticket issuance JSON
messages, an ordered edge-address response, and the `gateway.invalid_request` problem code. The
bounded D-88 user-certificate issuance request codec accepts exactly one ordered Host or HostGroup
selector, a canonical raw SSH public key, a preserved SSH username, and an integer TTL. Its
`certificate.invalid_request` 400/413 problem vectors are published. The D-90 response codec
accepts a bounded 201 certificate Resource with exact ETag and no-cache headers, a canonical
OpenSSH user-certificate line, and a separate request-subject comparison. Parsing does not verify
the certificate signature, CA trust, current validity, requested scope, policy, or revocation;
the SSH consumer must check these before use. Issuance, authorization, and durable idempotency
belong to the server.
The D-99 current-account `AccountProfile` codec accepts a complete 4 KiB Resource response with
required `data.email` as a preserved bounded string or JSON null. It rejects missing email,
duplicate names at every depth, invalid Resource metadata, and mismatched ETag or cache headers.
The Cedar `Account.email` attribute is optional; policies reading it must use a `has` guard.
These contracts do not authenticate the account or verify an address. The production GET route and
email enrollment remain server work.

The D-101 Personal invitation and first-device enrollment codecs bound complete JSON bodies,
reject duplicate and unknown request fields, enforce canonical base64url and revision-one
artifact identities, and redact secret-bearing diagnostics. HTTP helpers reject prohibited
headers and a foreign browser Origin. OpenAPI, generated TypeScript, public vectors, and parser
fuzz seeds describe the same messages. A parsed request does not verify signatures or invitation
state; the server must authenticate the issuing operator and atomically create the account,
device, key bundle, and Personal vault while consuming the invitation.

`scoplen-crypto` also signs and statelessly verifies D-100 enrolled-device access tokens as bounded
Ed25519 compact JWS values. The `spl-device-access+jwt` profile uses its own trusted issuer and
configured keyring, an exact 600-second lifetime, complete ordered organization and SSO snapshots,
bounded scopes, and a thumbprint computed from the verified device signing public key at issuance.
Public signed and rejection vectors are in `vectors/device-access-token.json`. Consumers still own
current-state checks, DPoP proof and replay verification, and route authorization; the K-3 JSON
response continues to treat the token as opaque.

The gateway-ticket issuance codecs validate syntax and size; their ticket field remains opaque.
`scoplen-crypto` signs and statelessly verifies the D-96 dedicated Ed25519 gateway-ticket profile with a trusted
issuer and ticket-only keyring, exact 60-second validity, UUIDv7 claims, and DPoP-key and SSH-key
hashes. It checks fallible signer output and redacts ticket diagnostics. Consumers still own
authenticated issuance, authorization, SSH-key use, and atomic single-use consumption. The D-97
raw-TLS proof uses a separate `spl-gw-proof+jwt` ES256 profile, signs the exact ticket hash, and
requires the verified ticket's device-key thumbprint and 60-second window. The shared verifier
checks ticket and proof together; edge adoption, current policy, and replay storage remain
consumer work. K-6 also includes
the bounded gateway client-hello frame (`ticket` and `dpop_proof`) with a published vector and
failure-path coverage. OpenAPI
resources now have an authored OpenAPI 3.1 document at `crates/scoplen-api/openapi/v1.yaml`,
generated Rust envelope/query types, and the local `@scoplen/api` TypeScript package surface.
The control-plane and shared `ProblemDetails` Rust paths use the same validated eight-field
JSON/CBOR error type. The OpenAPI schema and generated TypeScript declaration require `type`,
`title`, `status`, `detail`, `instance`, `code`, `changed`, and `retryable`; decoders accept unknown
response fields and syntactically valid future error codes.

The six successful K-4 key-management mutation responses expose request/path-aware validators:
vault creation, epoch publication and retirement, member addition and removal, and account-key
PUT. Callers validate the echoed id, epoch, account, or revision against the original request or
typed path value before applying local metadata. These checks do not establish authorization,
cryptographic validity, or durable server mutation; response CBOR and additive extensions are
unchanged.

`SyncAckResponse::validate_for_request` checks that a decoded acknowledgement returns at least
the cursor sent. A higher stored maximum is valid when another acknowledgement has already
advanced it. Call this before applying acknowledgement metadata locally; the check does not
establish the current vault sequence or server persistence. Existing CBOR bytes remain valid.

`SyncChangesQuery::from_query` rejects raw change-feed and snapshot queries longer than 37 bytes
before parsing; canonical `after` and `limit` values fit within that bound in either order.
`SyncAckRequest::from_cbor` rejects complete request bodies longer than the 17-byte maximum for
the exact `{cursor: uint}` map before CBOR parsing. These checks retain the existing valid wire
shapes and return the shared invalid-input error; HTTP consumers must bound collection as well.

The K-4 session request codec caps its complete CBOR body at 4,096 bytes. Session responses use a
4 MiB default complete-body budget; `SyncSessionResponse` also provides
`validate_with_body_limit`, `to_cbor_with_body_limit`, and `from_cbor_with_body_limit` for a positive
caller-selected budget. Encoders preflight exact bytes before copying version strings or vaults;
decoders reject over-budget input, including ignored extensions, before CBOR parsing. Choose the
response budget from local policy, not the advertised vault quota. A rejected response must not
replace the consumer's current vault list, and HTTP consumers must also bound decompressed bytes
while collecting the response.

Change-feed, snapshot, and version-history responses accept an explicit `SyncReadLimits` profile
through their `*_with_limits` methods, including query/path-aware validators. The independent
default read budgets are 260 KiB per opaque payload and 266,295,039 bytes for the complete CBOR
body. Select positive budgets from trusted local policy; retained payloads may exceed the current
write limit. Decoders reject over-budget complete input, including ignored extensions, before CBOR
parsing. Encoders check exact encoded size before copying payloads. HTTP consumers must also bound
decompressed bytes while collecting the response; a codec check alone cannot limit that allocation.

Atomic write exchanges accept an explicit `SyncWriteLimits` profile in their `*_with_limits`
methods. Select positive envelope, object-count, and encoded batch-byte budgets from trusted
configuration or acceptable session values; an announcement does not authorize an allocation.
Requests, assignments, conflicts, and their request-aware validators use the same profile.
Defaults remain 260 KiB, 500 objects, and 4 MiB; the complete conflict cap stays fixed at 128 MiB.
The request encoder checks its exact size before copying payloads, and decoders check complete
body limits before CBOR parsing. `vectors/sync-write-limits.json` publishes exact CBOR hex and
explicit profiles with `accept`/`reject` outcomes. Tests also round-trip 501-entry exchanges and
requests above 4 MiB. Storage/router adoption remains separate.

The K-3 authentication boundary now validates strict, bounded challenge and signed-device JSON
requests, canonical HTTPS origins, and the exact domain-separated P-256 signature input. The
shared `validate_server_origin` entrypoint applies the same canonical-origin rules to trusted
deployment configuration without constructing a challenge or accepting request headers. The
native refresh body requires one opaque token (at most 2,048 UTF-8 bytes); the browser body is
exactly `{}` with its HttpOnly refresh cookie supplied by the browser. Both JSON bodies are capped
at 4,096 encoded bytes. The browser response omits and rejects any `refresh_token` field while
retaining unrelated response extensions. OpenAPI and generated TypeScript types describe all three
authentication paths, including the DPoP-only refresh operation and distinct browser response.
Callers pass the returned bytes to the fallible K-2 `DeviceSigner::sign` boundary and propagate
signer failures, including hardware-device failures. `scoplen-crypto` also constructs and verifies
bounded ES256 DPoP proofs through `DpopTarget`, `DpopToken`, and `DpopProof`. Targets combine a
trusted canonical HTTPS origin with the router's canonical absolute path; protected proofs bind an
ASCII access token with `ath`, while refresh proofs omit it. Verification returns a JWK thumbprint,
proof identifier, creation time, and last accepted second. It checks the signature, request,
key/token binding, nonce, and 60-second past/future window, but does not authorize or prevent replay.
Consumers must atomically claim `(jkt, jti)` across instances through the inclusive acceptance
boundary before authorizing or rotating credentials. The published RFC 9449 vector exercises a
signature and token hash from an independent source.
Challenge storage, credential verification, and token issuance are server responsibilities; this
library does not implement a production authentication service. Origin and cookie handling,
atomic refresh rotation, and reuse detection remain server responsibilities.
`PersonalEnrollmentContext` constructs D-101's exact first-device signature input
from the trusted HTTPS origin, decoded invitation-token digest, UUIDv7 account/vault
ids, public account keys, and hashes of the exact uploaded artifacts. It signs through
the fallible `DeviceSigner` and verifies with the certified P-256 public key. Diagnostics
redact the input artifacts and token digest. Public signature-input and rejection vectors
are in `vectors/personal-enrollment-proof.json`. The consumer still verifies the K-4
bundle and K-2 certificate signatures, uses the bounded enrollment codec, and atomically redeems
the invitation; possession-proof verification alone does not enroll or authenticate a device.
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
remaining K-4 message vectors are in `vectors/api-auth.json`, `vectors/api-dpop.json`, `vectors/api-problem.json`,
`vectors/sync-session.json`, `vectors/sync-session-limits.json`, `vectors/sync-changes.json`, `vectors/sync-messages.json`,
`vectors/sync-read-limits.json`,
`vectors/sync-notifications.json`, `vectors/sync-notification-auth.json`, `vectors/sync-keys.json`,
`vectors/sync-keys-failures.json`,
`vectors/sync-vaults.json`, `vectors/sync-vault-keys.json`, `vectors/sync-vault-epochs.json`,
`vectors/sync-vault-members.json`, `vectors/gateway.json`, `vectors/gateway-ticket-issuance.json`,
`vectors/certificate-issuance-request.json`, `vectors/certificate-issuance-response.json`, and
`vectors/account-profile.json`.
The shared loader is usable by both workstreams.

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

The tracked `fuzz/corpus/<target>/seed-*` files provide synthetic valid and malformed
inputs for all ten parser targets. Valid model and certificate inputs come from the published
known-answer vectors in `vectors/baseline.json` and `vectors/crypto.json`; SSH, SFTP, and agent
frames follow the public codec tests. The `sync_notification` target checks context, credentials,
acknowledgements, and events through their public codecs and requires accepted messages to
survive a canonical encode/decode round trip. Its seeds include the published notification
vectors, truncated credentials, a zero sequence, and contexts exactly at and above the 16 KiB
bound. `sync_control` and `sync_data` select each remaining public K-4 request, response, or query
parser by a one-byte prefix, including the ordinary K-4 CBOR problem body. They check accepted
values through the public encoder and decoder,
including canonical encoding stability after ignored response extensions. Explicit low and raised
resource profiles exercise the bounded session, read, write, and version-history entrypoints.
Their synthetic seeds derive from published K-4 vectors and include malformed key updates,
truncated CBOR, and the exact and exceeded session, query, and acknowledgement input bounds.
The Linux change check replays every target's corpus, and
the daily five-minute fuzz run starts from the same seeds. On Linux, replay one target with nightly
Rust and `cargo-fuzz` using `cargo +nightly fuzz run sftp_decoder fuzz/corpus/sftp_decoder -- -runs=0`.
The `crypto_decoders` target additionally parses and statelessly verifies DPoP against fixed RFC
9449 context and signed gateway tickets and D-100 device access tokens against separate fixed
synthetic keyrings. Tracked seeds include the RFC proof, published gateway and access tokens,
signed wrong-purpose and wrong-audience access tokens, signed duplicate header and nested claims,
malformed signatures, truncation, a proof one byte over the 8 KiB bound, and access tokens at and
one byte over their 4 KiB bound.
The `api_json` target exercises all seven authentication/refresh message types, both gateway-ticket
issuance messages, the certificate issuance request and response, and the current-account profile
through public decoders. Accepted messages must preserve their values across canonical encoding,
and a second encode must preserve those bytes. Gateway request checks also
enforce rejection of an idempotency header. Seeds include the published JSON vectors, duplicate
fields, forbidden browser refresh tokens, ambiguous edge hosts, nested response extensions,
invalid certificate selectors and duplicate fields, signed certificate response Resource vectors,
current-account email/null profiles and failures, duplicate nested response fields, truncation,
and complete bodies at and one byte above request and response limits. This checks
message syntax; token authentication, ticket signatures, and authorization remain consumer work.
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
