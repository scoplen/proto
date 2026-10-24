# Shared repository architecture

The `proto` repository implements contracts shared by the client and server workstreams. It has
no runtime dependency on either consumer.

| Crate | Contract or role |
| --- | --- |
| `scoplen-ssh` | K-7 protocol core |
| `scoplen-model` | K-1 object model |
| `scoplen-crypto` | K-2 cryptographic formats |
| `scoplen-api` | K-3 through K-6 wire contracts |
| `scoplen-test-vectors` | Known-answer vector envelope and loader |

The K-1 crate owns strict deterministic CBOR, UUIDv7/HLC values, object envelopes, typed field
validation, tombstones, and pure merge helpers. Later gates add contract behavior in the order
defined by `scoplen-docs/17-implementation-roadmap.md`; no consumer may define a second copy of a
wire format or cryptographic construction.

The K-2 implementation uses HPKE 0.14 and P-256 0.14 with the existing RFC 9180
P-256/X25519, HKDF-SHA-256 and ChaCha20-Poly1305 suites. HPKE's features are explicit;
its optional post-quantum suites are not enabled. The workspace and fuzz locks pin
`crypto-bigint` to 0.7.6 and `ctutils` to 0.4.5 after
[RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).
Dependency upgrades must preserve the published K-2 known answers, including fixed-width
ECDSA signatures and existing HPKE ciphertexts. Consumers resolve their own locks and must
update affected transitive versions when upgrading their pinned shared revision.

The K-7 crate owns the client algorithm preference lists from `10-protocol-core.md` §3.
`HostAlgorithmPolicy::with_legacy` validates an explicit list for one Host and appends accepted
legacy names after modern defaults. Host certificate algorithms precede raw host keys (D-42).
`prefer_default` promotes one same-category default name to the front for one Host while retaining
all other defaults in order and leaving any enabled legacy names at the tail. The default policy
is unchanged; the concrete adapter offers only the engine-supported subset.
`TransportOffer` turns those lists into role-specific KEXINIT offers, selects the first local
preference present in each peer list, and enables RFC 8308 and strict-KEX markers only when both
roles advertise them. `StrictKeyExchange` enforces the initial KEXINIT-first rule, KEX-family
message admission, one-message limits, sequence-wrap refusal, and sequence-number reset after
NEWKEYS. `TcpTransport` provides a bounded direct TCP byte stream with capped resolution results,
RFC 8305 style staggered Happy Eyeballs attempts, one total connect timeout, `TCP_NODELAY`, typed
read/write failures, and `Read`/`Write` adapters. Attempts run in one bounded runtime and are
cancelled and joined before return, so a successful address is not held up by a slower candidate.
It intentionally stops before SSH version exchange, key exchange, authentication, or channel
scheduling. The engine-independent authentication boundary supplies Ed25519, ECDSA
P-256/P-384/P-521, and RSA/SHA-2 `Signer` adapters, FIDO2 `SecurityKeyProvider` adapters,
RFC 4252 publickey probes and signed requests,
bounded OpenSSH certificate parsing and validation, and a host-key trust callback that is called
only after validation. Security-key requests preserve the OpenSSH application, user-presence and
user-verification flags, and authenticator counter while rejecting malformed or unbounded input.
The agent boundary provides bounded request-identities, signing, identity management, smart-card,
lock, unlock, and `SSH_AGENTC_EXTENSION` request/response codecs, transport-neutral client calls,
and server dispatch that maps key-store errors to opaque failures. `FramedAgentChannel` applies
bounded read/write framing over a blocking stream, with platform constructors for Unix-domain
sockets and Windows named pipes. The forwarded-agent adapter reassembles fragmented and multi-frame
channel data, applies the fail-closed per-profile authorizer, and bounds response count and
channel-data fragments. `AuthAgentChannel` composes that adapter with the bounded RFC 4254
`auth-agent@openssh.com` open, data, EOF, and close lifecycle; it validates channel numbers and
peer packet limits and reports clean versus truncated close outcomes. Pageant named-pipe
compatibility is available on Windows through the same bounded framing; legacy WM_COPYDATA discovery
remains open. The concrete `russh` client adapter now owns TCP and caller-supplied stream
handshakes, validates host keys and certificates before the trust callback, supports password
authentication, and exposes opaque session and `direct-tcpip` channels with PTY, shell, exec,
window-change, bounded data, EOF, close, and peer-event operations. `ClientChannelStream` adapts a
forwarding channel to the async stream boundary, and
`ClientConnection::connect_via_direct_tcpip` composes a target handshake through an authenticated
jump host; repeating the operation supports arbitrary chain depth while callers retain each
parent connection. A shared connection opens independent session and forwarding channels up to
its configured cap. Failed opens and dropped channel streams release their channel slot. Outbound
SOCKS5 and HTTP CONNECT transports compose bounded proxy handshakes over `Transport`; SOCKS5 RFC
1929 and HTTP CONNECT Basic authentication accept bounded zeroized credentials;
`ProxyCommandTransport` composes a
bounded direct child process over stdin/stdout without a shell and reaps it on shutdown or drop.
`ClientConnection::connect_via_socks5` and `connect_via_http_connect` run those bounded proxy
handshakes on blocking workers, upgrade the resulting nonblocking sockets to the async `russh`
stream boundary, and preserve typed proxy rejection and timeout errors. `GatewayTransport` writes
and flushes one validated K-6 client-hello frame over an established byte transport before handing
the stream to the SSH engine, including partial-write and typed failure handling. TLS/ALPN
negotiation and interoperability with other SSH engines remain open. `AsyncGatewayTransport` and
`ClientConnection::connect_via_gateway_stream` compose the same one-shot frame over an already
negotiated async TLS/ALPN stream before the SSH version exchange. The concrete adapter accepts
server-opened `auth-agent@openssh.com` channels through `ForwardedChannelKind::Agent` only while
a live session on that connection has explicitly requested forwarding. Peer and local close revoke
the opt-in even when the caller does not consume the peer event; EOF retains it. Callers can serve
the channel with `ForwardedChannel::serve_agent`, which rechecks authorization, reassembles channel
fragments, refuses every request under a disabled policy, and bounds every response. In-process
russh tests cover unsolicited opens and revocation; a disposable OpenSSH fixture covers forwarded
signing, disabled and denied policies, and management-request refusal. Pageant interoperability
and broader channel scheduling remain unverified.
An agent-channel open does not identify its originating session. Admission is therefore scoped
to the connection while at least one live session has opted in; the caller still selects the
appropriate profile's serving policy. Under an ambiguous peer close during session opening,
the pending session refuses a later opt-in.
Native Pageant interoperability remains unverified because hosted CI has no Pageant installation.
The agent server can consume
multiple bounded frames from a blocking stream through clean peer close while applying the same
malformed and oversized-frame checks.
The supported management surface includes exact-key removal, smart-card provider load and removal,
remove-all, lock, and unlock; private-key add-identity remains intentionally outside this opaque
boundary until its algorithm-specific fields have a dedicated contract.
Agent message debug output reports only bounded lengths and non-sensitive metadata, so signing
payloads and lock credentials are not emitted through ordinary diagnostics.
Forwarded agent serving uses an explicit per-profile policy that is disabled by default and invokes
an authorizer for each signature before the key store; management and extension requests are
rejected on a forwarded channel. The `AuthAgentChannel` boundary keeps that policy in force while
leaving channel allocation, window updates, and engine scheduling to the concrete SSH engine.
The channel boundary exposes bounded RFC 4254 channel-open, data, lifecycle, session-request, and
global forwarding codecs, including direct and forwarded TCP, Unix streamlocal, and agent-forwarding
channel types. It validates exact message consumption, field limits, request names, booleans, signal
names, and forwarding failure reasons; the concrete engine and connection multiplexing remain
separate outcomes.
The authentication boundary also encodes `none`, `password` and password-change, and
keyboard-interactive exchanges with bounded context, prompt, and response fields; password and
interactive response bytes are held in zeroizing secret containers. `EcdsaSshSigner` accepts only
OpenSSH ECDSA private keys and selects NIST P-256, P-384, or P-521 from the key; the existing
`P256SshSigner` still wraps Scoplen's P-256 key type. `RsaSshSigner` accepts only RSA
private keys and binds the selected `rsa-sha2-256` or `rsa-sha2-512` hash to the signature wrapper;
raw `ssh-rsa` SHA-1 authentication is rejected. The SFTP boundary provides bounded v3 negotiation,
core open/read/write/close/stat packets, directory and path operations (opendir, readdir, remove,
mkdir, rmdir, and realpath), metadata and symbolic-link operations (setstat, fsetstat, readlink,
and symlink), binary-safe handles and extension data, attributes, status, and directory-entry
responses, request-id correlation for bounded pipelining, and the OpenSSH `limits@openssh.com`,
`posix-rename@openssh.com`, `statvfs@openssh.com`, `fstatvfs@openssh.com`, `hardlink@openssh.com`,
`fsync@openssh.com`, `lsetstat@openssh.com`, `expand-path@openssh.com`, and `copy-data`
requests and responses. `SftpChannel` composes the bounded v3 handshake and packet framing over
an accepted SSH `session` channel; `SftpSession` layers bounded pipelining, request correlation,
resume-by-offset uploads/downloads, and progress callbacks on that channel, while the
interoperability matrix remains open.
