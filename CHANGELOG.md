# Changelog

All notable changes to the `proto` repository will be recorded here.

## Unreleased

- Added D-126's Organization-bound Cedar authorizer with immutable guards, current Membership
  roles, all seven inventory entity types and independent `view_inventory`. Canonical graph,
  identity, owner, reference, device and action-context checks and every evaluation error fail
  closed even with a permissive custom policy. Linked custom policies survive id collisions.
  Removed global role groups, blanket Member permits and D-125's retired Personal invitation
  Cedar action. This breaks the pre-Stable K-5 schema/context and role representation; legacy
  Operator scope encoding is unchanged. Public role and failure vectors cover the boundary;
  current-state storage, transactional checks and consumer delivery remain separate work.

- Add D-124 current Operator-family logout codecs, explicit authenticated intrinsic operation,
  OpenAPI/TypeScript, independent vectors, parser bounds and a scripted reference peer. The
  fixed confirmation never supplies general authorization. Replace the pre-Stable Operator
  `required_scope` method with typed `requirement`; issued scopes and JWT bytes stay unchanged.
  Logout's explicit fresh-proof recovery after an unknown commit leaves existing refresh and
  login recovery unchanged. Production family revocation and console adoption remain consumer work.

- Added mixed OpenSSH 9.9p2/Dropbear 2024.86 Jump acceptance at depths one through
  three with either ingress implementation. Independent hop identities, per-position
  trust/password rejection, closed targets, exact commands and binary/EOF output,
  canceled nested handshakes and complete reverse teardown exercise existing public
  APIs. The fixed-version fixture runs in CI without changing wire formats or dependencies.

- Extend the pinned Dropbear fixture with direct TCP and SOCKS4a/5 forwarding,
  concurrent binary transfers with an EOF-only trailer, disabled-forwarding and
  closed-target refusal, subsequent session commands, and active-listener cancellation.
  Existing password, SFTP and wrong-credential/host-key controls remain required;
  fixture profiles keep distinct strict OpenSSH and Dropbear banner checks. Banner
  checks tolerate a coalesced binary KEX packet, and cancellation still requires
  bounded final EOF after already queued SSH bytes.

- Take zeroizing ownership of every keyboard-interactive response before validating count or
  size, so rejected input buffers are also cleared on drop. Public errors and bounds are unchanged.

- Registered D-123 Credential kind 8 for explicit SSH keyboard-interactive login, requiring
  none binding and no saved secret, device entry, public key, provider or certificate scope.
  Cleared-field markers and unknown fields retain ordinary model behavior. This registry
  extension breaks pre-Stable readers that reject the new kind; it changes no object envelope
  or SSH message. Independent canonical vectors, parser seeds and public object/conversion tests cover the
  model boundary. Desktop prompt handling and authentication remain consumer responsibilities.

- Implemented D-121 by replacing the synchronous keyboard-interactive callback with an async responder
  accepting an owned checked request and returning `KeyboardInteractiveResponse`. This is a
  pre-Stable source and behavior break, with no synchronous wrapper or wire change. Complete
  peer rejection permits another factor on the same connection; interruption after dispatch
  closes the engine and transport and locally refuses later authentication, channels and
  forwarding. Callers own timeout/cancellation and reconnect after interruption. Added public
  encrypted-peer scheduling/cancellation tests and a pinned OpenSSH/PAM acceptance fixture.

- Added D-116's object-safe async signing hook for concrete public-key and certificate
  authentication. The built-in SSH agent signer now moves its complete synchronous exchange to
  Tokio's blocking pool, preserving channel serialization and fail-closed response ordering after
  cancellation. Existing signers keep the synchronous default; this adds no agent I/O deadline or
  asynchronous connection setup and changes no wire format.

- Fixed notification route lookup to recognize D-75's HTTP/2 extended `CONNECT` alongside the
  classic `GET`, both requiring exactly `sync:read`. Public route vectors and regressions reject
  other methods, path aliases and query-bearing templates. DPoP public tests retain the actual
  opening method and HTTPS target and reject proof substitution between handshakes. The wire
  format and operation's canonical `GET` method are unchanged; production transport, replay,
  current-state and subscription authorization remain consumer work.

- Added D-114's strict public pairing link and secret-bearing QRv2, canonical authenticated
  new-device/handoff codecs and confirmed-channel frame helpers. Account roots, certificates,
  key projection anchors and exact new-device acceptance/approval inputs now share one crypto
  boundary. QRv1 is removed without a compatibility path. QR and plaintext encodings use
  zeroizing containers with redacted debug output. Public independent Node-produced vectors,
  role/context/substitution/limit regressions and parser seeds cover these exports; durable
  single-attempt state, key opening, admission and client/server integration remain consumer work.

- Added D-113's complete account device-statement snapshot codec with canonical base64url,
  strict raw-byte ordering, recursive duplicate-name rejection, per-artifact, aggregate and
  complete-body bounds, cache-header validation and input-free GET validation. Registered
  `AccountDevicesRead` under the unchanged `account:read` ceiling and replaced the provisional
  OpenAPI Page with the precise snapshot, generated TypeScript, public vectors and parser seeds.
  Account binding, K-2 signature verification, complete-set trust and current authorization
  remain consumer responsibilities; K-4 codecs are unchanged.

- Raised the Tokio minimum and updated workspace and fuzz locks to 1.53.3 for
  RUSTSEC-2026-0386, addressing Unix `AsyncFd` I/O safety.

- Updated workspace and fuzz `ctutils` locks to 0.4.4 for RUSTSEC-2026-0385,
  fixing non-constant-time mask generation and integer comparison.

- Added public DPoP presented-key verification for initial Operator ceremonies. It shares the
  existing signature, exact target, token hash, time, and nonce checks and returns the verified
  JWK thumbprint without requiring an existing binding. Trusted identity, credential binding,
  authorization, and durable replay claims remain consumer responsibilities; existing
  expected-thumbprint verification and wire formats are unchanged.
- Fixed K-1 reference discovery for Host default profiles and live groups, AccessProfile
  forwards, HostGroup parents, and Workspace session maps. Cleared memberships, TrustRecord
  account/device provenance, and unknown fields no longer create false object dependencies.
  Public round-trip regressions also retain Route and Forward reference behavior.
- Added D-111's separate Operator browser access-token signing and verification boundary,
  family binding, independent trust type, public signed/rejection vectors and parser seeds.
  Device profiles remain separate; passkey verification and current-state authorization are
  consumer responsibilities.
- Added D-111 bounded independent Operator ceremony codecs, discoverable ES256 options,
  a separate Operator route/scope registry, four OpenAPI POSTs and Operator JWKS discovery,
  generated TypeScript, public vectors and parser seeds. Cedar distinguishes current active
  Operators from Account roles and limits deployment invitations to `Deployment::"self"`.
  Wire decoding leaves embedded WebAuthn parsing and ceremony consumption to the server.
- Updated the shared UUID dependency to 1.28.0 for compatibility with the maintained
  WebAuthn verifier's UUID requirement; canonical UUIDv7 identity bytes are unchanged.
- Updated the workspace and fuzz TLS certificate verifier locks to `rustls-webpki` 0.103.16 for
  RUSTSEC-2026-0382, rejecting certificate paths through the distrusted intermediates.
- Added D-110 public JSON and independently encoded CBOR problem regressions and sync parser
  seeds for known rollback and uncertain write or acknowledgement commits. Both retain
  `sync.storage_unavailable` and the existing wire shape, while preserving distinct mutation
  and retry flags. Transaction classification and recovery remain consumer responsibilities.
- Added D-109 retained-device invitation re-signing regressions and an independently encoded
  replacement-token vector. Both original and replacement proofs reject every changed signed
  field; the signing contract is unchanged and recovery decisions remain consumer work.

- Added D-107's exact initial enrolled-device scope ceiling and typed 16-operation route
  registry, with public scope/mapping vectors and signed-token compatibility checks. OpenAPI
  records issuance, non-expanding refresh, and current-account scope requirements. Unknown
  valid JWT scopes remain accepted; current-state and complete route authorization remain
  consumer responsibilities.
- Added D-106's independent authentication admission headers and bounded public-only Ed25519
  JWKS codec, with canonical key ordering, recursive duplicate-name rejection, and public-key
  field checks. OpenAPI and generated TypeScript include root JWKS discovery, authentication
  no-store and rate responses, known rollback versus uncertain commit, and absolute refresh
  family expiry. Public vectors and API parser seeds cover success and failure paths; durable
  authentication and trusted key distribution remain consumer work.
- Added an isolated Windows CI fixture for the native OpenSSH agent named-pipe connector. It
  verifies raw-key authentication to a disposable SSH server, exact command output and exit,
  identity, host-key, and pipe rejections, and precise cleanup of its generated test key.
- Expanded the pinned OpenSSH 8.8p1 fixture through the existing public SSH examples: Ed25519
  user certificates with principal, CA, and KRL rejection controls; mixed raw and certified host
  identity with CA, principal, and expiry rejection; direct TCP forwarding; and nested jumps with
  wrong-host-pin rejection and parent connection reuse.
- Extended the pinned OpenSSH 8.8p1 fixture with the existing SFTP v3 workflow, including exact
  streaming-upload length and resume offset, directory and metadata operations, advertised
  extensions, and explicit `copy-data` unsupported response. CI runs this shared example against
  the 8.8 server while newer fixtures retain their full extension checks.
- Added D-102 Route proxy-username field validation and canonical clear/merge vectors. HTTP CONNECT
  now rejects non-ASCII Basic credentials and usernames containing `:` before opening a proxy
  socket, while SOCKS5 retains its byte-string credential interface. Public proxy transport and
  SSH-route tests cover authenticated success, rejection, and invalid-credential preflight. Basic
  encoding also handles a two-byte final Base64 group without aborting the connection task.
- Added bounded async-reader SFTP uploads with explicit byte count and remote resume offset.
  Slice and stream uploads share contiguous progress and pipeline accounting, including
  out-of-order acknowledgements. Source failures isolate the SFTP channel; the OpenSSH
  interoperability fixture exercises streaming resume with exact byte comparison.
- Covered D-77 cancellation during a blocked outbound SFTP write through an authenticated SSH
  channel whose peer stops replenishing its write window. The canceled session releases its
  request slot; independent and replacement channels still work on the parent connection.
  Peer-induced outbound write I/O error isolation remains unverified.
- Added D-101 Personal invitation and enrollment JSON codecs, HTTP header/origin checks,
  artifact identity validation, OpenAPI and generated TypeScript, public vectors and parser
  corpus coverage. Structural decoding remains separate from signature verification,
  operator authorization, and atomic invitation redemption.
- Exposed the existing shared canonical HTTPS origin validator for deployment configuration,
  using the same rules as device authentication, DPoP, enrollment, and token contexts.
- Added D-101 Personal enrollment possession-signature contexts with exact origin, token-digest,
  identity, key, and artifact binding, fallible device signing, public verification, redacted
  diagnostics, and independent signature-input/rejection vectors. Enrollment transactions remain
  a consumer responsibility.
- Extended the cryptographic parser fuzz target to verify D-100 device access tokens through
  their public API, with signed valid and rejection seeds and exact encoded-size boundaries.
- Added D-100's dedicated enrolled-device Ed25519 access-token signer and stateless verifier,
  bounded claims and keyring, complete membership and scope checks, redacted diagnostics, and
  public signed/rejection vectors. DPoP replay, current-state and route authorization remain
  consumer checks.
- Extended the disposable OpenSSH 9.9p2 authentication, certificate, SFTP, and route fixture to
  current OpenSSH 10.6p1 with an exact package and SSH banner check. CI runs both server versions
  through the same positive and rejection paths; wider platform and implementation coverage remains open.
- Added a pinned OpenSSH 8.8p1 Linux-server fixture using the public SSH client example. The
  Windows-hosted Docker run verifies installed version and banner, password, Ed25519 and both
  RSA-SHA2 hashes, exact command output and exit status, plus credential and host-pin rejection.
  The remaining release, platform, certificate, SFTP, and forwarding matrix stays open.
- Added continuous parser fuzz coverage for K-4 sync requests, responses, queries, and selected
  resource limits beyond notifications. Two public-codec targets replay vector-derived positive,
  malformed, truncated, and input-boundary seeds in Linux change checks and scheduled fuzzing.
- Reject unsolicited forwarded-agent channels until a live session opts in, revoke permission on
  locally failed or canceled sends and session close, and reject all forwarded agent requests without
  touching the key store when the forwarding policy is disabled.
- Broadened external OpenSSH SFTP transfers to all byte values and verified that a rejected
  four-request write pipeline invalidates only its SFTP session. A fresh channel reads the
  unchanged file and an independent SSH session still opens on the same connection.
- Extended external OpenSSH repeated-rekey verification to ChaCha20-Poly1305 and AES256-GCM
  alongside AES256-CTR, with exact bidirectional cipher/MAC logs, client/server initiation,
  high-limit controls, binary echo, and strict NEWKEYS sequence resets. Explicit limits do not
  establish cipher-dependent OpenSSH defaults.
- Bound raw K-4 change-feed and snapshot queries to 37 bytes and acknowledgement requests to
  17 complete CBOR bytes before parsing. Exact-boundary and rejection vectors and public tests
  preserve all valid query and CBOR bytes.
- Added an automated external OpenSSH forwarding fixture for direct Unix sockets, remote TCP,
  and remote Unix sockets. Public client checks cover exact binary data, half-close, forwarded
  metadata, cancellation and listener reuse, denied and missing targets, and parent session
  reuse after failure; the fixture runs in the OpenSSH CI job.
- Added D-99's bounded current-account Resource codec, exact OpenAPI/TypeScript profile,
  portable email/null/failure/budget vectors, and recursive duplicate-name rejection. Cedar
  `Account.email` is optional, with strict guarded-policy validation and authorization tests
  for present and absent addresses. The production GET route and email verification remain
  server work.
- Corrected D-98 strict-KEX helper admission: each direction resumes ordinary transport traffic
  after its initial NEWKEYS, later rekeys allow interleaved ordinary packets, and sequence resets
  remain per-direction after every strict NEWKEYS. KEX-control boundaries, family, and repetition
  checks remain enforced; non-strict sequence numbers continue without reset. Public regressions
  and a rekey fuzz seed cover the corrected helper boundary, not the encrypted engine.
- Added D-97 raw-TLS gateway possession proofs in `scoplen-crypto`, with dedicated ES256 type,
  exact-ticket hash and device-key binding, combined trusted-ticket verification, strict lifetime,
  signed vector, failure-path tests, and fuzz seeds. The `dpop_proof` CBOR carriage is unchanged;
  authorization, edge adoption, and atomic ticket replay claims remain consumer work.
- Added a disposable external OpenSSH forwarded-agent fixture with a real second-hop public-key
  signature, exact command output, fail-closed disabled and denied policy checks, blocked
  remove-all management request, and valid reconnect controls. The source private key and build
  artifacts remain inside the container; Windows agent transports and the broader matrix remain
  unverified.
- Added D-96 bounded Ed25519 gateway-ticket signing and stateless verification in
  `scoplen-crypto`: dedicated trusted issuer/keyring, strict JOSE and claims, verified signer
  output, exact 60-second validity, public signed vector and failure-path tests, and decoder fuzz
  seeds. Issuance authorization, raw-TLS proof binding, SSH-key use, and atomic replay claims remain
  consumer work.
- Verified strict-KEX rekey against disposable OpenSSH in both initiation directions. DEBUG3
  evidence now requires strict negotiation before authentication and a nonzero send/read sequence
  reset after every initial and later NEWKEYS; repeated rekeys preserve exact channel bytes and
  successful remote exit. The no-rekey control remains unchanged.
- Bounded the complete K-4 session request to 4,096 CBOR bytes and added caller-selected session
  response body budgets with a 4 MiB default. Encoders preflight exact size; decoders check the
  complete input before CBOR parsing. Seven portable budget recipes and public boundary tests
  retain the existing session bytes and future-vault-kind behavior.
- Corrected generic SSH agent extensions to RFC 9987: raw request contents, named response 29,
  request-name binding, empty success, and unsupported-versus-failed dispatch. Forwarded
  session-bind-shaped requests are refused without ending the channel. The provisional extra
  contents string and nonempty success encoding are removed; the response name and unsupported
  error are pre-Stable source-breaking changes. Nine portable vectors, public boundary/recovery
  regressions, and decoder fuzz seeds cover the correction.

- Framed SSH agent streams now fail closed after uncertain write, flush, read, or response-frame
  failures. Later requests return typed `ChannelUnusable` without I/O, preventing a late response
  from being assigned to a new request; complete agent refusals and pre-I/O validation errors remain
  recoverable. Pageant named pipes share this behavior. The new `AgentError` variant is a
  pre-Stable source-breaking change for exhaustive matches.
- Preserve LF endings for shell scripts so the native Unix agent fixture also runs from a
  Windows checkout mounted into its Linux container.
- Added independent, caller-selected read budgets for complete K-4 change-feed, snapshot, and
  version-history responses. Encoders preflight exact CBOR sizes, decoders reject oversized input
  before parsing, and default methods enforce 260 KiB payloads and a 266,295,039-byte body cap.
  Nine portable profile vectors and public boundary tests cover all three response types.
- Added the bounded D-90 K-5 certificate issuance Resource response codec and exact 201 OpenAPI
  and generated TypeScript shape. Seven signed user-certificate vectors, host-role and malformed
  response rejection, 64 KiB binary and 131072-byte JSON boundaries, HTTP metadata checks, and
  API JSON fuzz seeds cover the wire. Request-subject comparison is separate from SSH trust,
  signature, authorization, current-validity, and revocation checks.
- Added explicit deployment-selected limits for complete K-4 write exchanges: requests,
  assignments, conflicts, and request-aware checks accept raised or lowered budgets. Encoders
  preflight exact request sizes and decoders check body bounds before CBOR parsing. Default
  methods enforce 260 KiB envelopes, 500 writes, and 4 MiB requests; the complete conflict cap
  remains 128 MiB. Nine public profile vectors and higher/lower/boundary tests cover the APIs.
- Published portable account-key PUT failure vectors for malformed fields, UUIDs, wrap order,
  revision progression and overflow, artifact/body limits, and signature width. Public tests
  exercise canonical CBOR input and the request decoder or contextual revision validator.
- Added request-aware K-4 acknowledgement validation that rejects a cursor below the request
  while preserving higher stored maxima, zero/maximum cursor bounds, and response extensions.
  Published acknowledgement vectors and CBOR bytes remain unchanged.
- Added the bounded D-88 K-5 user-certificate issuance request codec with exact OpenAPI and
  TypeScript selector union, seven raw-key algorithms, request and 400/413 problem vectors,
  failure-path tests, and API JSON fuzz seeds. Existing 201 Resource and required idempotency
  header are retained; issuance and response-data binding remain separate work.
- Added native Linux Unix-socket interoperability for the public OpenSSH agent connector, using
  the same raw-key and user-certificate fixture with five rejection and reconnection controls.
  The Linux test runs in a disposable container with a pinned Rust toolchain and bounded test
  processes; Windows pipe and Pageant connectors remain unverified.
- Added D-87 request/path-aware validation for six successful K-4 key-management mutation
  responses. Public tests bind decoded published vectors, reject mismatched and invalid inputs,
  and retain additive response extensions without changing CBOR bytes or error types.
- Added an API JSON fuzz target covering authentication, native/browser refresh, and gateway-ticket
  issuance decoders, canonical round trips, and prohibited idempotency headers. Public-vector and
  malformed/size-bound seeds feed both Linux change checks and the daily fuzz matrix.
- Added a disposable real OpenSSH agent interoperability fixture for raw Ed25519 keys and user
  certificates. It verifies pinned host and user CA keys, exact command output, exit zero, five
  rejection paths, and valid reconnection controls. A loopback TCP bridge exercises the agent wire
  protocol without claiming native Unix-socket, Windows pipe, or Pageant connector coverage.
- The disposable OpenSSH host-certificate fixture now offers P-384/P-521 raw keys and host
  certificates together on the same listeners. Thirty cases verify default certificate selection,
  exact authenticated commands, wrong CA/principal/expiry rejection without raw-key fallback, and
  healthy reconnects while retaining the separate raw and certificate controls.
- Added bounded gateway-ticket issuance request/response JSON codecs, canonical SSH public-key
  and edge-address validation, redacted credentials, and the `gateway.invalid_request` problem
  code. OpenAPI, generated TypeScript, vectors, and both dependency graphs are synchronized;
  provisional ticket resource CRUD and idempotency are removed. Ticket claims/signatures,
  authorization, raw-TLS proof binding, and atomic single-use consumption remain incomplete.
- Reject bare hexadecimal IPv4 markers such as `0x` and `edge.0x` in device-authentication
  origins and DPoP targets, including non-default ports. This prevents signed origins from
  changing under URL host parsing; canonical IPv4 and ordinary non-final DNS labels remain valid.
- Added per-Host promotion of a validated default SSH algorithm while preserving the defaults
  of unconfigured Hosts and the legacy tail. A 15-case disposable OpenSSH matrix verifies every currently mapped modern
  KEX and cipher, both SHA-2 ETM MACs under CTR, and `none` versus selected delayed zlib. It
  checks actual bidirectional negotiation, host-key pinning and wrong-pin rejection, authentication,
  exact binary command output, and exit status. Sntrup, UMAC, and the broader peer/platform matrix
  remain open.
- Added software ECDSA user authentication on NIST P-384 and P-521 through a curve-selecting
  `EcdsaSshSigner` for imported OpenSSH private keys. The shared request and concrete client
  bind the selected curve, complete certificate, subject key, and session. Public and disposable
  OpenSSH tests cover raw keys, user certificates, unauthorized keys, and subject/principal
  rejection; the existing P-256 signer and SSH wire formats remain unchanged.
- Validate default host certificates against the system Unix time at verification, so delayed or
  reused client configurations cannot accept expired certificates. Clock failure is typed;
  explicit fixed-time policies retain their behavior. In-process regression tests cover delayed
  expiry and callback suppression, while a disposable OpenSSH fixture covers P-384/P-521 raw host
  keys, valid certificates, wrong CA, wrong principal, expired certificates, and fresh connections
  after rejection.
- The paired SSH throughput comparison now exits with an error when either required cipher's
  same-host median ratio falls below 80% of OpenSSH. It rejects invalid samples before computing
  the ratio; a passing local diagnostic still does not establish the fixed-hardware release budget.
- Added once-per-connection, two-second-bounded RSA SHA-2 discovery from `server-sig-algs`.
  The concrete client reports SHA-512, SHA-256, advertised SHA-1-only, or undetermined without
  selecting SHA-1 or probing authentication. Success and terminal timeout, engine, or cancellation
  errors are cached. In-process tests cover mapping and auth continuation; a disposable OpenSSH
  fixture checks constrained advertisements and real SHA-2 public-key authentication.
- Bounded direct SSH setup with async DNS and family-interleaved Happy Eyeballs dialing under one
  ten-second resolve-and-TCP deadline, followed by a separate ten-second SSH handshake deadline.
  `connect_with_timeout` selects both budgets; typed direct transport and handshake timeout errors
  distinguish failures. Cancellation stops pending dials and closes a stalled handshake socket.
- Added D-80 ES256/P-256 DPoP construction and stateless verification in `scoplen-crypto`,
  including strict canonical target/JWK/JWS validation, RFC 7638 thumbprints, token and nonce
  binding, inclusive freshness limits, redacted credential diagnostics, and signer-output
  verification. An RFC 9449 proof vector, public failure-path tests, and DPoP fuzz seeds cover
  the shared boundary. Consumers still own token authentication, cross-instance replay claims,
  authorization, and refresh rotation.
- Extended the SSH protocol fuzz target to public security-key and SSH certificate boundaries,
  including canonical round-trip assertions, certificate signature/role/principal/validity
  validation, and tracked valid and malformed identity seeds.
- Added the D-78 K-3 JSON refresh request and browser-safe response codecs, strict body and token
  bounds, redacted errors and Debug output, and three refresh problem codes. OpenAPI and generated
  TypeScript now distinguish native body tokens from browser HttpOnly-cookie requests and reject a
  browser response containing `refresh_token`. Published auth/problem vectors cover the wire;
  DPoP verification and atomic token rotation remain server responsibilities.
- Added a notification protocol fuzz target with published valid vectors, malformed and size-bound
  seeds, and canonical round-trip assertions for every accepted message. Linux change checks
  replay the corpus, and the daily fuzz matrix includes the new target.
- Added bounded K-4 notification WebSocket context, first-message authentication, and ready
  acknowledgement codecs with GET/CONNECT vectors, strict compact-JWS lexical checks, redacted
  credential debug output, and rejection of mixed message fields. The existing event reader now
  enforces the same 16 KiB bound and rejects zero advancement sequence numbers. JWT/DPoP
  verification and connection lifecycle remain consumer responsibilities.
- Enabled both OpenSSH FIDO2 security-key user-certificate algorithms through the shared signer
  and concrete client. Authentication binds the complete certificate, raw subject key and
  application, username, service, and session; malformed or mismatched subjects fail before
  signing. In-process SSH and disposable OpenSSH checks cover both algorithms, wrong signature
  inputs, subject/application/principal/validity failures, local CA pins, server-untrusted CAs,
  and KRL serial and key-ID revocation with unrevoked and raw-key controls. CA trust remains a
  caller decision, KRL enforcement remains server-side, and physical-token integration is open.
- Connected selected FIDO2 providers to raw `sk-ssh-ed25519@openssh.com` and
  `sk-ecdsa-sha2-nistp256@openssh.com` public-key authentication. The signer rechecks its pinned
  identity and application, algorithm, and required UP/UV flags before dispatch. Corrected the
  OpenSSH signature wrapper so flags and counter follow the raw signature string; agent-backed
  security-key signatures preserve those fields. A disposable OpenSSH fixture verifies both raw
  algorithms and rejects wrong-key, wrong-application, and wrong-payload signatures. Physical
  token adapters remain open.
- Made SFTP sessions fail closed after interrupted or uncorrelated exchanges. Canceled transfers,
  transport and protocol errors, and pipelined failures now isolate stale responses on the old
  channel; callers receive a typed `SessionUnusable` error on later use and can open a fresh SFTP
  channel without reconnecting the SSH transport. Fully correlated file-status rejection remains
  reusable.
- Verified the default ML-KEM/ChaCha20 negotiation against a disposable OpenSSH listener that
  offers only those algorithms. Pinned-key authentication, exact command output, and exit status
  pass alongside the existing modern, legacy, strict-KEX, and rekey checks; the full algorithm
  interoperability matrix remains incomplete.
- Expanded the disposable OpenSSH fixture with a real KRL: the server rejects Ed25519 user
  certificates revoked by serial and key ID, while a certificate from the same trusted CA and
  the same raw public key still complete authenticated commands. The test disables OpenSSH's
  source penalties so deliberate rejection cases do not block later controls.
- Enabled the released SSH engine's 3DES implementation and mapped `3des-cbc` only for explicit
  per-Host legacy selection. The constrained OpenSSH fixture now tests AES-CBC and 3DES
  separately, including default-policy rejection, exact command output, exit status, and Host
  isolation. Modern default offers are unchanged.
- Reject repeated password, public-key, certificate, keyboard-interactive, and none-probe calls
  after full authentication with the typed local `AlreadyAuthenticated` error. A bounded real
  SSH regression verifies all five calls and continued channel use on the same connection.
- Added the bounded K-3 challenge request codec, exact device-authentication signature input,
  canonical HTTPS origin validation, published vectors, unauthenticated OpenAPI paths, and
  generated TypeScript auth declarations. Request codecs reject malformed and oversized bodies;
  the pre-Stable UTC challenge-time validation rejects leap-second labels. Challenge storage and
  token issuance remain server-owned. `AuthTokenResponse` debug output redacts both opaque tokens.
- Expanded the disposable OpenSSH check to cover raw Ed25519, P-256, RSA-SHA2-256/512 keys and
  all four user-certificate variants, with wrong-password, unauthorized-key, wrong-principal,
  local CA-pin, and server-untrusted CA failures. The shared example bounds SSH steps and
  requires exact output and a successful exit status. CI runs the expanded fixture alongside
  existing SFTP and route checks; the wider interoperability matrix remains incomplete.
- Added disposable OpenSSH client- and server-initiated rekey checks using constrained modern
  algorithms. Each transfers 128 KiB of exact binary echo on one authenticated channel;
  OpenSSH DEBUG3 logs establish post-authentication KEXINIT direction and completed NEWKEYS, while
  a high-limit control must show no rekey. Corrected the keystroke benchmark's russh version label.
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
