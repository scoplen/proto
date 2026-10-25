# Scoplen protocol principles

This repository is a component of Scoplen, a Plystra project. The project-level adoption record is
[`scoplen-docs/PROJECT_PRINCIPLES.md`](../scoplen-docs/PROJECT_PRINCIPLES.md).

## Review record

- Philosophy version reviewed: Plystra Craft 1.0.1
- Source commit reviewed: `plystra/craft@dd617b370203d5dce1d30b8b81284d16d96a432c`
- Review date and maintainer: 2026-10-06, Plystra LLC
- Maturity: Exploration
- Maintenance: Active
- Components: Rust libraries and shared known-answer test vectors
- Public data surface: none; the crates do not collect user data
- Review status: Open gaps remain while contract implementations are built

## Applicable standards

The repository applies `plystra-craft` and `plystra-craft-code` from `.agents/skills/`. The source
license is Apache-2.0. Security-sensitive protocol and cryptographic behavior is implemented only
after its contract is specified in `scoplen-docs` and covered by vectors and failure-path tests.

## Open gaps

- The S1 baseline and S2 object-model gate are complete, including schema handling, model limits
  and merge laws. S3 remains Incomplete under D-125 through D-127: shared key hierarchy,
  certificates, encrypted envelopes and password bootstrap are implemented, while scoped recovery
  and retirement of historical recovery exports remain open. Historical whole-Account escrow exports
  do not implement the current recovery flow. D-127 adds fixed Unicode 17 NFC,
  Argon2id-v19, separate authentication/KEK outputs, the exact ARK envelope and reconstruction of
  both Account roots, with independent vectors, failure tests and bounded parser fuzz targets.
  Transport, freshness and credential lifecycle remain consumer work under D-128.
  S4 has a concrete client adapter for transport, authentication, channels, routes, and SFTP,
  with per-Host algorithm, incoming/outgoing byte and elapsed rekey configuration, and initial and
  repeated strict-KEX interoperability verification; complete algorithm/extension support, default compatibility, interoperability, and performance remain
  open. A mixed OpenSSH/Dropbear fixture checks one to three independent Jump hosts,
  per-hop trust/password refusal, exact output, cancellation and parent teardown;
  this does not establish the complete server/platform matrix.
  S6 has the error contract, K-3 device-auth JSON codecs, and K-4 sync codecs, while complete
  API and production endpoint behavior remain open. D-106 adds a bounded public-only JWKS
  codec, separate authentication rate headers, and documented failure/recovery responses with
  public vectors and parser seeds; it does not establish issuer or keyring trust. D-107 adds
  exact coarse device scopes and explicit operation requirements with public vectors, while
  complete current-state and resource authorization remain consumer work. Notification route
  lookup covers both defined opening methods, with public exact-route and DPoP method-binding
  regressions; production notification lifecycle remains consumer work. The canonical roadmap
  records each outcome.
  D-124 adds bounded fixed logout wire and an explicit authenticated intrinsic requirement,
  with vectors and scripted terminal/uncertain-result behavior. The reference peer supplies no
  general authorization evidence; durable revocation, exact Origin/DPoP admission, cookie
  isolation and browser adoption remain consumer responsibilities.
  D-113 adds bounded complete signed-statement transport and its existing-scope operation,
  with precise OpenAPI/TypeScript, public vectors and parser seeds. Account context, K-2
  signatures, completeness/freshness and current-state authorization remain consumer checks.
  D-128 adds bounded native Account entry/protected bootstrap codecs and exact Account/Device
  proof inputs with independent vectors, generated contracts and parser seeds. Retired Personal
  invitation/pairing/replacement public surfaces and fixtures are removed. Local key opening,
  durable admission/receipts/current-state CAS and production consumers remain separate work.
  S5 and S7 have no completed gate evidence.
- D-121 uses an asynchronous bounded interactive responder with connection termination after
  dispatched interruption and local refusal of later operations. Public encrypted-peer tests and
  a pinned OpenSSH/PAM fixture cover protocol acceptance; consumer prompt UI, cancellation UX,
  credential custody and the broader PAM/server matrix remain consumer acceptance work. The
  consumer owns user-input deadlines because a pending engine response may defer observing EOF.
- Independent security review and interoperability evidence are required before a Stable release.
