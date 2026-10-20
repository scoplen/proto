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

- The S1 baseline, S2 object-model gate, and S3 cryptographic gate are complete, including schema
  handling, model limits, merge laws, key hierarchy, device certificates, encrypted envelopes,
  recovery, Shamir, escrow wrapping, CPace/QR pairing, and executable known-answer vectors.
  S4 has a concrete client adapter for transport, authentication, channels, routes, and SFTP,
  with per-Host algorithm, incoming/outgoing byte and elapsed rekey configuration, and initial and
  repeated strict-KEX interoperability verification; complete algorithm/extension support, default compatibility, interoperability, and performance remain
  open. S6 has the error contract, K-3 device-auth JSON codecs, and K-4 sync codecs, while complete
  API and production endpoint behavior remain open. D-106 adds a bounded public-only JWKS
  codec, separate authentication rate headers, and documented failure/recovery responses with
  public vectors and parser seeds; it does not establish issuer or keyring trust. D-107 adds
  exact coarse device scopes and explicit operation requirements with public vectors, while
  complete current-state and resource authorization remain consumer work. The canonical
  roadmap records each outcome.
  S5 and S7 have no completed gate evidence.
- Independent security review and interoperability evidence are required before a Stable release.
