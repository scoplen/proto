# Shared test vectors

Vector files are UTF-8 JSON documents with the `scoplen-test-vectors` format name and version `1`.
Each vector has a stable `id`, a contract-specific `kind`, and opaque `input` and `expected` strings.
The loader in `scoplen-test-vectors` validates the envelope and identifiers; the contract crate that
owns a kind validates its encoding and interprets the values.

The baseline document includes K-1 vectors for shortest-form maps, NFC text, the complete CBOR
negative-integer range, and an executable object merge. `model.cbor` vectors use hexadecimal CBOR
for both `input` and `expected`. `model.merge` vectors use two hexadecimal object envelopes joined
by `|` in `input`, with the expected merged envelope in `expected`. Contract-specific vector kinds
and additional canonical encodings are added with the corresponding contract gate and are
consumed by both client and server workstreams.

`ssh-agent-extensions.json` contains K-7 RFC 9987 section 5.8 agent-extension frames.
Inputs are complete agent frames as lowercase hex. Valid vectors expect exact re-encoded hex;
invalid vectors expect `reject`. The synthetic session-bind-shaped body has multiple raw SSH
fields and a boolean; it tests opaque framing, not session-bind signature or semantic validation.
The set includes an empty `query`, named response 29, empty success 6, failures 5/28, malformed
names and nonempty success rejection. Public tests separately cover response-name binding,
resource bounds, and forwarded refusal followed by healthy queries and authorized signing.

`gateway-signed-ticket.json` contains a deterministic D-96 compact JWS signed by a synthetic
Ed25519 key. The exact input bytes and expected UUIDv7 identifier/expiry are verified through the
public `scoplen-crypto` API. It is test material, not a deployment credential or replay claim.

`gateway-signed-proof.json` contains a synthetic D-97 ES256 raw-TLS proof and its signed ticket.
The public verifier authenticates the ticket first, then checks the proof's exact-byte hash,
device-key thumbprint, signature, audience, and lifetime. The `dpop_proof` client-hello field
continues to carry the compact proof; this fixture does not establish replay prevention.

`sync-changes.json` contains K-4 change-feed vectors. Query inputs are JSON objects with `after`
and `limit`; expected values are the canonical query string. Response inputs are JSON objects with
`changes`, `next_cursor`, and `more`; payloads are lowercase hexadecimal and a missing signer is
represented by JSON `null`. Response expected values are deterministic CBOR. Each response change
entry uses integer map keys 1 through 5, as defined by `07-sync-protocol.md` §4.

`sync-messages.json` contains the remaining K-4 wire vectors. Write requests are JSON arrays with
`object_id`, nullable `base_seq`, lowercase hexadecimal `payload`, and `tombstone`; their
expected value is a direct deterministic CBOR array of integer-keyed maps 1 through 4. Write
responses are JSON arrays of `object_id` and `seq` assignments and encode as a direct array of
integer-keyed maps 1 and 2. Acknowledgement requests and responses use a JSON object with
`cursor` and encode as a text-keyed CBOR map. Snapshot responses use `objects`, `next_cursor`,
and `more`, with the same integer-keyed entries and page rules as the change feed. Version
responses use `versions`, contain one object id in ascending sequence order, and include at most
the current entry plus 20 retained entries. All expected values are deterministic CBOR in lowercase
hexadecimal. Conflict responses use `sync.writes.conflict` with a complete RFC 9457 `problem`
and a `conflicts` array in request order. Each conflict names an `object_id` and carries a current
change entry or JSON `null` for an absent object. Default codecs bound the array to 1–500 unique
ids and each current payload to 260 KiB; explicit exchange limits may raise or lower these
defaults. The encoded conflict problem body remains capped at 128 MiB.

`sync-write-limits.json` applies explicit profiles to exact write-request, assignment, and
conflict CBOR. Each JSON `input` contains positive `max_envelope_bytes`, `max_batch_objects`,
and `max_batch_bytes`, plus `cbor_hex`. `expected` is `accept` or `reject`. Accepted messages
round-trip to those exact bytes. These vectors include low-limit rejection and a raised profile;
public tests additionally generate 501-entry exchanges and requests above the default 4 MiB cap.

`sync-read-limits.json` applies explicit profiles to the existing change-feed, snapshot, and
version-history CBOR bytes. Each JSON `input` contains positive `max_envelope_bytes` and
`max_body_bytes`, plus `cbor_hex`; `expected` is `accept` or `reject`. For each response, the
exact-body vector sets `max_body_bytes` to half the hex string length, while the two rejection
vectors subtract one byte from either the body or the two-byte payload limit. Accepted responses
round-trip to the exact published bytes. Public tests additionally cover larger historical
payloads, CBOR length transitions, overflow, ignored extensions, and request/path correlation.

`sync-notifications.json` contains the content-free K-4 notification events sent over the WebSocket.
Vault advancement uses `{seq, vault}`, rotation pending uses `{rotation_pending, vault}`, and
device revocation uses the boolean marker `{device_revoked: true}` until the specification defines
an event payload. UUIDs are encoded as 16-byte UUIDv7 strings, and all expected values are
deterministic CBOR in lowercase hexadecimal.

`sync-notification-auth.json` contains the K-4 WebSocket opening context for both `GET` and
`CONNECT`, the client's first authentication message, and the successful server acknowledgement.
Inputs are JSON objects; expected values are deterministic CBOR in lowercase hexadecimal. The
compact-JWS strings are synthetic public test data. The shared codec validates their lexical wire
shape and limits, not signatures, claims, device state, key binding, or proof replay.

`api-auth.json` includes K-3 challenge/device vectors and D-78 native/browser refresh request
and response JSON vectors. The browser response has no `refresh_token`; its rotated credential
travels in an HttpOnly cookie managed by the server. `api-problem.json` includes refresh failure
examples as canonical JSON with the registered codes and `changed`/`retryable` fields; its older
CBOR vectors remain valid. All token strings are synthetic public test data.

`api-dpop.json` publishes the compact ES256 protected-resource proof from RFC 9449 Figure 13,
with its public JWK thumbprint from Figure 11, proof id and timestamp, inclusive
last accepted second, and independently computed `ath`. The public `scoplen-crypto` test verifies
the original JWS signing bytes against the RFC's access token and these expected values. The vector is public RFC test material,
not a production credential; replay prevention remains a consumer obligation.

`gateway-ticket-issuance.json` contains K-5/K-6 JSON request and successful response vectors
for the transient ticket issuance action. They use synthetic public key and ticket strings,
validate bounded canonical syntax, and preserve edge preference order. The response ticket is
opaque; these vectors do not prove a signature, authorization, expiry, or single-use consumption.
`api-problem.json` also contains 400 and 413 `gateway.invalid_request` JSON problem vectors.

`certificate-issuance-request.json` contains the D-88 K-5 JSON request vectors for ordered Host
and HostGroup selectors. Inputs deliberately vary member order; expected values use the shared
encoder's exact order and no whitespace. The raw public key is synthetic public test data. These
vectors prove request syntax and bounds, not authorization or certificate issuance.
`api-problem.json` also contains 400 and 413 `certificate.invalid_request` JSON problem vectors.

`certificate-issuance-response.json` contains D-90 K-5 successful certificate Resource vectors
for all seven supported subject-key algorithms, including both security-key forms. The synthetic
OpenSSH user certificates carry valid CA signatures; `input` also includes the matching raw
request public key, while `expected` is the exact compact Resource encoding. Public tests verify
their signatures as fixture provenance, then exercise the shared parser and request-subject check.
The response parser itself validates canonical syntax, role, bounds, and interval but does not
establish CA trust, signature validity, authorization, current validity, or revocation.

`account-profile.json` contains D-99 K-3/K-5 current-account Resource response vectors.
`account.profile.response_json` expects exact compact JSON after decoding, including string
and null email values and ignored extensions. `account.profile.response_invalid` expects the
stable codec error name. `account.profile.response_budget` uses a JSON recipe: start from the
named `base` vector, append the named string `extension` filled with ASCII `a` until the complete
body reaches `total_bytes`, then require `accept:<bytes>` or `reject:<bytes>`. These recipes
exercise the 4,096/4,097-byte boundary without large literal bodies. The codec establishes syntax
and bounds, not authenticated account ownership or email verification.

`sync-keys.json` contains the K-4 account key-bundle vectors from `07-sync-protocol.md` §8.1 and
D-50. The GET response uses opaque non-empty artifact hex strings and lexicographically sorted
certificate and revocation arrays. The PUT request uses one sorted device wrap per device, a
synthetic fixed-width 64-byte signature, and the same deterministic map encoding for the exact
replay vector. The signature-input vector covers the `spl-sync-keys-v1` domain prefix and unsigned
map bytes. The successful PUT response is `{revision}`. These vectors exercise transport encoding
only; key authenticity is owned by `scoplen-crypto`.

`sync-keys-failures.json` publishes the §8.1 negative PUT fixtures. Every `expected` value is
`reject`. For `sync.keys.put.decode-reject`, `input` is lowercase hexadecimal deterministic CBOR;
the public request decoder must reject it. For `sync.keys.put.next-revision-reject`, `input` is
`current|cbor_hex`; the decoder must accept the request, then the next-revision check must reject
it against the decimal `current` revision. This includes a skipped revision and unsigned overflow.
All literal CBOR fixtures decode canonically before the K-4 field checks run.

The two large `sync.keys.put.decode-reject-generated` fixtures use a compact JSON recipe in
`input`. Both start from the encoded `sync-keys-put-request-v1` value. The `account_kem_key` recipe
replaces that byte string with `length` repetitions of the single hexadecimal `byte`. The
`device_wraps` recipe replaces the array with `count` wraps; its UUIDv7 device ids are consecutive
16-bit suffixes starting at `first_device_id`, and each wrap uses `wrapped_ark_length` repetitions
of `wrapped_ark_byte`. Encode the resulting map as deterministic CBOR, then require decoder
rejection. The first fixture exceeds only the 64 KiB artifact bound; the second uses 1,000 sorted
wraps of 4,200 bytes each to exceed only the 4 MiB body bound. A 63-byte signature fails the K-4
wire width check; cryptographic verification of any 64-byte signature belongs to K-2 consumers.

The existing `sync-vaults.json`, `sync-vault-epochs.json`, `sync-vault-members.json`, and
`sync-keys.json` success-response vectors also exercise D-87 request/path binding through the
public codecs. Binding changes validation behavior only; their deterministic CBOR bytes remain
unchanged.

`crypto.json` contains K-2 known answers. All private keys and plaintexts in this document are
synthetic, public test material and must never be used for real data. Every binary field is
lowercase hexadecimal; fields in `input` are separated by `|`. Decimal integer fields and the
recovery display and safety-number outputs are written as text.

| Kind | Input fields, in order | Expected |
| --- | --- | --- |
| `crypto.hkdf-sha256` | IKM, salt, info, output length | Derived bytes (RFC 5869 case 1) |
| `crypto.xchacha20poly1305` | key, nonce, plaintext, AAD | ciphertext and tag |
| `crypto.p256-signature` | private scalar, message | uncompressed public key, fixed-width signature |
| `crypto.ed25519-signature` | private seed, message | public key, signature |
| `crypto.hpke-account-open`, `crypto.hpke-device-open` | recipient private key, encapsulated key, info, AAD, ciphertext | plaintext |
| `crypto.device-key-wrap-open` | device private key, encapsulated key, info, AAD, ciphertext | 32-byte unwrapped key |
| `crypto.device-certificate` | account signing seed, device UUID, account UUID, device signing scalar, device KEM private key, UTF-8 name, UTF-8 platform, Unix milliseconds | signed deterministic CBOR |
| `crypto.device-revocation` | account signing seed, device UUID, Unix milliseconds, UTF-8 reason | signed deterministic CBOR |
| `crypto.object-envelope` | vault UUID, epoch, K-1 object CBOR, vault key, signer UUID, P-256 signing scalar, nonce | signed encrypted envelope |
| `crypto.recovery-display` | raw recovery key | `SPL1-` display with checksum |
| `crypto.recovery-blob` | raw recovery key, account UUID, ARK, nonce | encoded wrapped ARK |
| `crypto.shamir-split` | secret, threshold, share count, coefficient bytes | serialized shares, separated by `|` |
| `crypto.safety-number` | account UUID, Ed25519 public key, and X25519 KEM public key for each account | sixty decimal digits, both 32-byte fingerprints, and canonical `splsafety2:` QR text |
| `crypto.local-db-key` | UTF-8 passphrase, database key, Argon2 memory KiB, time cost, parallelism, salt, nonce | encoded Argon2id wrapper |
| `crypto.escrow-account-open` | account UUID, administrator UUID, recipient private key, encapsulated key, ciphertext | serialized authenticated Shamir share |
| `crypto.escrow-device-open` | account UUID, request UUID, device signing public key, recipient private key, encapsulated key, ciphertext | serialized authenticated Shamir share |
| `crypto.escrow-verification` | account UUID, administrator UUID, request UUID, device signing and KEM public keys | grouped 80-bit verification code and account/device contexts |
| `crypto.qr-pairing` | pairing UUIDv7, P-256 KEM public key, P-256 signing public key | canonical `splpair1:` QR text |
| `crypto.cpace-pairing` | pairing UUIDv7, initiator and responder UUIDv7, code, initiator and responder RNG bytes, nonce, plaintext | initiator share, responder share, 64-byte CPace session id, both confirmations, and nonce-prefixed XChaCha frame |

The `crypto.cpace-pairing` expected fields are lowercase hexadecimal and are
separated by `|` in this order: initiator share, responder share, session id,
initiator confirmation, responder confirmation, and the frame (`nonce ||
ciphertext || tag`).  Its fixed context and role ordering are the K-3
typed-code contract from `06-identity-and-authentication.md` §2; the RNG fields
make the published shares reproducible without exposing production secrets.

The HPKE seal operations use fresh randomness, so their published known answers exercise opening
fixed ciphertexts. The test suite separately exercises sealing and tamper rejection. The local
database wrapper vector uses 8 MiB and one pass to keep CI practical; production defaults remain
256 MiB, three passes, and four lanes.

`api-problem.json` contains `api.problem.cbor` vectors, including quota and rate failures. Each
`input` is the JSON form of an RFC 9457 problem with all eight required Scoplen fields; `expected`
is the deterministic CBOR body in lowercase hexadecimal. The `scoplen-api` tests exercise the
public JSON and CBOR contract, including
unknown error-code preservation and malformed-body rejection.

`api-auth.json` contains the K-3 JSON and signature-input vectors. Challenge requests contain
only a canonical UUIDv7 device id and have a 256-byte encoded-body limit. The signature-input
vector encodes `spl-auth-v1 || UTF-8 canonical HTTPS origin || raw nonce || raw UUIDv7` in lowercase
hexadecimal; the public crypto test signs it with the K-2 device signer and rejects substituted
origin, nonce, or device values. Challenge responses use a 32-byte lowercase
hexadecimal nonce and a normalized RFC 3339 UTC timestamp with seconds `00` through `59`. Device
requests use a canonical UUIDv7, the
canonical challenge nonce, and a fixed-width P-256 `r || s` signature as lowercase hexadecimal.
Token responses use literal `DPoP`; `AuthTokenResponse::new` writes the default 600-second and
30-day lifetimes, while readers and validators accept any positive integer lifetime. The expected
values are canonical field order; readers ignore unknown response fields while device requests
reject unknown fields. Device request bodies have a 4,096-byte encoded-body limit, including
whitespace; both request codecs reject duplicate, missing, and mistyped fields.

`sync-session.json` contains `sync.session.request` and `sync.session.response` vectors. Each
`input` is a JSON description of the typed K-4 session value; `expected` is deterministic CBOR in
lowercase hexadecimal. UUIDs are written as canonical text in the vector input and encoded as
16-byte CBOR byte strings. The public codec tests consume both vectors and reject missing fields,
invalid limits, duplicate vaults, and malformed nested values.

`sync-session-limits.json` contains bounded generation recipes against those two published base
vectors. `base` names the exact `sync-session.json` vector. An optional `replace` selects its
version text field; `repeat_ascii` is one ASCII character repeated `length` times before canonical
CBOR encoding. Response recipes set a positive `body_limit`; requests use the fixed 4,096-byte
limit. Each `expected` is `accept:<exact encoded bytes>` or `reject:<exact encoded bytes>`. The
recipes cover request 4,096/4,097, the existing response bytes at exact and one-byte-short local
budgets, and default 4 MiB/one-byte-over response bodies with a raised accepting budget. This
keeps multi-megabyte hex out of the repository while allowing both workstreams to reproduce exact
CBOR boundary inputs.

`gateway.json` contains K-6 client-hello vectors. The `input` object has compact-JWS `ticket` and
`dpop_proof` strings. `gateway.client_hello.cbor` expects the deterministic CBOR map, while
`gateway.client_hello.frame` adds the four-byte big-endian body length. The public codec rejects
unknown or missing fields, malformed compact-JWS strings, non-canonical CBOR, truncation, trailing
bytes, and body lengths above the 16 KiB unauthenticated read bound.
