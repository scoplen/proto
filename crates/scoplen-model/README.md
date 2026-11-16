# scoplen-model

The shared K-1 object model, deterministic CBOR, merge rules and D-142 portable JSON profile.
The canonical specification is `scoplen-docs/04-object-model.md`.

`portable::JSON_SCHEMA` publishes the initial closed JSON Schema for all eleven object types.
The codec additionally checks encoded bytes, NFC, canonical UUID/base64url, conditional model
rules and represented CBOR map keys; JSON Schema alone does not replace these checks.

Use `portable::Entry::from_object` to project a live object without clocks, tombstones or clear
markers. Deleted objects return `None`; unknown model fields are reported rather than lost.
`SecretMode::Omitted` removes portable Credential secrets and Secret Snippet defaults and records
exact omission pointers. `Entry` holds numeric model paths for Rust consumers, redacts `Debug`,
and wipes its owned values on drop. Its `to_object` method requires an explicit destination id,
clock and writer, leaves reference remapping to the consumer and refuses redacted Credentials.
It never fabricates a password or changes a Credential binding.

`portable::write_archive` streams an iterator of entries into any `std::io::Write`.
`portable::read_archive` streams any `std::io::Read` through a per-entry callback and returns a
`Summary` only after validating the complete header and JSON EOF. Document members may appear
in any order. Callbacks can therefore run before final header validation and are **tentative**:
stage their effects and roll back unless the entire read succeeds. The reader retains one
bounded encoded entry and the archive's distinct ids, never the whole JSON document.

The format accepts at most 100,000 entries, 8 MiB per encoded entry and 64 KiB each for header
and final framing. Text, map, layout and complete decoded-object bounds remain K-1 bounds.
Arbitrary Preference and Snippet values use the lossless tagged profile, including unsigned
64-bit integers, negative values through -2^64 and compound map keys. Float, duplicate JSON
names, unknown members and trailing content are rejected with content-free errors.
Nested null remains a value. A cleared top-level Preference value is omitted, like every
other scalar clear marker; importing `fields.value: null` is rejected rather than reinterpreted.

This crate performs no encryption or authorization. Native secret-bearing transfer uses the
optional standard age adapter in `scoplen-crypto`. The consumer must authenticate the complete
age payload, finish JSON EOF and recheck the reviewed source and destination before one atomic
publication of objects, ownership, receipts and sync dirty state. Never commit a decrypted
prefix. Publishing an export also requires successful finalization of its enclosing age writer.
Identity receipts, remapping, missing references, imported-trust consent and vault permissions
remain consumer responsibilities. Parsing metadata never establishes historical authority.

Independent synthetic positive and rejection examples are published in
`vectors/model-portable.json` and exposed through `scoplen_test_vectors::MODEL_PORTABLE`.
