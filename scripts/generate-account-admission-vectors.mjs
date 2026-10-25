// SPDX-License-Identifier: Apache-2.0
// Independent Node D-128 writer. Every key and credential below is synthetic fixture material.
import { createHash, createHmac, createPrivateKey, createPublicKey, createECDH, sign, verify } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const vectors = [], outputs = [];
const hex = v => Buffer.from(v, "hex");
const uuid = v => hex(v.replaceAll("-", ""));
const b64 = v => v.toString("base64url");
const hash = (...v) => { const h = createHash("sha256"); for (const x of v) h.update(x); return h.digest(); };
function head(major, n) {
  n = BigInt(n);
  if (n < 24n) return Buffer.from([major << 5 | Number(n)]);
  const size = n <= 255n ? 1 : n <= 65535n ? 2 : n <= 4294967295n ? 4 : 8;
  const out = Buffer.alloc(size + 1); out[0] = major << 5 | ({ 1: 24, 2: 25, 4: 26, 8: 27 })[size];
  if (size === 8) out.writeBigUInt64BE(n, 1); else out.writeUIntBE(Number(n), 1, size);
  return out;
}
function cbor(v) {
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (typeof v === "string") { const b = Buffer.from(v); return Buffer.concat([head(3, b.length), b]); }
  if (typeof v === "boolean") return Buffer.from([v ? 0xf5 : 0xf4]);
  if (typeof v === "number" || typeof v === "bigint") return head(0, v);
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(cbor)]);
  const entries = v instanceof Map ? [...v] : Object.entries(v);
  const pairs = entries.map(([k, x]) => [cbor(k), cbor(x)]).sort(([a], [b]) => Buffer.compare(a, b));
  return Buffer.concat([head(5, pairs.length), ...pairs.flat()]);
}
const origin = "https://control.example.com", username = "fixture.user";
const ids = {
  operation: "018f35d4-1f8f-7e2a-9e56-7a5e8a9f1101", account: "04000000-0000-7000-8000-000000000000",
  vault: "05000000-0000-7000-8000-000000000000", first: "03000000-0000-7000-8000-000000000000",
  second: "03000000-0000-7000-8000-000000000002", admission: "018f35d4-1f8f-7e2a-9e56-7a5e8a9f1102",
};
const ed = createPrivateKey({ key: Buffer.concat([hex("302e020100300506032b657004220420"), Buffer.alloc(32, 1)]), format: "der", type: "pkcs8" });
const accountRoot = createPublicKey(ed).export({ format: "der", type: "spki" }).subarray(-32);
const hierarchy = JSON.parse(await readFile(new URL("vectors/account-hierarchy.json", root), "utf8")).vectors;
const crypto = JSON.parse(await readFile(new URL("vectors/crypto.json", root), "utf8")).vectors;
const artifact = (kind, index) => hex(hierarchy.find(v => v.kind === kind).input.split("|")[index]);
const wrap = artifact("crypto.hierarchy.device-ark-open", 3);
const rootSigning = artifact("crypto.hierarchy.account-signing-open", 3), rootKem = artifact("crypto.hierarchy.account-kem-open", 3);
const personalWrap = artifact("crypto.hierarchy.personal-vault-open", 4);
const recovery = hex(crypto.find(v => v.kind === "crypto.recovery-blob").expected);
function p256(seed) {
  const scalar = Buffer.alloc(32, seed), ecdh = createECDH("prime256v1"); ecdh.setPrivateKey(scalar);
  const point = ecdh.getPublicKey();
  const key = createPrivateKey({ key: { kty: "EC", crv: "P-256", x: b64(point.subarray(1, 33)), y: b64(point.subarray(33)), d: b64(scalar) }, format: "jwk" });
  return { scalar, point, key };
}
const firstSign = p256(2), firstKem = p256(3), secondSign = p256(4), secondKem = p256(5);
function certificate(device, signer, kem) {
  const fields = new Map([[1, uuid(device)], [2, uuid(ids.account)], [3, signer.point], [4, kem.point], [5, "Fixture device"], [6, "test"], [7, 42]]);
  fields.set(8, sign(null, cbor(fields), ed)); return cbor(fields);
}
const firstCert = certificate(ids.first, firstSign, firstKem), secondCert = certificate(ids.second, secondSign, secondKem);
function bundle(revision, wraps) {
  const fields = { revision, device_wraps: wraps.map(device_id => ({ device_id: uuid(device_id), wrapped_ark: wrap })), account_signing_key: rootSigning, account_kem_key: rootKem, recovery_blob: recovery };
  return cbor({ ...fields, signature: sign(null, Buffer.concat([Buffer.from("spl-sync-keys-v1"), cbor(fields)]), ed) });
}
const firstBundle = bundle(1, [ids.first]), secondBundle = bundle(2, [ids.first, ids.second]);
const passwordArk = Buffer.concat([Buffer.from([1]), Buffer.alloc(72, 0x17)]);
const registration = {
  version: 1, operation_id: uuid(ids.operation), origin, username, account_id: uuid(ids.account), personal_vault_id: uuid(ids.vault), device_id: uuid(ids.first),
  account_signing_public_key: accountRoot, account_kem_public_key: Buffer.alloc(32, 8), credential_generation: 1, password_profile: 1,
  password_salt: Buffer.alloc(16, 0x11), verifier: hash(Buffer.alloc(32, 0x12)), password_ark: passwordArk,
  device_certificate: firstCert, key_bundle: firstBundle, personal_epoch: 1, personal_wrapped_key: personalWrap,
};
const snapshot = {
  version: 1, origin, username, account_id: uuid(ids.account), personal_vault_id: uuid(ids.vault), account_signing_public_key: accountRoot,
  account_kem_public_key: Buffer.alloc(32, 8), credential_generation: 1, password_profile: 1, password_salt: registration.password_salt,
  password_ark: passwordArk, key_bundle: firstBundle, certificates: [firstCert], revocations: [],
  personal: { current_epoch: 1, rotation_pending: false, epochs: [{ epoch: 1, wrapped_key: personalWrap }] },
};
const token = Buffer.alloc(32, 0x33), snapshotBytes = cbor(snapshot);
const admission = { version: 1, operation_id: uuid(ids.admission), origin, username, account_id: uuid(ids.account), personal_vault_id: uuid(ids.vault), device_id: uuid(ids.second), credential_generation: 1, snapshot_digest: hash("spl-account-bootstrap-v1", snapshotBytes), capability_digest: hash(token), device_certificate: secondCert, key_bundle: secondBundle };
function add(id, kind, input, expected = "rejected") { vectors.push({ id: `account-admission-${id}`, kind: `account.admission.${kind}`, input, expected }); }
function jsonVector(id, kind, value, expected = value) { add(id, kind, typeof value === "string" ? value : JSON.stringify(value), typeof expected === "string" ? expected : JSON.stringify(expected)); }
function lp16(text) {
  const bytes = Buffer.from(text, "utf8"), size = Buffer.alloc(2);
  size.writeUInt16BE(bytes.length);
  return Buffer.concat([size, bytes]);
}
for (const [name, probeKey, probeOrigin, probeUsername] of [
  ["base", Buffer.alloc(32, 0x44), origin, username],
  ["different-key", Buffer.alloc(32, 0x45), origin, username],
  ["different-origin", Buffer.alloc(32, 0x44), "https://control.example.com:8443", username],
  ["minimum-username", Buffer.alloc(32, 0x44), origin, "0._"],
  ["maximum-username", Buffer.alloc(32, 0x44), "https://[2001:db8::1]", "a".repeat(64)],
]) {
  const derive = label => createHmac("sha256", probeKey).update(Buffer.concat([Buffer.from(label, "ascii"), lp16(probeOrigin), lp16(probeUsername)])).digest();
  jsonVector(`probe-${name}`, "probe", { probe_key: probeKey.toString("hex"), origin: probeOrigin, username: probeUsername }, {
    synthetic_salt: derive("spl-account-synthetic-salt-v1").subarray(0, 16).toString("hex"),
    synthetic_verifier: derive("spl-account-synthetic-verifier-v1").toString("hex"),
    username_admission_identity: derive("spl-account-admission-username-v1").toString("hex"),
  });
}
const attempt = Buffer.alloc(32, 0x21), nonce = Buffer.alloc(32, 0x22);
function request(kind, intent, p, device, signer) {
  const payload = cbor(p), t = Buffer.concat([Buffer.from(kind === "register" ? "spl-account-register-v1" : "spl-account-device-admit-v1"), payload]);
  const signature = sign(null, t, ed), digest = hash(t, signature), lp = Buffer.alloc(2); lp.writeUInt16BE(Buffer.byteLength(origin));
  const proof = Buffer.concat([Buffer.from("spl-account-request-proof-v1"), Buffer.from([kind === "register" ? 1 : 2, intent === "submit" ? 1 : 2]), lp, Buffer.from(origin), attempt, nonce, p.operation_id, uuid(device), digest]);
  const deviceProof = sign("sha256", proof, { key: signer.key, dsaEncoding: "ieee-p1363" });
  if (!verify(null, t, createPublicKey(ed), signature) || !verify("sha256", proof, { key: createPublicKey(signer.key), dsaEncoding: "ieee-p1363" }, deviceProof)) throw new Error("independent proof verification failed");
  // ECDSA uses randomized nonces in OpenSSL; reuse the previous independently verified signature
  // only when every immutable input still matches, keeping regeneration/check deterministic.
  const id = `account-admission-${kind}-${intent}`;
  const previous = previousVectors.find(v => v.id === id && v.kind === `account.admission.${kind}.request`);
  let stableProof = deviceProof;
  if (previous) { const old = JSON.parse(previous.input); const oldProof = Buffer.from(old.device_proof, "base64url"); if (old.payload === b64(payload) && old.account_signature === b64(signature) && old.attempt_id === b64(attempt) && old.nonce === b64(nonce) && verify("sha256", proof, { key: createPublicKey(signer.key), dsaEncoding: "ieee-p1363" }, oldProof)) stableProof = oldProof; }
  const body = { intent, payload: b64(payload), account_signature: b64(signature), attempt_id: b64(attempt), nonce: b64(nonce), device_proof: b64(stableProof) };
  if (kind === "admit") body.admission_token = intent === "submit" ? b64(token) : null;
  jsonVector(`${kind}-${intent}`, `${kind}.request`, body);
  jsonVector(`${kind}-${intent}-signature-input`, "proof", { kind, intent, origin, attempt_id: attempt.toString("hex"), nonce: nonce.toString("hex"), operation_id: kind === "register" ? ids.operation : ids.admission, device_id: device, request_digest: digest.toString("hex"), signing_scalar: signer.scalar.toString("hex"), signing_public_key: signer.point.toString("hex"), account_public_key: accountRoot.toString("hex"), account_input: t.toString("hex"), account_signature: signature.toString("hex"), device_signature: stableProof.toString("hex") }, proof.toString("hex"));
  return { body, digest, signature };
}
let previousVectors = [];
try { previousVectors = JSON.parse(await readFile(new URL("vectors/account-admission.json", root), "utf8")).vectors; } catch (e) { if (e.code !== "ENOENT") throw e; }
const register = request("register", "submit", registration, ids.first, firstSign);
request("register", "confirm", registration, ids.first, firstSign);
const admit = request("admit", "submit", admission, ids.second, secondSign);
request("admit", "confirm", admission, ids.second, secondSign);
for (const [name, data] of [["registration", registration], ["admission", admission], ["snapshot", snapshot]]) {
  add(`${name}-protected`, `${name}.cbor`, cbor(data).toString("hex"), cbor(data).toString("hex"));
  for (const [id, bad] of [["unknown", { ...data, extra: 1 }], ["version", { ...data, version: 2 }], ["generation-zero", { ...data, credential_generation: 0 }], ["origin", { ...data, origin: `${origin}/` }], ["username", { ...data, username: "Fixture.User" }]]) add(`${name}-${id}`, `${name}.cbor.reject`, cbor(bad).toString("hex"));
  add(`${name}-trailing`, `${name}.cbor.reject`, Buffer.concat([cbor(data), Buffer.from([0])]).toString("hex"));
}
jsonVector("options-request", "options.request", { username });
jsonVector("options-response", "options.response", { attempt_id: b64(attempt), profile: 1, salt: b64(registration.password_salt), expires_at_ms: "1700000120000" });
jsonVector("login-request", "login.request", { attempt_id: b64(attempt), auth_secret: b64(Buffer.alloc(32, 0x12)) });
jsonVector("login-response", "login.response", { admission_token: b64(token), expires_at_ms: "1700000300000", snapshot: b64(snapshotBytes) });
for (const kind of ["register", "admit"]) for (const intent of ["submit", "confirm"]) jsonVector(`challenge-${kind}-${intent}`, "challenge.request", { kind, intent, operation_id: kind === "register" ? ids.operation : ids.admission, device_id: kind === "register" ? ids.first : ids.second });
jsonVector("challenge-response", "challenge.response", { attempt_id: b64(attempt), nonce: b64(nonce), expires_at_ms: "1700000120000" });
for (const [kind, result, operation, device, revision] of [["register", register, ids.operation, ids.first, "1"], ["admit", admit, ids.admission, ids.second, "2"]]) jsonVector(`${kind}-confirmation`, "confirmation", { outcome: "committed", kind, operation_id: operation, request_digest: b64(result.digest), account_id: ids.account, personal_vault_id: ids.vault, device_id: device, admitted_key_revision: revision });
for (const [name, raw] of [["duplicate", '{"username":"fixture.user","username":"fixture.user"}'], ["escaped-duplicate", '{"username":"fixture.user","user\\u006eame":"fixture.user"}'], ["nested-duplicate", '{"username":"fixture.user","extra":{"a":1,"a":2}}'], ["unknown", '{"username":"fixture.user","extra":null}'], ["uppercase", '{"username":"Fixture.User"}'], ["numeric", '{"username":1}'], ["bom", '\ufeff{"username":"fixture.user"}']]) add(`options-${name}`, "options.request.reject", raw);
for (const [name, bad] of [["numeric-expiry", { expires_at_ms: 1700000120000 }], ["leading-zero", { expires_at_ms: "01700000120000" }], ["zero", { expires_at_ms: "0" }], ["overflow", { expires_at_ms: "18446744073709551616" }], ["profile", { profile: 2 }], ["padded", { attempt_id: `${b64(attempt)}=` }]]) jsonVector(`options-response-${name}`, "options.response.reject", { attempt_id: b64(attempt), profile: 1, salt: b64(registration.password_salt), expires_at_ms: "1700000120000", ...bad }, "rejected");
for (const [name, body] of [["submit-null", { ...admit.body, admission_token: null }], ["confirm-token", { ...admit.body, intent: "confirm" }], ["missing-token", Object.fromEntries(Object.entries(admit.body).filter(([k]) => k !== "admission_token"))]]) jsonVector(`admit-${name}`, "admit.request.reject", body, "rejected");
add("snapshot-digest", "snapshot.digest", snapshotBytes.toString("hex"), admission.snapshot_digest.toString("hex"));
add("capability-digest", "capability.digest", token.toString("hex"), admission.capability_digest.toString("hex"));
// Preallocation regressions: tiny bodies declaring huge nested collections must fail promptly.
for (const key of ["certificates", "revocations", "epochs", "device_wraps"]) add(`declared-${key}`, "snapshot.cbor.reject", Buffer.concat([head(5, 1), cbor(key), hex("9bffffffffffffffff")]).toString("hex"));
outputs.push(["vectors/account-admission.json", Buffer.from(`${JSON.stringify({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2)}\n`)]);
for (const v of vectors) {
  if (v.kind.endsWith(".cbor") || v.kind.endsWith(".cbor.reject")) outputs.push([`fuzz/corpus/api_json/seed-${v.id}`, hex(v.input)]);
  else if (!v.kind.endsWith("proof") && !v.kind.endsWith("digest") && !v.kind.endsWith("probe")) outputs.push([`fuzz/corpus/api_json/seed-${v.id}`, Buffer.from(v.input)]);
}
for (const [kind, body, bound] of [["options", JSON.stringify({ username }), 256], ["challenge", JSON.stringify({ kind: "register", intent: "submit", operation_id: ids.operation, device_id: ids.first }), 512]]) for (const n of [bound, bound + 1]) outputs.push([`fuzz/corpus/api_json/seed-account-${kind}-complete-${n}`, Buffer.from(" ".repeat(n - Buffer.byteLength(body)) + body)]);
for (const [path, expected] of outputs) {
  const url = new URL(path, root);
  if (process.argv.includes("--check")) { const actual = await readFile(url); const normalized = path.endsWith(".json") ? Buffer.from(actual.toString().replaceAll("\r\n", "\n")) : actual; if (!normalized.equals(expected)) throw new Error(`D-128 output is stale: ${path}`); }
  else await writeFile(url, expected);
}
console.log(`validated ${vectors.length} independent D-128 vectors and ${outputs.length - 1} parser seeds`);
