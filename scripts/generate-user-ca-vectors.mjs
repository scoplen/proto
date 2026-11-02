// SPDX-License-Identifier: Apache-2.0
// Independent D-137 public user-CA examples; no Rust implementation or generated schema is read.
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const id = n => `019bdad6-b800-7000-8000-${n.toString(16).padStart(12, "0")}`;
const sshString = bytes => {
  const length = Buffer.alloc(4); length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
};
// RFC 8032 section 7.1 test 1's public key, independently wrapped in RFC 4253 strings.
const ed25519 = Buffer.from("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "hex");
const blob = Buffer.concat([sshString(Buffer.from("ssh-ed25519")), sshString(ed25519)]);
const publicKey = `ssh-ed25519 ${blob.toString("base64")}`;
const fingerprint = `SHA256:${createHash("sha256").update(blob).digest("base64").replace(/=+$/, "")}`;
const request = { id: id(1), data: { kind: "user", backend: "local" } };
const resource = {
  id: id(1), etag: '"1"', created_at: "2026-11-01T00:00:00Z", updated_at: "2026-11-01T00:00:00.123Z",
  data: { kind: "user", backend: "local", state: "active", public_key: publicKey, fingerprint },
};
const page = { items: [resource], next_cursor: null };
const vectors = [];
const add = (name, kind, input, expected = "rejected") => vectors.push({ id: `user-ca-${name}-v1`, kind: `user_ca.${kind}`, input, expected });
const json = JSON.stringify;
const mutate = (base, fn) => { const changed = structuredClone(base); fn(changed); return json(changed); };
const canonicalResource = json(resource);
add("create", "create", json(request), json(request));
add("create-order", "create", ` { "data": { "backend": "local", "kind": "user" }, "id": "${id(1)}" } `, json(request));
add("create-escaped", "create", json(request).replace('"kind"', '"k\\u0069nd"'), json(request));
for (const [name, change] of [
  ["unknown", r => { r.extra = true; }], ["data-unknown", r => { r.data.private_key = "fixture"; }],
  ["host-kind", r => { r.data.kind = "host"; }], ["remote-backend", r => { r.data.backend = "aws_kms"; }],
  ["state", r => { r.data.state = "active"; }], ["key", r => { r.data.public_key = publicKey; }],
  ["missing-id", r => { delete r.id; }], ["missing-kind", r => { delete r.data.kind; }],
  ["missing-backend", r => { delete r.data.backend; }], ["null-kind", r => { r.data.kind = null; }],
  ["numeric-backend", r => { r.data.backend = 1; }], ["data-array", r => { r.data = []; }],
  ["uuid-case", r => { r.id = r.id.toUpperCase(); }], ["uuid-version", r => { r.id = r.id.replace("7000", "4000"); }],
  ["id-number", r => { r.id = 1; }], ["id-space", r => { r.id += " "; }],
]) add(`create-${name}`, "create.reject", mutate(request, change));
for (const [name, input] of [
  ["duplicate", json(request).replace('"kind":"user"', '"kind":"user","kind":"user"')],
  ["escaped-duplicate", json(request).replace('"kind":"user"', '"kind":"user","k\\u0069nd":"user"')],
  ["extension-duplicate", json(request).slice(0, -1) + ',"extra":{"x":1,"x":2}}'],
  ["bom", '\ufeff' + json(request)], ["trailing", json(request) + '{}'], ["null", 'null'],
]) add(`create-${name}`, "create.reject", input);

add("resource", "resource", canonicalResource, canonicalResource);
add("resource-extensions", "resource", mutate(resource, r => { r.extra = { retained: false }; r.data.future = [1, 2]; }), canonicalResource);
add("resource-order", "resource", json({ data: resource.data, updated_at: resource.updated_at, created_at: resource.created_at, etag: resource.etag, id: resource.id }), canonicalResource);
add("resource-leap-date", "resource", mutate(resource, r => { r.created_at = "2024-02-29T23:59:59Z"; }), mutate(resource, r => { r.created_at = "2024-02-29T23:59:59Z"; }));
for (const [name, change] of [
  ["host-kind", r => { r.data.kind = "host"; }], ["remote-backend", r => { r.data.backend = "pkcs11"; }],
  ["next-state", r => { r.data.state = "next"; }], ["previous-state", r => { r.data.state = "previous"; }],
  ["missing-state", r => { delete r.data.state; }], ["missing-key", r => { delete r.data.public_key; }],
  ["missing-fingerprint", r => { delete r.data.fingerprint; }], ["null-key", r => { r.data.public_key = null; }],
  ["wrong-fingerprint", r => { r.data.fingerprint = 'SHA256:' + 'A'.repeat(43); }],
  ["fingerprint-padding", r => { r.data.fingerprint += '='; }], ["fingerprint-case", r => { r.data.fingerprint = r.data.fingerprint.toLowerCase(); }],
  ["fingerprint-comment", r => { r.data.fingerprint += ' fixture'; }],
  ["hash-line", r => { r.data.fingerprint = 'SHA256:' + createHash('sha256').update(publicKey).digest('base64').replace(/=+$/, ''); }],
  ["hash-bare-key", r => { r.data.fingerprint = 'SHA256:' + createHash('sha256').update(ed25519).digest('base64').replace(/=+$/, ''); }],
  ["key-comment", r => { r.data.public_key += ' fixture'; }], ["key-newline", r => { r.data.public_key += '\n'; }],
  ["key-space", r => { r.data.public_key = ' ' + publicKey; }], ["key-double-space", r => { r.data.public_key = publicKey.replace(' ', '  '); }],
  ["key-tab", r => { r.data.public_key = publicKey.replace(' ', '\t'); }],
  ["key-padding", r => { r.data.public_key += '='; }], ["key-base64url", r => { r.data.public_key = publicKey.replaceAll('+', '-').replaceAll('/', '_'); }],
  ["key-blob-trailing", r => { r.data.public_key = 'ssh-ed25519 ' + Buffer.concat([blob, Buffer.of(0)]).toString('base64'); }],
  ["key-31-bytes", r => { r.data.public_key = 'ssh-ed25519 ' + Buffer.concat([sshString(Buffer.from('ssh-ed25519')), sshString(ed25519.subarray(0,31))]).toString('base64'); }],
  ["key-algorithm-mismatch", r => { r.data.public_key = publicKey.replace('ssh-ed25519 ', 'ssh-rsa '); }],
  ["key-certificate", r => { r.data.public_key = publicKey.replace('ssh-ed25519 ', 'ssh-ed25519-cert-v01@openssh.com '); }],
  ["key-private", r => { r.data.public_key = '-----BEGIN OPENSSH PRIVATE KEY-----'; }],
  ["weak-etag", r => { r.etag = 'W/"1"'; }], ["etag-unquoted", r => { r.etag = '1'; }],
  ["etag-space", r => { r.etag = '"one two"'; }], ["etag-unicode", r => { r.etag = '"é"'; }],
  ["etag-over", r => { r.etag = '"' + 'x'.repeat(255) + '"'; }],
  ["calendar", r => { r.created_at = '2026-02-29T00:00:00Z'; }], ["leap-second", r => { r.updated_at = '2026-11-01T00:00:60Z'; }],
  ["timezone", r => { r.updated_at = '2026-11-01T00:00:00+00:00'; }], ["time-null", r => { r.created_at = null; }],
  ["uuid-case", r => { r.id = r.id.toUpperCase(); }], ["uuid-version", r => { r.id = r.id.replace('7000', '4000'); }],
]) add(`resource-${name}`, "resource.reject", mutate(resource, change));
for (const [name, input] of [
  ["duplicate", canonicalResource.replace('"state":"active"', '"state":"active","state":"active"')],
  ["extension-duplicate", canonicalResource.slice(0, -1) + ',"extra":[{"x":1,"x":2}]}'],
  ["data-extension-duplicate", canonicalResource.replace('"data":{', '"data":{"extra":{"x":1,"x":2},')],
  ["bom", '\ufeff' + canonicalResource], ["trailing", canonicalResource + '{}'],
]) add(`resource-${name}`, "resource.reject", input);
for (const field of ['id', 'etag', 'created_at', 'updated_at', 'data']) add(`resource-missing-${field}`, "resource.reject", mutate(resource, r => { delete r[field]; }));

add("page", "page", json(page), json(page));
add("page-empty", "page", '{"items":[],"next_cursor":null}', '{"items":[],"next_cursor":null}');
add("page-next", "page", json({ ...page, next_cursor: id(1) }), json({ ...page, next_cursor: id(1) }));
add("page-extensions", "page", json({ ...page, extra: { future: true } }), json(page));
const second = structuredClone(resource); second.id = id(2);
add("page-two", "page", json({ items: [resource, second], next_cursor: id(2) }), json({ items: [resource, second], next_cursor: id(2) }));
for (const [name, input] of [
  ["duplicate-id", json({ items: [resource, resource], next_cursor: null })],
  ["descending", json({ items: [second, resource], next_cursor: null })],
  ["next-mismatch", json({ ...page, next_cursor: id(2) })], ["empty-next", json({ items: [], next_cursor: id(1) })],
  ["missing-next", '{"items":[]}'], ["missing-items", '{"next_cursor":null}'], ["items-null", '{"items":null,"next_cursor":null}'],
  ["next-number", json({ ...page, next_cursor: 1 })], ["next-case", json({ ...page, next_cursor: id(1).toUpperCase() })],
  ["nested-duplicate", json(page).slice(0, -1) + ',"extra":{"x":1,"x":2}}'],
]) add(`page-${name}`, "page.reject", input);
for (const [kind, base, bound] of [["create", json(request), 16384], ["resource", canonicalResource, 16384], ["page", '{"items":[],"next_cursor":null}', 1048576]]) {
  for (const extra of [0, 1]) add(`${kind}-bound-${extra}`, "bound", json({ kind, base, bytes: bound + extra }), extra ? "rejected" : "accepted");
}
for (const extra of [0, 1]) add(`page-item-bound-${extra}`, "item-bound", json({ base: canonicalResource, bytes: 16384 + extra }), extra ? "rejected" : "accepted");
for (const count of [500, 501]) add(`page-count-${count}`, "page-count", json({ base: resource, count }), count === 500 ? "accepted" : "rejected");
for (const [suffix, status, code, changed, retryable] of [
  ["invalid", 400, "organization.invalid_request", false, false], ["overflow", 413, "organization.invalid_request", false, false],
  ["not-found", 404, "organization.not_found", false, false], ["conflict", 409, "organization.conflict", false, false],
  ["storage", 503, "organization.storage_unavailable", false, true], ["unknown", 503, "organization.commit_outcome_unknown", true, true],
]) {
  const problem = json({ type: 'about:blank', title: 'Team operation not confirmed', status, detail: 'Retain the original operation and review current authorization.', instance: 'fixture-request', code, changed, retryable });
  add(`problem-${suffix}`, "problem", problem, problem);
}

if (new Set(vectors.map(vector => vector.id)).size !== vectors.length) throw new Error("duplicate D-137 user-CA vector id");
const outputs = [["vectors/user-ca.json", json({ format: 'scoplen-test-vectors', version: 1, vectors }, null, 2) + '\n']];
for (const vector of vectors.filter(v => ['create', 'create.reject', 'resource', 'resource.reject', 'page', 'page.reject', 'problem'].includes(v.kind.slice('user_ca.'.length)))) outputs.push([`fuzz/corpus/api_json/seed-${vector.id}`, vector.input]);
for (const [kind, base] of [["create", json(request)], ["resource", canonicalResource]]) {
  for (const extra of [0, 1]) outputs.push([`fuzz/corpus/api_json/seed-user-ca-${kind}-bound-${extra}`, ' '.repeat(16384 + extra - Buffer.byteLength(base)) + base]);
}
for (const extra of [0, 1]) {
  const expanded = canonicalResource.slice(0, -1) + ' '.repeat(16384 + extra - Buffer.byteLength(canonicalResource)) + '}';
  outputs.push([`fuzz/corpus/api_json/seed-user-ca-page-item-bound-${extra}`, `{"items":[${expanded}],"next_cursor":null}`]);
}
for (const [path, expected] of outputs) {
  const url = new URL(path, root);
  if (process.argv.includes('--check')) {
    const actual = await readFile(url, 'utf8');
    if ((path.endsWith('.json') ? actual.replaceAll('\r\n', '\n') : actual) !== expected) throw new Error(`D-137 user-CA output stale: ${path}`);
  } else await writeFile(url, expected);
}
console.log(`validated ${vectors.length} D-137 user-CA vectors and ${outputs.length - 1} parser seeds`);
