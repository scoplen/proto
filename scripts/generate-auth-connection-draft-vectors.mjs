// SPDX-License-Identifier: Apache-2.0
import { readFile, writeFile } from "node:fs/promises";

const id = "0191d3e0-8000-7000-8000-000000000002";
const organization = "0191d3e0-8000-7000-8000-000000000001";
const tag = '"' + id + '"';
const instant = "2026-10-26T00:00:00.123Z";
const issuer = "https://issuer.example/tenant/";
const data = { organization_id: organization, issuer };
const resource = { id, etag: tag, created_at: instant, updated_at: instant, data };
const canonical = value => JSON.stringify(value);
const create = issuer => canonical({ data: { issuer } });
const vectors = [];
function add(name, kind, input, expected = "rejected") {
  vectors.push({ id: "draft-" + name + "-v1", kind: "auth.draft." + kind, input, expected });
}
for (const [name, value] of [
  ["tenant", issuer], ["bare", "https://issuer.example"], ["slash", "https://issuer.example/"],
  ["case-port", "HTTPS://ISSUER.example:443/Case"], ["ipv6", "https://[2001:db8::1]:8443/path/"],
  ["unicode", "https://issuer.example/é"], ["max", "https://example.com/" + "a".repeat(2028)],
]) add(name, "create", create(value), create(value));
add("escaped", "create", ' { "data" : { "issuer": "https://issuer.example/\\u0074enant/" } } ', create(issuer));
for (const [name, value] of [
  ["http", "http://issuer.example/tenant"], ["missing-host", "https:///tenant"],
  ["relative", "/tenant"], ["fragment", issuer + "#"], ["query", issuer + "?"],
  ["empty-user", "https://@issuer.example"], ["user", "https://name@issuer.example"],
  ["password", "https://:value@issuer.example"], ["backslash", issuer + "\\x"],
  ["space", issuer + " x"], ["control", issuer + "\u0000"], ["nonbreaking", issuer + "\u00a0"],
  ["c1-control", issuer + "\u009f"], ["line-separator", issuer + "\u2028"], ["userinfo-port", "https://@:443/"],
  ["port", "https://issuer.example:90000/"], ["oversize", "https://example.com/" + "é".repeat(1015)],
]) add(name, "create", create(value));
for (const [name, field] of [["activation", "active"], ["secret", "client_secret"], ["client", "client_id"], ["account", "account_id"], ["callback", "callback_url"]])
  add(name, "create", canonical({ data: { issuer, [field]: null } }));
add("duplicate", "create", '{"data":{"issuer":"https://one.example/","issuer":"https://two.example/"}}');
add("root-extra", "create", canonical({ data: { issuer }, role: "owner" }));
add("size-exact", "create", create(issuer).padEnd(4096), create(issuer));
add("size-overflow", "create", create(issuer).padEnd(4097));
const read = (body, etag = tag, org = organization, cache = "no-store", pragma = "no-cache") =>
  canonical({ body, etag, organization: org, cache, pragma });
add("generation", "resource", read(canonical(resource)), canonical(resource));
add("extension", "resource", read(canonical({ ...resource, data: { ...data, extra: 1 }, extension: { safe: true } })), canonical(resource));
add("wrong-org", "resource", read(canonical(resource), tag, id));
add("wrong-tag", "resource", read(canonical(resource), '"other"'));
add("weak-tag", "resource", read(canonical(resource), "W/" + tag));
add("wrong-body-tag", "resource", read(canonical({ ...resource, etag: '"other"' }), '"other"'));
add("wrong-time", "resource", read(canonical({ ...resource, updated_at: "2026-10-26T00:00:00Z" })));
add("wrong-generation", "resource", read(canonical({ ...resource, id: organization })));
add("cache", "resource", read(canonical(resource), tag, organization, "public"));
add("missing-pragma", "resource", read(canonical(resource), tag, organization, "no-store", null));
add("nested-duplicate", "resource", read(canonical(resource).replace(/}$/, ',"ext":{"x":1,"x":2}}')));
add("resource-exact", "resource", read(canonical(resource).padEnd(8192)), canonical(resource));
add("resource-overflow", "resource", read(canonical(resource).padEnd(8193)));
const printable = text => text.replaceAll("\u009f", "\\u009f").replaceAll("\u2028", "\\u2028");
const expected = printable(JSON.stringify({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2)) + "\n";
const outputs = [["vectors/auth-connection-draft.json", expected]];
for (const name of ["tenant", "duplicate", "c1-control", "generation", "nested-duplicate"]) {
  const vector = vectors.find(v => v.id === "draft-" + name + "-v1");
  const seed = vector.kind === "auth.draft.resource" ? JSON.parse(vector.input).body : vector.input;
  outputs.push(["fuzz/corpus/api_json/seed-" + vector.id, printable(seed)]);
}
for (const [file, contents] of outputs) {
  const path = new URL("../" + file, import.meta.url);
  if (process.argv.includes("--check")) {
    const actual = await readFile(path, "utf8");
    if ((file.endsWith(".json") ? actual.replaceAll("\r\n", "\n") : actual) !== contents)
      throw new Error("D-166 output is stale: " + file);
  } else await writeFile(path, contents);
}
console.log("validated " + vectors.length + " Organization draft vectors");
