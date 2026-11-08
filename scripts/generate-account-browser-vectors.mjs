// SPDX-License-Identifier: Apache-2.0
// Independent Node SHA-256 known answers and D-140 lexical/route examples.
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

const vectors = [];
const add = (id, kind, input, expected = "rejected") => vectors.push({ id: `account-browser-${id}-v1`, kind: `account.browser.${kind}`, input: typeof input === "string" ? input : JSON.stringify(input), expected: typeof expected === "string" ? expected : JSON.stringify(expected) });
const bytes = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const access = `ab1_${bytes.toString("base64url")}`, refresh = `ar1_${bytes.toString("base64url")}`;
for (const [kind, token, domain] of [["access", access, "spl-account-browser-access-v1"], ["refresh", refresh, "spl-account-browser-refresh-v1"]]) {
  add(`${kind}-digest`, `${kind}.digest`, token, createHash("sha256").update(domain, "ascii").update(Buffer.from([0])).update(token, "ascii").digest("hex"));
  for (const [name, value] of [["padding", `${token}=`], ["short", token.slice(0, -1)], ["long", `${token}A`], ["wrong-profile", kind === "access" ? refresh : access], ["jwt", "eyJhbGciOiJFZERTQSJ9.e30.c2ln"], ["tail", token.slice(0, -1) + "_"], ["space", ` ${token}`]]) add(`${kind}-${name}`, `${kind}.reject`, value);
}
const options = { attempt_id: bytes.toString("base64url"), profile: 1, salt: bytes.subarray(0, 16).toString("base64url"), expires_at_ms: "1700000120000" };
const login = { attempt_id: options.attempt_id, auth_secret: Buffer.alloc(32, 7).toString("base64url") };
const session = { access_token: access, token_type: "DPoP", expires_in: 600, refresh_expires_in: 2592000 };
for (const [kind, value] of [["options.request", { username: "alice" }], ["options.response", options], ["login.request", login], ["login.response", session], ["refresh.request", {}], ["refresh.response", { ...session, refresh_expires_in: 123 }], ["logout.request", {}], ["logout.response", { revoked: true }]]) {
  add(`${kind}-valid`, kind, value, value);
  add(`${kind}-duplicate`, `${kind}.reject`, JSON.stringify(value).replace(/}$/, ',"duplicate":{"x":1,"x":2}}'));
  add(`${kind}-trailing`, `${kind}.reject`, `${JSON.stringify(value)}{}`);
}
for (const kind of ["login.response", "refresh.response"]) {
  add(`${kind}-extensions`, kind, { ...session, extra: { safe: true } }, session);
  for (const field of ["refresh_token", "admission_token", "snapshot"]) for (const [label, value] of [["null", null], ["string", ""], ["object", {}]]) add(`${kind}-${field}-${label}`, `${kind}.reject`, { ...session, [field]: value });
  for (const [field, value] of [["expires_in", 599], ["expires_in", 601], ["refresh_expires_in", 0], ["refresh_expires_in", 2592001], ["access_token", refresh]]) add(`${kind}-${field}-${value}`, `${kind}.reject`, { ...session, [field]: value });
}
add("login-response-short-family", "login.response.reject", { ...session, refresh_expires_in: 123 });
add("logout-false", "logout.response.reject", { revoked: false });
add("logout-extension", "logout.response.reject", { revoked: true, extra: null });
add("options-extension", "options.response", { ...options, extra: 1 }, options);
add("options-request-field", "options.request.reject", { username: "alice", family_id: "chosen" });
add("login-request-field", "login.request.reject", { ...login, device_id: "chosen" });
add("scope", "scope", "initial", "account:read inventory:read inventory:write orgs:create orgs:read orgs:write policies:read policies:write teams:join teams:manage");
const operation = (method, path, scopes, writerReceipt = false) => add(`operation-${vectors.length}`, "operation", { method, path }, { scopes, writerReceipt });
operation("GET", "/api/v1/accounts/me", ["account:read"]);
for (const [method, suffix, scopes] of [["POST", "", ["orgs:create"]], ["GET", "", ["orgs:read"]], ["GET", "/{org}", ["orgs:read"]], ["PATCH", "/{org}", ["orgs:write"]]]) operation(method, `/api/v1/orgs${suffix}`, scopes);
for (const [method, path, scopes] of [["GET", "invitations", ["teams:manage"]], ["POST", "invitations", ["teams:manage"]], ["GET", "invitations/{invitation}", ["teams:join", "teams:manage"]], ["DELETE", "invitations/{invitation}", ["teams:manage"]], ["POST", "invitations/{invitation}/accept", ["teams:join"]], ["GET", "members", ["teams:manage"]], ["GET", "members/{membership}", ["teams:manage"]], ["PATCH", "members/{membership}", ["teams:manage"]], ["DELETE", "members/{membership}", ["teams:join", "teams:manage"]], ["POST", "dissolve", ["teams:manage"]]]) operation(method, `/api/v1/orgs/{org}/${path}`, scopes);
for (const kind of ["hosts", "host-groups", "access-profiles", "routes", "groups", "policies"]) for (const [method, suffix] of [["GET", ""], ["POST", ""], ["GET", "/{id}"], ["PUT", "/{id}"], ["DELETE", "/{id}"]]) {
  const scope = kind === "groups" ? method === "GET" ? "policies:read" : "teams:manage" : kind === "policies" ? method === "GET" ? "policies:read" : "policies:write" : method === "GET" ? "inventory:read" : "inventory:write";
  operation(method, `/api/v1/orgs/{org}/${kind}${suffix}`, [scope], method === "POST");
}
add("operation-logout", "operation.logout", { method: "POST", path: "/api/v1/auth/accounts/browser/logout" }, "self-session-termination");
for (const [method, path] of [["GET", "/api/v1/accounts/me/devices"], ["GET", "/sync/v1/keys"], ["POST", "/api/v1/orgs/{org}/certificates"], ["POST", "/api/v1/auth/operator/logout"], ["POST", "/api/v1/orgs/{org}/trust-records"], ["GET", "/api/v1/orgs/{org}/snippets"], ["GET", "/api/v1/orgs/{org}/gateway-networks"], ["GET", "/api/v1/admin/accounts"], ["GET", "/api/v1/orgs/"], ["get", "/api/v1/accounts/me"]]) add(`operation-denied-${vectors.length}`, "operation.reject", { method, path });
add("writer", "writer", { account_id: "0191d3e0-8000-7000-8000-000000000001", family_id: "0191d3e0-8000-7000-8000-000000000002" }, { kind: "account-browser", origin: "0191d3e0-8000-7000-8000-000000000002" });
const output = `${JSON.stringify({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2)}\n`;
const outputs = [["vectors/account-browser.json", output]];
for (const [kind, limit] of [["options.request", 256], ["options.response", 1024], ["login.request", 512], ["login.response", 8192], ["refresh.request", 256], ["refresh.response", 8192], ["logout.request", 256], ["logout.response", 256]]) {
  const body = vectors.find(vector => vector.kind === `account.browser.${kind}`).input;
  for (const [label, size] of [["exact", limit], ["overflow", limit + 1]]) outputs.push([`fuzz/corpus/api_json/seed-account-browser-${kind}-${label}`, " ".repeat(size - body.length) + body]);
}
for (const vector of vectors.filter(vector => ["access.digest", "refresh.digest", "access.reject", "refresh.reject"].some(kind => vector.kind === `account.browser.${kind}`))) outputs.push([`fuzz/corpus/api_json/seed-${vector.id}`, vector.input]);
for (const id of ["login.response-duplicate", "login.response-snapshot-null", "login.response-expires_in-601"]) {
  const vector = vectors.find(vector => vector.id === `account-browser-${id}-v1`);
  outputs.push([`fuzz/corpus/api_json/seed-${vector.id}`, vector.input]);
}
for (const [path, expected] of outputs) {
  const url = new URL(`../${path}`, import.meta.url);
  if (process.argv.includes("--check")) {
    const actual = await readFile(url, "utf8");
    if ((path.endsWith(".json") ? actual.replaceAll("\r\n", "\n") : actual) !== expected) throw new Error(`D-140 output is stale: ${path}`);
  } else await writeFile(url, expected);
}
console.log(`validated ${vectors.length} independent Account browser vectors`);
