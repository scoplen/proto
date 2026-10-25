// SPDX-License-Identifier: Apache-2.0
// Independent D-124 JSON examples and complete-body parser boundaries.
import { readFile, writeFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const vectors = [];
function vector(id, kind, input, expected = "rejected") {
  vectors.push({ id: `operator-logout-${id}-v1`, kind: `operator.logout.${kind}`, input, expected });
}
vector("request", "request", "{}", "{}");
vector("request-whitespace", "request", " \n { }\t", "{}");
vector("response", "response", '{"revoked":true}', '{"revoked":true}');
vector("response-whitespace", "response", '{ "revoked" : true }', '{"revoked":true}');
for (const [id, input] of [
  ["body-null", "null"], ["body-array", "[]"], ["body-trailing", "{}{}"],
  ["body-family", '{"sid":"another-family"}'], ["body-refresh", '{"refresh_token":"fixture-only"}'],
  ["body-duplicate", '{"x":{"y":1,"y":2}}'],
]) vector(id, "request.reject", input);
for (const [id, input] of [
  ["missing", "{}"], ["false", '{"revoked":false}'], ["number", '{"revoked":1}'],
  ["string", '{"revoked":"true"}'], ["duplicate", '{"revoked":true,"revoked":true}'],
  ["escaped-duplicate", '{"revoked":true,"rev\\u006fked":true}'],
  ["extra", '{"revoked":true,"extra":null}'],
]) vector(id, "response.reject", input);
for (const [id, method, path, expected] of [
  ["route", "POST", "/api/v1/auth/operator/logout", "self-session-termination"],
  ["invitation", "POST", "/api/v1/admin/personal-invitations", "unmapped"],
  ["method", "GET", "/api/v1/auth/operator/logout", "unmapped"],
  ["route-case", "post", "/api/v1/auth/operator/logout", "unmapped"],
  ["route-slash", "POST", "/api/v1/auth/operator/logout/", "unmapped"],
  ["route-query", "POST", "/api/v1/auth/operator/logout?sid=other", "unmapped"],
]) vector(id, "operation", JSON.stringify({ method, path }), expected);
for (const [id, status, code, changed, retryable] of [
  ["known-rollback", 503, "auth.storage_unavailable", false, true],
  ["unknown-commit", 503, "auth.commit_outcome_unknown", true, true],
  ["authentication-required", 401, "auth.authentication_required", false, false],
]) {
  const fields = { status, code, changed, retryable };
  // Keep vector spelling stable; problem objects have no canonical JSON key order.
  const expected = JSON.stringify(Object.fromEntries(Object.entries(fields).sort(([a], [b]) => a.localeCompare(b))));
  vector(id, "problem", id, expected);
}

const outputs = [["vectors/operator-logout.json", `${JSON.stringify({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2)}\n`]];
for (const [kind, body] of [["request", "{}"], ["response", '{"revoked":true}']]) {
  for (const [bound, size] of [["exact", 256], ["oversized", 257]]) {
    outputs.push([`fuzz/corpus/api_json/seed-operator-logout-${kind}-${bound}`, " ".repeat(size - body.length) + body]);
  }
}
for (const [path, expected] of outputs) {
  const url = new URL(path, root);
  if (process.argv.includes("--check")) {
    const actual = await readFile(url, "utf8");
    const normalized = path.endsWith(".json") ? actual.replaceAll("\r\n", "\n") : actual;
    if (normalized !== expected) throw new Error(`D-124 output is stale: ${path}`);
  } else await writeFile(url, expected);
}
console.log(`validated ${vectors.length} Operator logout vectors and four parser bounds`);
