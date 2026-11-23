// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { generateAuthDraftTypes } from "./generate-auth-connection-draft.mjs";
import { generateAuthConnectionTypes } from "./generate-auth-connection.mjs";
import { generateMemberLinkTypes } from "./generate-member-link.mjs";

const doc = JSON.parse(await readFile(new URL("v1.yaml", import.meta.url), "utf8"));
test("D-170 declares eight browser-only link operations with distinct self and withdrawal scopes", () => {
  const root = "/orgs/{org}/auth-link";
  const named = "/orgs/{org}/members/{membership}/auth-link";
  const attempt = root + "/attempts/{attempt}";
  const expected = [
    [root, "get"], [root, "delete"], [root + "/attempts", "post"],
    [attempt, "get"], [attempt, "delete"], [attempt + "/confirm", "post"],
    [named, "get"], [named, "delete"],
  ];
  assert.match(generateMemberLinkTypes(doc), /interface OrganizationSelfLinkStatus/);
  for (const [path, method] of expected) {
    const op = doc.paths[path][method];
    const start = path.endsWith("/attempts"), confirm = path.endsWith("/confirm");
    assert.deepEqual(op.security, [{ accountBrowserAccess: [], dpopProof: [] }]);
    assert.equal(op["x-scoplen-request-max-bytes"], 0);
    assert.equal(op.requestBody, undefined);
    assert.equal(op["x-scoplen-fetch-credentials"], start ? "same-origin" : "omit");
    assert.equal(op.parameters.some(p => p.name === "Idempotency-Key"), confirm);
    assert.equal(op["x-scoplen-original-password-max-age-seconds"], start || confirm ? 300 : undefined);
    assert.equal(op["x-scoplen-required-browser-scope"], path === named ? "auth-links:withdraw" : "auth-links:self");
    assert.deepEqual(op["x-scoplen-required-membership-roles-any"], path === named ? ["owner"] : undefined);
  }
  for (const mutate of [
    d => { d.paths[named].delete["x-scoplen-cedar-action"] = "manage_organization"; },
    d => { delete d.paths[attempt + "/confirm"].post.responses[201].headers.ETag; },
    d => { d.paths[root + "/attempts"].post["x-scoplen-request-max-bytes"] = 512; },
    d => { d.components.schemas.OrganizationLinkAttempt.not.anyOf = []; },
    d => { d.paths[root + "/extra"] = { post: {} }; },
  ]) {
    const changed = structuredClone(doc);
    mutate(changed);
    assert.throws(() => generateMemberLinkTypes(changed), /D-170/);
  }
});

const path = "/orgs/{org}/auth-connection-draft";
test("only the three role- and scope-bound draft operations are published", () => {
  assert.match(generateAuthDraftTypes(doc), /AuthConnectionDraftResource/);
  assert.deepEqual(Object.keys(doc.paths[path]), ["post", "get", "delete"]);
  for (const op of Object.values(doc.paths[path])) {
    assert.deepEqual(op.security, [{ accessToken: [], dpopProof: [] }, { accountBrowserAccess: [], dpopProof: [] }]);
    assert.deepEqual(op["x-scoplen-required-membership-roles-any"], ["owner", "administrator"]);
    assert.equal(op["x-scoplen-cedar-action"], "manage_organization");
    assert.equal(op["x-scoplen-required-device-scope"], "auth-drafts:manage");
    assert.equal(op["x-scoplen-required-browser-scope"], "auth-drafts:manage");
  }
  for (const mutate of [
    d => { delete d.paths[path].delete.parameters[2]; },
    d => { d.paths[path].get.security = []; },
    d => { delete d.paths[path].post.responses["201"].headers.ETag; },
    d => { d.components.schemas.AuthConnectionDraftCreate.properties.data.additionalProperties = true; },
    d => { d.components.schemas.AuthConnectionDraftResource["x-scoplen-max-bytes"]++; },
  ]) {
    const copy = structuredClone(doc);
    mutate(copy);
    assert.throws(() => generateAuthDraftTypes(copy), /D-166/);
  }
});

test("D-167 admits only browser-scope test operations and only start can set a cookie", () => {
  const testPath = `${path}/test-login`;
  const { post } = doc.paths[testPath];
  const { get } = doc.paths[`${testPath}/{attempt}`];
  for (const operation of [post, get]) {
    assert.deepEqual(operation.security, [{ accountBrowserAccess: [], dpopProof: [] }]);
    assert.equal(operation["x-scoplen-required-browser-scope"], "auth-test:run");
    assert.equal(operation["x-scoplen-required-device-scope"], undefined);
    assert.ok(operation.parameters.every(parameter => parameter.name !== "Idempotency-Key"));
  }
  assert.equal(post["x-scoplen-fetch-credentials"], "same-origin");
  assert.match(post.responses[201].headers["Set-Cookie"].description, /__Host-spl-auth-test.*SameSite=Lax/);
  assert.equal(get["x-scoplen-fetch-credentials"], "omit");
  assert.equal(get.responses[200].headers["Set-Cookie"], undefined);
  for (const mutate of [
    d => { d.paths[testPath].post.security.push({ accessToken: [], dpopProof: [] }); },
    d => { d.paths[testPath].post["x-scoplen-fetch-credentials"] = "omit"; },
    d => { delete d.paths[testPath].post.responses[201].headers["Set-Cookie"]; },
    d => { delete d.components.schemas.DraftLoginAttempt.not; },
    d => { d.components.schemas.DraftLoginStarted.properties.status.const = "verified"; },
    d => { d.components.schemas.DraftLoginCredentials.properties.client_secret["x-scoplen-max-utf8-bytes"]++; },
  ]) {
    const copy = structuredClone(doc);
    mutate(copy);
    assert.throws(() => generateAuthDraftTypes(copy), /D-167/);
  }
});

const connection = "/orgs/{org}/auth-connection";
const activations = connection + "/activations";
const item = activations + "/{attempt}";
const transitions = [item + "/confirm", connection + "/suspend"];
const operations = [
  ["get", connection, 200, "AuthConnectionResource"],
  ["post", activations, 201, "AuthConnectionActivationStarted"],
  ["get", item, 200, "AuthConnectionActivation"],
  ["delete", item, 204, null],
  ["post", transitions[0], 200, "AuthConnectionActiveResource"],
  ["post", transitions[1], 200, "AuthConnectionSuspendedResource"],
];

test("D-169 maps six exact Owner operations and only durable transitions have writer receipts", () => {
  assert.match(generateAuthConnectionTypes(doc), /AuthConnectionActivationStarted/);
  const map = doc["x-scoplen-account-browser-operations"].filter(op =>
    op.path === "/api/v1" + connection || op.path.startsWith("/api/v1" + connection + "/"));
  assert.equal(map.length, 6);
  for (const [method, path, status, dto] of operations) {
    const op = doc.paths[path][method];
    const response = op.responses[status];
    const mapped = map.find(row => row.method === method.toUpperCase() && row.path === "/api/v1" + path);
    assert.deepEqual(mapped.scopes, ["auth-connection:manage"]);
    assert.equal(mapped.writerReceipt, transitions.includes(path));
    assert.deepEqual(op.security, [{ accountBrowserAccess: [], dpopProof: [] }]);
    assert.equal(op["x-scoplen-required-device-scope"], undefined);
    assert.deepEqual(op["x-scoplen-required-membership-roles-any"], ["owner"]);
    assert.equal(op["x-scoplen-cedar-action"], "manage_organization");
    assert.equal(op["x-scoplen-required-browser-scope"], "auth-connection:manage");
    assert.equal(op.parameters.find(p => p.name === "Origin").required, method !== "get");
    assert.equal(op.parameters.some(p => p.name === "Idempotency-Key" && p.required), transitions.includes(path));
    assert.equal(op.parameters.some(p => p.in === "query"), false);
    assert.equal(op["x-scoplen-fetch-credentials"], path === activations ? "same-origin" : "omit");
    assert.equal(op["x-scoplen-request-max-bytes"], path === activations ? 4096 : 0);
    assert.equal(op.requestBody !== undefined, path === activations);
    assert.equal(op["x-scoplen-problem-max-bytes"], 4096);
    assert.equal(op["x-scoplen-response-max-bytes"], status === 204 ? 0 : 8192);
    assert.equal(response.headers.ETag !== undefined, path === connection || transitions.includes(path));
    assert.equal(response.headers["Set-Cookie"] !== undefined, path === activations);
    assert.equal(response.content?.["application/json"].schema.$ref, dto ? "#/components/schemas/" + dto : undefined);
    assert.ok(response.headers["X-Request-ID"].required);
    assert.equal(response.headers["Cache-Control"].schema.const, "no-store");
    assert.equal(response.headers.Pragma.schema.const, "no-cache");
  }
  const start = doc.paths[activations].post;
  assert.match(start.responses[201].headers["Set-Cookie"].description, /__Host-spl-auth-activate-<state_digest>.*32 decoded state bytes.*Path=\/; HttpOnly; Secure; SameSite=Lax; no Domain/);
  for (const path of [activations, transitions[0]]) {
    const op = doc.paths[path].post;
    assert.deepEqual(op["x-scoplen-exactly-one-header"], ["If-None-Match", "If-Match"]);
    assert.equal(op["x-scoplen-original-password-max-age-seconds"], 300);
    assert.equal(op.parameters.find(p => p.name === "If-Match").required, false);
    assert.deepEqual(op.parameters.find(p => p.name === "If-None-Match").schema, { type: "string", const: "*" });
  }
  const suspend = doc.paths[transitions[1]].post;
  assert.ok(suspend.parameters.find(p => p.name === "If-Match").required);
  assert.ok(suspend.parameters.every(p => p.name !== "If-None-Match"));
  assert.equal(suspend["x-scoplen-original-password-max-age-seconds"], undefined);
  assert.ok(!doc.paths["/auth/device"].post["x-scoplen-initial-device-scope"].split(" ").includes("auth-connection:manage"));
});

test("D-169 bounds candidates, distinguishes start from status and detects contract drift", () => {
  const schemas = doc.components.schemas;
  const input = schemas.AuthConnectionCandidate;
  assert.deepEqual(input.required, ["draft_generation", "client_id", "client_secret", "space_id"]);
  assert.equal(input.additionalProperties, false);
  for (const name of ["client_id", "client_secret"]) {
    const field = input.properties[name];
    assert.equal(field["x-scoplen-max-utf8-bytes"], 512);
    const text = new RegExp(field.pattern, "u");
    assert.ok(text.test(" exact 秘 "));
    for (const bad of ["", "bad\u0000value", "bad\nvalue", "bad\u0085value"]) assert.ok(!text.test(bad));
  }
  const spaceID = new RegExp(input.properties.space_id.pattern, "u");
  for (const allowed of ["spc_X", "spc_aB0_-", "spc_" + "Z".repeat(92)]) assert.ok(spaceID.test(allowed));
  for (const denied of ["spc_", "SPC_X", "spc_ä", "spc_a/b", "spc_" + "Z".repeat(93)]) assert.ok(!spaceID.test(denied));
  assert.equal(schemas.AuthConnectionActivationStarted.properties.status.const, "pending");
  assert.deepEqual(schemas.AuthConnectionActivation.properties.status.enum, ["pending", "verified", "failed"]);
  assert.deepEqual(schemas.AuthConnectionResource.properties.data.properties.status.enum, ["active", "suspended"]);
  assert.equal(schemas.AuthConnectionActiveResource.allOf[1].properties.data.properties.status.const, "active");
  assert.equal(schemas.AuthConnectionSuspendedResource.allOf[1].properties.data.properties.status.const, "suspended");
  assert.equal(schemas.AuthConnectionActivation.properties.expected_revision.anyOf[1].type, "null");
  const forbidden = s => s.not.anyOf.map(test => test.required[0]);
  for (const s of [schemas.AuthConnectionActivation, schemas.AuthConnectionActivationStarted, schemas.AuthConnectionResource, schemas.AuthConnectionResource.properties.data]) {
    for (const key of ["client_secret", "access_token", "refresh_token", "id_token", "claims"]) assert.ok(forbidden(s).includes(key));
  }
  assert.ok(forbidden(schemas.AuthConnectionActivation).includes("authorization_url"));
  for (const mutate of [
    d => { delete d.paths[item].delete; },
    d => { d.paths[connection + "/activate"] = d.paths[activations]; },
    d => { d.paths[activations].post["x-scoplen-fetch-credentials"] = "omit"; },
    d => { d.paths[activations].post.responses[201].headers["Set-Cookie"].description = "__Host-spl-auth-test"; },
    d => { d.paths[item].get.security = [{ accessToken: [], dpopProof: [] }]; },
    d => { d.paths[transitions[0]].post["x-scoplen-exactly-one-header"].pop(); },
    d => { d.paths[transitions[1]].post.parameters = []; },
    d => { delete d.components.schemas.AuthConnectionActivation.not; },
    d => { d.components.schemas.AuthConnectionResource.properties.data.properties.space_id.pattern = ".*"; },
  ]) {
    const copy = structuredClone(doc);
    mutate(copy);
    assert.throws(() => generateAuthConnectionTypes(copy), /D-169/);
  }
});
