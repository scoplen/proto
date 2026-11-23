// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { accessRequestDefinitions, generateAccessRequestTypes } from "./generate-access-requests.mjs";
import { accountBrowserOperations, initialAccountBrowserScope } from "./generate-account-browser.mjs";
import { initialTeamDeviceScope } from "./generate-team.mjs";

const authored = JSON.parse(await readFile(new URL("v1.yaml", import.meta.url), "utf8"));
const collection = "/orgs/{org}/access-requests", item = `${collection}/{id}`;
const check = `${collection}/check`, decisions = `${item}/decisions`, cancel = `${item}/cancel`;

test("D-150 has exactly six typed operations without provisional edits, deletes or aliases", async () => {
  const output = generateAccessRequestTypes(authored);
  const registry = await readFile(new URL("types.ts", import.meta.url), "utf8");
  const index = await readFile(new URL("index.ts", import.meta.url), "utf8");
  assert.deepEqual(Object.keys(authored.paths).filter(path => path.startsWith(collection)).sort(), [collection, item, check, decisions, cancel].sort());
  assert.deepEqual(Object.keys(authored.paths[collection]), ["get", "post"]);
  assert.deepEqual(Object.keys(authored.paths[item]), ["get"]);
  for (const path of [check, decisions, cancel]) assert.deepEqual(Object.keys(authored.paths[path]), ["post"]);
  for (const name of ["AccessRequest", "AccessDecision", "DecisionRequest"]) {
    assert.equal(authored.components.schemas[name], undefined);
    assert.doesNotMatch(registry, new RegExp(`(?:interface ${name} \\{|^    ${name}:)`, "m"));
  }
  for (const name of [...Object.keys(accessRequestDefinitions().schemas), "AccessRequestListQuery"]) {
    assert.match(index, new RegExp(`^  ${name},$`, "m"));
    if (name !== "AccessRequestListQuery") assert.match(registry, new RegExp(`^    ${name}: ${name};$`, "m"));
  }
  assert.match(output, /view: AccessRequestView; limit\?: number; cursor\?: string/);
  assert.match(output, /decision: AccessRequestDecision \| null; grant: AccessRequestGrant \| null/);
  assert.match(output, /valid_until: string;/);
});

test("D-150 fixes writable fields, nested response fields, finite times and complete encoded budgets", () => {
  const { schemas, responses, paths } = accessRequestDefinitions();
  const fields = ["host", "remote_user", "duration_seconds", "reason"];
  assert.deepEqual(schemas.AccessRequestFields.required, fields);
  assert.deepEqual(Object.keys(schemas.AccessRequestFields.properties), fields);
  for (const name of ["AccessRequestFields", "AccessRequestCheckRequest", "AccessRequestCreateRequest", "AccessRequestDecisionRequest"]) assert.equal(schemas[name].additionalProperties, false);
  assert.deepEqual(schemas.AccessRequestCheckRequest.required, ["data"]);
  assert.deepEqual(schemas.AccessRequestCreateRequest.required, ["id", "data"]);
  assert.deepEqual(schemas.AccessRequestDecisionRequest.required, ["decision"]);
  assert.deepEqual(schemas.AccessRequestDecisionRequest.properties.decision.enum, ["approve", "deny"]);
  assert.deepEqual(schemas.AccessRequestResource.required, ["id", "etag", "created_at", "updated_at", "data"]);
  assert.deepEqual(schemas.AccessRequestResource.properties.data.required, ["requester_account_id", "requester_membership_id", ...fields, "expires_at", "status", "decision", "grant"]);
  assert.deepEqual(schemas.AccessRequestDecision.required, ["outcome", "actor_account_id", "decided_at"]);
  assert.deepEqual(schemas.AccessRequestGrant.required, ["id", "valid_from", "valid_until"]);
  assert.equal(schemas.AccessRequestGrant.properties.valid_until.type, "string");
  for (const name of ["AccessRequestCheckResponse", "AccessRequestResource", "AccessRequestPage", "AccessRequestDecision", "AccessRequestGrant"]) assert.equal(schemas[name].additionalProperties, true);
  assert.equal(schemas.AccessRequestResource.properties.data.additionalProperties, true);
  for (const name of ["AccessRequestCheckRequest", "AccessRequestCreateRequest", "AccessRequestDecisionRequest", "AccessRequestCheckResponse"]) assert.equal(schemas[name]["x-scoplen-max-bytes"], 4096);
  assert.equal(schemas.AccessRequestResource["x-scoplen-max-bytes"], 8192);
  assert.equal(schemas.AccessRequestPage["x-scoplen-max-bytes"], 4194304);
  assert.equal(schemas.AccessRequestPage.properties.items.maxItems, 500);
  assert.match(schemas.AccessRequestPage.properties.items.description, /original encoded item.*<=8192/);
  assert.equal(schemas.AccessRequestFields.properties.remote_user["x-scoplen-max-utf8-bytes"], 255);
  assert.equal(schemas.AccessRequestFields.properties.reason["x-scoplen-max-utf8-bytes"], 2048);
  assert.match(schemas.AccessRequestFields.properties.reason.description, /non-whitespace.*except LF\/TAB.*without trimming/);
  assert.deepEqual(schemas.AccessRequestFields.properties.duration_seconds, { type: "integer", minimum: 1, maximum: 86400, description: "Requested finite access interval, not a promise of one certificate of this length." });
  assert.match(schemas.AccessRequestResource.description, /expires_at = created_at \+86400 seconds.*exact fractional instant/);
  assert.match(schemas.AccessRequestGrant.description, /valid_from equals floor\(decision.decided_at.*valid_until equals valid_from \+ duration_seconds/);
  assert.match(schemas.AccessRequestResource.description, /deadline independently disables actions/);
  const metadata = new RegExp(schemas.AccessRequestDecision.properties.decided_at.pattern);
  const validity = new RegExp(schemas.AccessRequestGrant.properties.valid_from.pattern);
  assert.ok(metadata.test("2026-11-17T00:00:00.123456789Z"));
  assert.ok(!validity.test("2026-11-17T00:00:00.123456789Z"));
  assert.ok(validity.test("2026-11-17T00:00:00Z"));
  const status = new RegExp(schemas.AccessRequestStatus.pattern);
  assert.ok(status.test("future_pending"));
  assert.ok(!status.test("Future-unknown"));
  assert.equal(schemas.AccessRequestStatus.maxLength, 64);
  assert.match(schemas.AccessRequestStatus.description, /revoked is reserved.*Unknown with no mutation or authority/);
  for (const response of Object.values(responses)) {
    assert.equal(response.headers["Cache-Control"].schema.const, "no-store");
    assert.equal(response.headers.Pragma.schema.const, "no-cache");
    assert.equal(response.headers["X-Request-ID"].required, true);
  }
  assert.equal(responses.AccessRequestResource.headers.ETag.required, true);
  assert.match(responses.AccessRequestResource.headers.ETag.description, /exactly equal to body etag/);
  assert.deepEqual(paths[check].post.parameters.map(p => p.name), ["org"]);
  assert.deepEqual(paths[collection].post.parameters.map(p => p.name), ["org", "Idempotency-Key"]);
  assert.deepEqual(paths[collection].get.parameters.map(p => p.name), ["org", "view", "limit", "cursor"]);
  assert.equal(paths[collection].get.parameters[1].required, true);
  assert.deepEqual(paths[collection].get.parameters[2].schema, { type: "integer", minimum: 1, maximum: 500, default: 50 });
  assert.deepEqual(paths[item].get.parameters.map(p => p.name), ["org", "id"]);
  for (const path of [decisions, cancel]) assert.deepEqual(paths[path].post.parameters.map(p => p.name), ["org", "id", "If-Match", "Idempotency-Key"]);
  assert.equal(paths[cancel].post.requestBody, undefined);
});

test("D-150 registers current Device/browser authority and only three original writer receipts", () => {
  const { paths } = accessRequestDefinitions();
  const browser = accountBrowserOperations().filter(o => o.path.includes("/access-requests"));
  assert.equal(browser.length, 6);
  const prefix = ["access-requests:decide", "access-requests:read", "access-requests:write"];
  for (const scope of [initialAccountBrowserScope, initialTeamDeviceScope]) assert.deepEqual(scope.split(" ").slice(0, 3), prefix);
  assert.equal(initialAccountBrowserScope.split(" ").length, 17);
  assert.equal(initialTeamDeviceScope.split(" ").length, 22);
  for (const [path, methods] of Object.entries(paths)) for (const [method, operation] of Object.entries(methods)) {
    const scope = method === "get" ? "access-requests:read" : path === decisions ? "access-requests:decide" : "access-requests:write";
    assert.equal(operation["x-scoplen-required-device-scope"], scope);
    assert.equal(operation["x-scoplen-required-browser-scope"], scope);
    assert.equal(operation["x-scoplen-fetch-credentials"], "omit");
    assert.equal(operation["x-scoplen-problem-max-bytes"], 4096);
    assert.deepEqual(operation.security, [{ accessToken: [], dpopProof: [] }, { accountBrowserAccess: [], dpopProof: [] }]);
    const registered = browser.find(o => o.method === method.toUpperCase() && o.path === `/api/v1${path}`);
    assert.deepEqual(registered?.scopes, [scope]);
    assert.equal(registered?.writerReceipt, method === "post" && path !== check);
    if (method === "get" || path === check) assert.equal(operation.responses["409"], undefined);
  }
  assert.match(paths[check].post.description, /complete policy Deny returns allowed=false; evaluation\/storage failure remains a problem/);
  assert.match(paths[check].post.description, /schema has no remote_user context/);
  assert.match(paths[collection].get.description, /view=approvals selects only unexpired pending/);
  assert.match(paths[item].get.description, /current requester Account or a caller satisfying current routing/);
  assert.match(paths[decisions].post.description, /including for Owner.*No view_policy/);
  assert.match(paths[decisions].post.description, /exact original active Membership/);
  assert.match(paths[decisions].post.description, /both request-approved\/Grant-created audit/);
  assert.match(paths[collection].post.description, /Historical confirmation.*does not recheck fresh creation eligibility/);
  assert.match(paths[cancel].post.description, /request_access and Host visibility are not required/);
  assert.match(paths[cancel].post.responses["503"].description, /explicit original-key, original-payload and original-If-Match confirmation/);
  for (const path of [decisions, cancel]) {
    assert.ok(paths[path].post.responses["412"]);
    assert.ok(paths[path].post.responses["428"]);
  }
});

test("D-150 exact generation rejects provisional routes and auth, field, time, bound, receipt drift", () => {
  for (const mutate of [
    d => { d.components.schemas.DecisionRequest = {}; },
    d => { d.components.schemas.AccessRequest = {}; },
    d => { d.components.schemas.AccessDecision = {}; },
    d => { d.paths[item].patch = {}; },
    d => { d.paths[item].delete = {}; },
    d => { d.paths[`${item}/decisions/{decision}`] = { get: {} }; },
    d => { delete d.paths[check]; },
    d => { delete d.paths[cancel]; },
    d => { d.components.schemas.AccessRequestFields.additionalProperties = true; },
    d => { d.components.schemas.AccessRequestFields.required.pop(); },
    d => { d.components.schemas.AccessRequestFields.properties.account = { type: "string" }; },
    d => { d.components.schemas.AccessRequestFields.properties.host_groups = { type: "array" }; },
    d => { d.components.schemas.AccessRequestFields.properties.host.pattern = ".*"; },
    d => { d.components.schemas.AccessRequestFields.properties.remote_user["x-scoplen-max-utf8-bytes"]++; },
    d => { d.components.schemas.AccessRequestFields.properties.duration_seconds.maximum++; },
    d => { d.components.schemas.AccessRequestFields.properties.reason["x-scoplen-max-utf8-bytes"]++; },
    d => { d.components.schemas.AccessRequestDecisionRequest.properties.reason = { type: "string" }; },
    d => { d.components.schemas.AccessRequestDecisionRequest.properties.decision.enum.push("revoke"); },
    d => { d.components.schemas.AccessRequestCreateRequest["x-scoplen-max-bytes"]++; },
    d => { d.components.schemas.AccessRequestCheckResponse.properties.allowed.type = "string"; },
    d => { d.components.schemas.AccessRequestStatus.maxLength++; },
    d => { d.components.schemas.AccessRequestResource.properties.data.required.pop(); },
    d => { d.components.schemas.AccessRequestResource["x-scoplen-max-bytes"]++; },
    d => { d.components.schemas.AccessRequestPage["x-scoplen-max-bytes"]++; },
    d => { d.components.schemas.AccessRequestPage.properties.items.maxItems++; },
    d => { d.components.schemas.AccessRequestPage.properties.items.description = "unbounded"; },
    d => { d.components.schemas.AccessRequestDecision.properties.decided_at.pattern = d.components.schemas.AccessRequestGrant.properties.valid_from.pattern; },
    d => { d.components.schemas.AccessRequestGrant.properties.valid_until = { type: ["string", "null"] }; },
    d => { d.components.schemas.AccessRequestGrant.description = "Any equal-length interval"; },
    d => { d.components.schemas.AccessRequestResource.description = "Ignore fractional deadline"; },
    d => { d.paths[collection].get.parameters[1].required = false; },
    d => { d.paths[collection].get.parameters.push({ name: "filter", in: "query" }); },
    d => { d.paths[check].post.parameters.push({ name: "Idempotency-Key", in: "header" }); },
    d => { d.paths[collection].post.parameters.pop(); },
    d => { d.paths[decisions].post.parameters[2].required = false; },
    d => { d.paths[cancel].post.parameters.pop(); },
    d => { d.paths[cancel].post.requestBody = { required: false }; },
    d => { d.paths[decisions].post.responses["503"].content["application/problem+json"].schema.oneOf.pop(); },
    d => { delete d.paths[cancel].post.responses["428"]; },
    d => { delete d.paths[decisions].post.responses["412"]; },
    d => { delete d.paths[check].post.responses["413"]; },
    d => { d.paths[decisions].post["x-scoplen-required-browser-scope"] = "policies:write"; },
    d => { d.paths[check].post["x-scoplen-required-device-scope"] = "inventory:read"; },
    d => { d.paths[item].get.security.pop(); },
    d => { d.paths[collection].get["x-scoplen-fetch-credentials"] = "same-origin"; },
    d => { d.paths[collection].post["x-scoplen-request-max-bytes"]++; },
    d => { d.paths[check].post["x-scoplen-response-max-bytes"]++; },
    d => { delete d.components.responses.AccessRequestResource.headers.ETag; },
    d => { delete d.components.responses.AccessRequestPage.headers.Pragma; },
    d => { delete d.components.responses.AccessRequestCheckResponse.headers["X-Request-ID"]; },
  ]) { const changed = structuredClone(authored); mutate(changed); assert.throws(() => generateAccessRequestTypes(changed), /D-150/); }
});

test("D-150 authored schemas accept every independently generated valid wire-vector shape", async () => {
  const { vectors } = JSON.parse(await readFile(new URL("../../../vectors/access-request.json", import.meta.url), "utf8"));
  const kinds = {
    "access_request.fields": "AccessRequestFields", "access_request.check_request": "AccessRequestCheckRequest",
    "access_request.check_response": "AccessRequestCheckResponse", "access_request.create": "AccessRequestCreateRequest",
    "access_request.decision": "AccessRequestDecisionRequest", "access_request.resource": "AccessRequestResource",
    "access_request.page": "AccessRequestPage",
  };
  function validate(value, schema) {
    if (schema.$ref) return validate(value, authored.components.schemas[schema.$ref.split("/").at(-1)]);
    if (schema.anyOf) {
      assert.ok(schema.anyOf.some(alternative => { try { validate(value, alternative); return true; } catch { return false; } }));
      return;
    }
    if (schema.enum) assert.ok(schema.enum.includes(value));
    if (schema.type === "null") { assert.equal(value, null); return; }
    if (schema.type === "object") {
      assert.ok(value && typeof value === "object" && !Array.isArray(value));
      for (const key of schema.required) assert.ok(Object.hasOwn(value, key), `required ${key}`);
      for (const [key, child] of Object.entries(value)) {
        if (schema.properties[key]) validate(child, schema.properties[key]);
        else assert.equal(schema.additionalProperties, true, `unknown ${key}`);
      }
    } else if (schema.type === "array") {
      assert.ok(Array.isArray(value));
      if (schema.maxItems !== undefined) assert.ok(value.length <= schema.maxItems);
      for (const child of value) validate(child, schema.items);
    } else if (schema.type === "string") {
      assert.equal(typeof value, "string");
      if (schema.pattern) assert.match(value, new RegExp(schema.pattern));
      if (schema.minLength !== undefined) assert.ok([...value].length >= schema.minLength);
      if (schema.maxLength !== undefined) assert.ok([...value].length <= schema.maxLength);
      if (schema["x-scoplen-max-utf8-bytes"]) assert.ok(Buffer.byteLength(value) <= schema["x-scoplen-max-utf8-bytes"]);
    } else if (schema.type === "integer") {
      assert.ok(Number.isInteger(value));
      if (schema.minimum !== undefined) assert.ok(value >= schema.minimum);
      if (schema.maximum !== undefined) assert.ok(value <= schema.maximum);
    } else if (schema.type === "boolean") assert.equal(typeof value, "boolean");
    if (schema["x-scoplen-max-bytes"]) assert.ok(Buffer.byteLength(JSON.stringify(value)) <= schema["x-scoplen-max-bytes"]);
  }
  const seen = new Set();
  for (const vector of vectors.filter(vector => vector.expected !== "rejected")) {
    if (vector.kind === "access_request.query") {
      const query = JSON.parse(vector.expected);
      validate(query.view, authored.components.schemas.AccessRequestView);
      const parameters = authored.paths[collection].get.parameters;
      validate(query.limit, parameters.find(p => p.name === "limit").schema);
      if (query.cursor !== null) validate(query.cursor, parameters.find(p => p.name === "cursor").schema);
    } else {
      assert.ok(kinds[vector.kind], `known vector kind ${vector.kind}`);
      const schema = authored.components.schemas[kinds[vector.kind]];
      validate(JSON.parse(vector.input), schema);
      validate(JSON.parse(vector.expected), schema);
      if (schema["x-scoplen-max-bytes"]) assert.ok(Buffer.byteLength(vector.input) <= schema["x-scoplen-max-bytes"], vector.id);
    }
    seen.add(vector.kind);
  }
  assert.deepEqual([...seen].sort(), [...Object.keys(kinds), "access_request.query"].sort());
});
