// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { generateAuditTypes } from "./generate-audit.mjs";

const document = JSON.parse(await readFile(new URL("v1.yaml", import.meta.url), "utf8"));

test("D-144 has only two read-only audit routes and immutable sequence schemas", async () => {
  assert.deepEqual(Object.keys(document.paths).filter(path => path.includes("audit-events")).sort(), ["/orgs/{org}/audit-events", "/orgs/{org}/audit-events/verify"]);
  for (const path of ["/orgs/{org}/audit-events", "/orgs/{org}/audit-events/verify"]) {
    assert.deepEqual(Object.keys(document.paths[path]), ["get"]);
    const operation = document.paths[path].get;
    assert.equal(operation["x-scoplen-required-device-scope"], "audit:read");
    assert.equal(operation["x-scoplen-required-browser-scope"], "audit:read");
    assert.equal(operation["x-scoplen-fetch-credentials"], "omit");
    assert.equal(operation.requestBody, undefined);
    assert.deepEqual(operation.security, [{ accessToken: [], dpopProof: [] }, { accountBrowserAccess: [], dpopProof: [] }]);
  }
  assert.equal(document.components.schemas.Verification, undefined);
  assert.ok(document.components.schemas.AuditResource.properties.kind.enum.includes("grant"));
  assert.ok(document.components.schemas.AuditResource.properties.kind.enum.includes("access_request"));
  assert.deepEqual(document.components.schemas.AuditEvent.required, ["organization_id", "sequence", "occurred_at", "category", "event_class", "outcome", "actor_account_id", "actor_device_id", "actor_browser_family_id", "resource", "previous_hash", "event_hash"]);
  assert.deepEqual(document.components.schemas.AuditVerification.required, ["organization_id", "from_sequence", "to_sequence", "checked_events", "valid", "failure_sequence", "previous_hash", "head_hash", "checkpoint", "uncheckpointed_from_sequence"]);
  assert.equal(document.components.schemas.AuditEvent.properties.id, undefined);
  const output = generateAuditTypes(document);
  assert.match(output, /sequence: string/);
  assert.match(output, /checked_events: string/);
  const index = await readFile(new URL("index.ts", import.meta.url), "utf8");
  for (const name of ["AuditEvent", "AuditPage", "AuditListQuery", "AuditRangeQuery", "AuditCheckpoint", "AuditVerification"]) assert.ok(index.includes(name), `public ${name}`);
});

test("D-144 generator rejects syntax, scope, byte, coverage and mutable surface drift", () => {
  for (const mutate of [
    d => { d.paths["/orgs/{org}/audit-events"].post = {}; },
    d => { d.paths["/orgs/{org}/audit-events/{id}"] = { get: {} }; },
    d => { d.components.schemas.Verification = { type: "boolean" }; },
    d => { d.components.schemas.AuditResource.properties.kind.enum = d.components.schemas.AuditResource.properties.kind.enum.filter(kind => kind !== "grant"); },
    d => { d.components.schemas.AuditResource.properties.kind.enum = d.components.schemas.AuditResource.properties.kind.enum.filter(kind => kind !== "access_request"); },
    d => { d.components.schemas.AuditEvent.properties.sequence.type = "number"; },
    d => { d.components.schemas.AuditEvent.required.pop(); },
    d => { d.components.schemas.AuditCheckpoint.properties.signature.maxLength = 88; },
    d => { d.components.schemas.AuditPage["x-scoplen-max-bytes"]++; },
    d => { d.paths["/orgs/{org}/audit-events/verify"].get["x-scoplen-max-original-event-bytes"]++; },
    d => { d.paths["/orgs/{org}/audit-events/verify"].get.parameters.pop(); },
    d => { d.paths["/orgs/{org}/audit-events"].get["x-scoplen-required-device-scope"] = "orgs:read"; },
    d => { d.components.responses.AuditStorageUnavailable.content["application/problem+json"].schema.allOf[1].properties.changed.const = true; },
  ]) { const changed = structuredClone(document); mutate(changed); assert.throws(() => generateAuditTypes(changed), /D-144/); }
});
