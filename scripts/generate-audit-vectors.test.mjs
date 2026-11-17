// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

test("independent D-144 vectors regenerate and retain exact calendar boundaries", async () => {
  execFileSync(process.execPath, [fileURLToPath(new URL("generate-audit-vectors.mjs", import.meta.url)), "--check"]);
  const { vectors } = JSON.parse(await readFile(new URL("../vectors/audit.json", import.meta.url), "utf8"));
  for (const [text, milliseconds] of [["0000-01-01T00:00:00Z", "-62167219200000"], ["1969-12-31T23:59:59.999Z", "-1"], ["9999-12-31T23:59:59.999Z", "253402300799999"]]) {
    assert.equal(vectors.find(v => v.kind === "audit.timestamp" && v.input === text)?.expected, milliseconds);
  }
  assert.equal(vectors.filter(v => v.kind === "audit.checkpoint").length, 5);
  assert.ok(vectors.some(v => v.id === "audit-event-missing-actor_account_id-v1"));
  assert.ok(vectors.some(v => v.id === "audit-event-null-sequence-v1"));
  for (const action of ["created", "updated", "deleted"]) {
    const vector = vectors.find(v => v.id === `audit-grants_${action}-v1`);
    const event = JSON.parse(vector.input);
    assert.equal(event.category, "authorization");
    assert.equal(event.resource.kind, "grant");
    assert.equal(event.event_class, `organization.grants_${action}`);
    assert.equal(vector.expected, vector.input);
  }
  assert.equal(vectors.find(v => v.id === "audit-grant-resource-filter-v1").expected, "accepted");
  for (const kind of ["Grant", "grants", "grant-extra"]) {
    assert.equal(vectors.find(v => v.id === `audit-grant-kind-${kind}-v1`).expected, "rejected");
    assert.equal(vectors.find(v => v.id === `audit-grant-filter-${kind}-v1`).expected, "rejected");
  }
  for (const action of ["created", "approved", "denied", "cancelled", "expired"]) {
    const vector = vectors.find(v => v.id === `audit-access_request_${action}-v1`);
    const event = JSON.parse(vector.input);
    assert.equal(event.category, "authorization");
    assert.equal(event.resource.kind, "access_request");
    assert.equal(vector.expected, vector.input);
    if (action === "expired") {
      assert.equal(event.actor_account_id, null);
      assert.equal(event.actor_browser_family_id, null);
    }
  }
  assert.equal(vectors.find(v => v.id === "audit-access-request-resource-filter-v1").expected, "accepted");
  for (const kind of ["AccessRequest", "access-requests", "access_request_extra"]) {
    assert.equal(vectors.find(v => v.id === `audit-access-request-kind-${kind}-v1`).expected, "rejected");
    assert.equal(vectors.find(v => v.id === `audit-access-request-filter-${kind}-v1`).expected, "rejected");
  }
});
