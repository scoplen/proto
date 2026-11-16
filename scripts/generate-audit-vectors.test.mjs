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
});
