// SPDX-License-Identifier: Apache-2.0
// Synthetic ssh -G fixtures only: no SSH connection, environment-derived User or local config.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import test from "node:test";
import { document, materialize } from "./generate-openssh-import-vectors.mjs";

test("installed OpenSSH independently agrees with representative supported mappings", async t => {
  const probe = spawnSync("ssh", ["-V"], { encoding: "utf8", windowsHide: true });
  assert.equal(probe.status, 0);
  t.diagnostic((probe.stdout + probe.stderr).trim());
  const owned = await mkdtemp(join(tmpdir(), "scoplen-openssh-import-"));
  // Fixed vectors cover numeric spelling; OpenSSH's OS-specific numeric canonicalization
  // is explicitly outside D-153's promise of matching ssh -G output.
  const selected = ["example", "quotes-concatenate", "escaped-space", "global-first", "wildcard-negation"];
  try {
    for (const name of selected) {
      const vector = document.vectors.find(vector => vector.id === `openssh-import-${name}-v1`);
      assert.ok(vector);
      const path = join(owned, `${name}.conf`);
      await writeFile(path, materialize(vector));
      for (const row of JSON.parse(vector.expected).candidates) {
        assert.equal(row.status, "ready");
        const output = execFileSync("ssh", ["-G", "-F", path, row.fields.name], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], windowsHide: true, timeout: 10000 });
        const value = key => output.split(/\r?\n/).find(line => line.startsWith(`${key} `))?.slice(key.length + 1);
        assert.equal(value("hostname"), row.fields.address, `${name}: hostname`);
        assert.equal(value("user"), row.fields.username, `${name}: user`);
        assert.equal(value("port"), String(row.fields.port), `${name}: port`);
      }
    }
  } finally {
    assert.ok(resolve(owned).startsWith(resolve(tmpdir()) + sep));
    await rm(owned, { recursive: true, force: true });
  }
});
