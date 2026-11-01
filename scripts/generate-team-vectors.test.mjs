// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("D-136 producer preserves exact independent JSON, secret-free locator and byte bounds", async () => {
  const root = await mkdtemp(join(tmpdir(), "scoplen-team-vectors-"));
  try {
    for (const directory of ["scripts", "vectors", "fuzz/corpus/api_json"]) await mkdir(join(root, directory), { recursive: true });
    const script = "scripts/generate-team-vectors.mjs";
    await copyFile(new URL(script, new URL("../", import.meta.url)), join(root, script));
    const run = (...args) => spawnSync(process.execPath, [join(root, script), ...args], { cwd: root, encoding: "utf8", timeout: 15000 });
    let result = run(); assert.equal(result.status, 0, result.stderr);
    const path = join(root, "vectors/team-membership.json");
    const text = await readFile(path, "utf8");
    const { vectors } = JSON.parse(text);
    assert.equal(vectors.length, 109);
    assert.equal(new Set(vectors.map(v => v.id)).size, vectors.length);
    const create = vectors.find(v => v.id === "team-create-v1");
    assert.deepEqual(Object.keys(JSON.parse(create.expected)), ["invitation_id", "recipient_username", "roles", "password_verifier"]);
    assert.deepEqual(JSON.parse(create.expected).roles, ["administrator", "member"]);
    assert.equal(Buffer.from(JSON.parse(create.expected).password_verifier, "base64url").length, 32);
    const link = vectors.find(v => v.id === "team-link-v1");
    assert.equal(new URL(link.expected).hash.split("&").length, 2);
    assert.equal(link.expected.includes("password"), false);
    for (const [kind, length] of [["create", 4096], ["accept", 256], ["member", 4096], ["dissolved", 512]]) {
      assert.equal((await readFile(join(root, `fuzz/corpus/api_json/seed-team-${kind}-bound-0`))).length, length);
      assert.equal((await readFile(join(root, `fuzz/corpus/api_json/seed-team-${kind}-bound-1`))).length, length + 1);
    }
    result = run("--check"); assert.equal(result.status, 0, result.stderr);
    await writeFile(path, text.replace('"team-create-v1"', '"team-create-drift"'));
    result = run("--check"); assert.notEqual(result.status, 0);
    assert.match(result.stderr, /D-136 output stale/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
