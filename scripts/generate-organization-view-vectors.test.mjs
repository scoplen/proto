// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("Organization view producer fixes independent CBOR, exact bounds and checked-in corpus", async () => {
  const root = await mkdtemp(join(tmpdir(), "scoplen-organization-view-vectors-"));
  try {
    for (const directory of ["scripts", "vectors", "fuzz/corpus/sync_data", "fuzz/corpus/sync_control", "fuzz/corpus/sync_notification"])
      await mkdir(join(root, directory), { recursive: true });
    const source = new URL("../", import.meta.url);
    const script = "scripts/generate-organization-view-vectors.mjs";
    await copyFile(new URL(script, source), join(root, script));
    await copyFile(new URL("vectors/sync-session.json", source), join(root, "vectors/sync-session.json"));
    const run = (...args) => spawnSync(process.execPath, [join(root, script), ...args], { cwd: root, encoding: "utf8", timeout: 15000 });
    let result = run(); assert.equal(result.status, 0, result.stderr);
    const path = join(root, "vectors/organization-view.json");
    const text = await readFile(path, "utf8");
    const { vectors } = JSON.parse(text);
    assert.equal(vectors.length, 65);
    assert.equal(new Set(vectors.map(vector => vector.id)).size, 65);
    const find = name => vectors.find(vector => vector.id === `organization-view-${name}-v1`);
    assert.equal(find("ack_request-maximum").input.length / 2, 40);
    assert.equal(find("query-maximum").input.length, 67);
    assert.equal(find("page-extension").expected, find("page").expected);
    const memberships = Buffer.from(find("memberships").input, "hex");
    assert.equal(memberships[0], 0xa1);
    assert.equal(memberships.subarray(2, -1).toString(), "memberships_changed");
    for (const [name, directory, selector] of [["page", "sync_data", 18], ["session", "sync_control", 1], ["revision-changed", "sync_data", 16]]) {
      const seed = await readFile(join(root, `fuzz/corpus/${directory}/seed-organization-view-${name}-v1`));
      assert.equal(seed[0], selector);
      assert.equal(seed.subarray(1).toString("hex"), find(name).input);
    }
    result = run("--check"); assert.equal(result.status, 0, result.stderr);
    await writeFile(path, text.replace("organization-view-page-v1", "organization-view-drift"));
    result = run("--check"); assert.notEqual(result.status, 0); assert.match(result.stderr, /D-137 output stale/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
