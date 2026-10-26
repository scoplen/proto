// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("D-130 producer independently preserves canonical examples and byte bounds", async () => {
  const root = await mkdtemp(join(tmpdir(), "scoplen-organization-vectors-"));
  try {
    for (const directory of ["scripts", "vectors", "fuzz/corpus/api_json"]) await mkdir(join(root, directory), { recursive: true });
    const script = "scripts/generate-organization-vectors.mjs";
    await copyFile(new URL(script, new URL("../", import.meta.url)), join(root, script));
    const run = (...args) => spawnSync(process.execPath, [join(root, script), ...args], { cwd: root, encoding: "utf8", timeout: 15000 });
    let result = run(); assert.equal(result.status, 0, result.stderr);
    const vectorPath = join(root, "vectors/organizations.json");
    const text = await readFile(vectorPath, "utf8");
    const { vectors } = JSON.parse(text);
    assert.equal(vectors.length, 45);
    assert.equal(new Set(vectors.map(vector => vector.id)).size, vectors.length);
    const roles = vectors.find(vector => vector.id === "organization-resource-roles-order-v1");
    assert.deepEqual(JSON.parse(roles.expected).data.membership.roles, ["administrator", "future_reader", "security_auditor"]);
    for (const [kind, bytes] of [["create", 1024], ["resource", 4096]]) {
      for (const extra of [0, 1]) assert.equal((await readFile(join(root, `fuzz/corpus/api_json/seed-organization-${kind}-bound-${extra}`))).byteLength, bytes + extra);
    }
    await writeFile(vectorPath, text.replaceAll("\n", "\r\n"));
    result = run("--check"); assert.equal(result.status, 0, result.stderr);
    const seed = join(root, "fuzz/corpus/api_json/seed-organization-resource-bound-0");
    await writeFile(seed, Buffer.concat([await readFile(seed), Buffer.from("\r\n")]));
    result = run("--check"); assert.notEqual(result.status, 0);
    assert.match(result.stderr, /D-130 output stale: fuzz\/corpus\/api_json\/seed-organization-resource-bound-0/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
