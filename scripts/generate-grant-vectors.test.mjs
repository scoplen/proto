// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("D-147 producer fixes exact seconds, explicit null and original parser bytes", async () => {
  const root = await mkdtemp(join(tmpdir(), "scoplen-grant-vectors-"));
  try {
    for (const directory of ["scripts", "vectors", "fuzz/corpus/api_json"]) await mkdir(join(root, directory), { recursive: true });
    const script = "scripts/generate-grant-vectors.mjs";
    await copyFile(new URL(script, new URL("../", import.meta.url)), join(root, script));
    const run = (...args) => spawnSync(process.execPath, [join(root, script), ...args], { cwd: root, encoding: "utf8", timeout: 15000 });
    let result = run(); assert.equal(result.status, 0, result.stderr);
    const path = join(root, "vectors/grant.json");
    const text = await readFile(path, "utf8"); const { vectors } = JSON.parse(text);
    assert.equal(new Set(vectors.map(value => value.id)).size, vectors.length);
    const get = name => vectors.find(value => value.id === `grant-${name}-v1`);
    assert.equal(get("timestamp-2038").expected, "2147483648");
    assert.equal(get("timestamp-maximum").expected, "253402300799");
    assert.equal(get("create-missing-valid_until").expected, "rejected");
    assert.equal(JSON.parse(get("create-nonexpiring").expected).data.valid_until, null);
    assert.equal(JSON.parse(get("create-exact-user").expected).data.remote_user, " e\u0301 ");
    assert.equal(Buffer.byteLength(JSON.parse(get("create-max-user").expected).data.remote_user), 255);
    assert.equal(get("create-nested-extension").expected, "rejected");
    assert.equal(get("resource-nested-extension").expected, get("resource").expected);
    await writeFile(path, text.replaceAll("\n", "\r\n"));
    result = run("--check"); assert.equal(result.status, 0, result.stderr);
    const seed = join(root, "fuzz/corpus/api_json/seed-grant-create-v1");
    await writeFile(seed, (await readFile(seed, "utf8")) + "\r\n");
    result = run("--check"); assert.notEqual(result.status, 0); assert.match(result.stderr, /D-147 output stale/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
