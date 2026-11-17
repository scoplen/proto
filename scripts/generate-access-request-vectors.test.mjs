// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("D-150 independent producer freezes exact input, fractional times and original parser bytes", async () => {
  const root = await mkdtemp(join(tmpdir(), "scoplen-access-request-vectors-"));
  try {
    for (const directory of ["scripts", "vectors", "fuzz/corpus/api_json"]) await mkdir(join(root, directory), { recursive: true });
    const script = "scripts/generate-access-request-vectors.mjs";
    await copyFile(new URL(script, new URL("../", import.meta.url)), join(root, script));
    const run = (...args) => spawnSync(process.execPath, [join(root, script), ...args], { cwd: root, encoding: "utf8", timeout: 15000 });
    let result = run(); assert.equal(result.status, 0, result.stderr);
    const path = join(root, "vectors/access-request.json"), text = await readFile(path, "utf8");
    const { vectors } = JSON.parse(text), get = name => vectors.find(value => value.id === `access-request-${name}-v1`);
    assert.equal(new Set(vectors.map(value => value.id)).size, vectors.length);
    assert.equal(get("resource-wrong-grant-start").expected, "rejected");
    assert.equal(get("resource-rounded-deadline").expected, "rejected");
    assert.equal(JSON.parse(get("resource-future_state_2").expected).data.status, "future_state_2");
    assert.equal(JSON.parse(get("fields-exact-reason").expected).reason, "  é\n\tgo  ");
    assert.equal(Buffer.byteLength(JSON.parse(get("fields-max-reason").expected).reason), 2048);
    assert.equal(get("resource-decision-grant-extension").expected, get("resource-approved").expected);
    await writeFile(path, text.replaceAll("\n", "\r\n"));
    result = run("--check"); assert.equal(result.status, 0, result.stderr);
    const seed = join(root, "fuzz/corpus/api_json/seed-access-request-create-v1");
    await writeFile(seed, (await readFile(seed, "utf8")) + "\r\n");
    result = run("--check"); assert.notEqual(result.status, 0); assert.match(result.stderr, /D-150 output stale/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
