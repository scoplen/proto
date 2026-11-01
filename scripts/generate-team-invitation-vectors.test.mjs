// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("D-136 producer preserves independent verifier bindings and detects fixture drift", async () => {
  const root = await mkdtemp(join(tmpdir(), "scoplen-team-invitation-vectors-"));
  try {
    for (const directory of ["scripts", "vectors", "fuzz/corpus/crypto_decoders"]) await mkdir(join(root, directory), { recursive: true });
    const script = "scripts/generate-team-invitation-vectors.mjs";
    await copyFile(new URL(script, new URL("../", import.meta.url)), join(root, script));
    const run = (...args) => spawnSync(process.execPath, [join(root, script), ...args], { cwd: root, encoding: "utf8", timeout: 15000 });
    let result = run(); assert.equal(result.status, 0, result.stderr);
    const output = join(root, "vectors/team-invitation.json");
    const text = await readFile(output, "utf8");
    const { vectors } = JSON.parse(text);
    assert.equal(vectors.length, 34);
    assert.equal(new Set(vectors.map(vector => vector.id)).size, vectors.length);
    const accepted = vectors.filter(vector => vector.kind === "crypto.team-invitation.verifier" && vector.expected !== "reject");
    assert.equal(accepted.length, 11);
    assert.equal(new Set(accepted.map(vector => vector.expected)).size, accepted.length);
    assert.equal(JSON.parse(accepted.find(vector => vector.id === "team-invitation-base").input).password_hex, Buffer.from("0123WXYZ").toString("hex"));
    assert.equal(vectors.find(vector => vector.id === "team-invitation-password-alias-o").expected, "reject");
    await writeFile(output, text.replaceAll("\n", "\r\n"));
    result = run("--check"); assert.equal(result.status, 0, result.stderr);
    await writeFile(output, text.replace('"expected": "accept"', '"expected": "reject"'));
    result = run("--check"); assert.notEqual(result.status, 0);
    assert.match(result.stderr, /D-136 invitation output is stale: vectors\/team-invitation.json/);
    await writeFile(output, text);
    const seed = join(root, "fuzz/corpus/crypto_decoders/seed-team-invitation-password-newline");
    const bytes = await readFile(seed);
    assert.equal(bytes.toString("utf8"), "0123456\n");
    await writeFile(seed, Buffer.concat([bytes, Buffer.from("\r\n")]));
    result = run("--check"); assert.notEqual(result.status, 0);
    assert.match(result.stderr, /D-136 invitation output is stale: fuzz\/corpus\/crypto_decoders\/seed-team-invitation-password-newline/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
