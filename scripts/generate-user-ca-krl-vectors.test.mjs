// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { encodeKrl, krlVectors, PUBLIC_CA } from "./generate-user-ca-krl-vectors.mjs";

test("independent D-141 wire writer freezes exact framing and bounded recipes", () => {
  const vectors = krlVectors();
  assert.equal(new Set(vectors.map(vector => vector.id)).size, vectors.length);
  const find = name => vectors.find(vector => vector.id === `user-ca-krl-${name}-v1`);
  assert.equal(Buffer.from(find("empty").expected, "hex").length, 44);
  const one = Buffer.from(find("one").expected, "hex");
  assert.equal(one.length, 121);
  assert.equal(one.subarray(0, 8).toString(), "SSHKRL\n\0");
  assert.equal(one.readUInt32BE(8), 1);
  assert.equal(one.readBigUInt64BE(12), 1n);
  assert.equal(one.readBigUInt64BE(28), 0n);
  assert.equal(one[44], 1);
  assert.equal(one.readUInt32BE(45), 72);
  assert.equal(one.readUInt32BE(49), 51);
  assert.equal(`ssh-ed25519 ${one.subarray(53, 104).toString("base64")}`, PUBLIC_CA);
  assert.equal(one[108], 0x20);
  assert.equal(one.readUInt32BE(109), 8);
  assert.equal(one.readBigUInt64BE(113), 1n);
  assert.equal(encodeKrl({ serials: Array.from({ length: 100000 }, (_, index) => BigInt(index + 1)) }).length, 800113);
  for (const count of [100000, 100001]) assert.equal(JSON.parse(find(`count-${count}`).input).count, count);
  assert.equal(find("bytes-4194305").expected, "input-too-large");
});

test("producer checks independent output, exact raw seeds and symlinked checkout boundaries", async () => {
  const parent = resolve(tmpdir());
  const temporary = await mkdtemp(join(parent, "scoplen-krl-vectors-"));
  const root = join(temporary, "checkout");
  try {
    for (const directory of ["scripts", "vectors", "fuzz/corpus/api_json"]) await mkdir(join(root, directory), { recursive: true });
    const script = "scripts/generate-user-ca-krl-vectors.mjs";
    await copyFile(new URL(script, new URL("../", import.meta.url)), join(root, script));
    const entry = join(temporary, "linked-checkout");
    await symlink(root, entry, process.platform === "win32" ? "junction" : "dir");
    const run = (...args) => spawnSync(process.execPath, [join(entry, script), ...args], { cwd: root, encoding: "utf8", timeout: 15000 });
    let result = run(); assert.equal(result.status, 0, result.stderr);
    const path = join(root, "vectors/user-ca-krl.json");
    const original = await readFile(path, "utf8");
    const { vectors } = JSON.parse(original);
    for (const vector of vectors.filter(vector => vector.kind === "user_ca.krl.bytes")) {
      assert.deepEqual(await readFile(join(root, `fuzz/corpus/api_json/seed-${vector.id}`)), Buffer.from(vector.expected, "hex"));
    }
    await writeFile(path, original.replaceAll("\n", "\r\n"));
    result = run("--check"); assert.equal(result.status, 0, result.stderr);
    await writeFile(path, original.replace('"expected": "', '"expected": "00'));
    result = run("--check"); assert.notEqual(result.status, 0);
    assert.match(result.stderr, /D-141 KRL output stale: vectors\/user-ca-krl.json/);
    await writeFile(path, original);
    const seed = join(root, "fuzz/corpus/api_json/seed-user-ca-krl-empty-v1");
    await writeFile(seed, Buffer.concat([await readFile(seed), Buffer.from("\n")]));
    result = run("--check"); assert.notEqual(result.status, 0);
    assert.match(result.stderr, /D-141 KRL output stale: fuzz\/corpus\/api_json\/seed-user-ca-krl-empty-v1/);
  } finally {
    assert.equal(dirname(resolve(temporary)), parent);
    assert.ok(temporary.startsWith(join(parent, "scoplen-krl-vectors-")));
    await rm(temporary, { recursive: true, force: true });
  }
});
