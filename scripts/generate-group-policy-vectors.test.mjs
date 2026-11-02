// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("D-137 group/policy producer independently fixes sorted typed rules and checkout bytes", async () => {
  const root = await mkdtemp(join(tmpdir(), "scoplen-group-policy-vectors-"));
  try {
    for (const directory of ["scripts", "vectors", "fuzz/corpus/api_json"]) await mkdir(join(root, directory), { recursive: true });
    const script = "scripts/generate-group-policy-vectors.mjs";
    await copyFile(new URL(script, new URL("../", import.meta.url)), join(root, script));
    const run = (...args) => spawnSync(process.execPath, [join(root, script), ...args], { cwd: root, encoding: "utf8", timeout: 15000 });
    let result = run(); assert.equal(result.status, 0, result.stderr);
    const path = join(root, "vectors/group-policy.json");
    const text = await readFile(path, "utf8"); const { vectors } = JSON.parse(text);
    assert.equal(new Set(vectors.map(value => value.id)).size, vectors.length);
    const view = vectors.find(value => value.id === "group-policy-source-all-inventory-types-v1");
    for (const type of ["Host", "AccessProfile", "Route", "HostGroup", "TrustRecord", "Snippet", "GatewayNetwork"]) assert.match(view.expected, new RegExp(`resource is ${type} && \\[${type}::`));
    assert.doesNotMatch(view.expected, /Credential::|context.now/);
    const connect = vectors.find(value => value.id === "group-policy-source-group-connect-v1");
    assert.match(connect.expected, /context.membership.groups.contains\(Group::/);
    assert.match(connect.expected, /resource.host_groups.contains\(HostGroup::/);
    assert.doesNotMatch(connect.expected, /Action::"view_inventory"/);
    assert.equal(vectors.find(value => value.id === "group-policy-profile-view-forbid-time-v1").expected, "rejected");
    assert.equal(vectors.find(value => value.id === "group-policy-profile-connect-time-v1").expected, "accepted");
    await writeFile(path, text.replaceAll("\n", "\r\n"));
    result = run("--check"); assert.equal(result.status, 0, result.stderr);
    const seed = join(root, "fuzz/corpus/api_json/seed-group-policy-source-member-view-v1");
    await writeFile(seed, (await readFile(seed, "utf8")) + "\r\n");
    result = run("--check"); assert.notEqual(result.status, 0); assert.match(result.stderr, /D-137 output stale/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
