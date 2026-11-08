// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { encodeKrl } from "./generate-user-ca-krl-vectors.mjs";

test("real OpenSSH queries D-141 serial revocation without revoking a key or another CA", async () => {
  const parent = resolve(tmpdir());
  const root = await mkdtemp(join(parent, "scoplen-krl-openssh-"));
  const run = (...args) => spawnSync("ssh-keygen", args, { cwd: root, encoding: "utf8", timeout: 15000 });
  const success = args => {
    const result = run(...args);
    assert.equal(result.error, undefined, "ssh-keygen must be installed and executable");
    assert.equal(result.status, 0, "fixture OpenSSH command failed");
  };
  try {
    for (const key of ["ca", "other-ca", "subject"]) success(["-q", "-t", "ed25519", "-N", "", "-f", join(root, key)]);
    for (const [name, ca, serial] of [["revoked", "ca", "7"], ["fresh-same-key", "ca", "8"], ["other-ca-equal-serial", "other-ca", "7"]]) {
      success(["-q", "-s", join(root, ca), "-I", "scoplen-krl-fixture", "-n", "fixture", "-V", "-1m:+5m", "-z", serial, join(root, "subject.pub")]);
      await rename(join(root, "subject-cert.pub"), join(root, `${name}.pub`));
    }
    const ca = (await readFile(join(root, "ca.pub"), "utf8")).trim().split(/\s+/).slice(0, 2).join(" ");
    for (const [file, serials] of [["empty.krl", []], ["revoked.krl", ["7"]]]) {
      const bytes = encodeKrl({ ca_public_key: ca, serials });
      await writeFile(join(root, file), bytes);
      for (const certificate of ["revoked", "fresh-same-key", "other-ca-equal-serial"]) {
        const result = run("-Q", "-f", join(root, file), join(root, `${certificate}.pub`));
        assert.equal(result.error, undefined, "ssh-keygen query did not run");
        const revoked = file === "revoked.krl" && certificate === "revoked";
        assert.equal(result.status, revoked ? 1 : 0, `unexpected KRL query outcome: ${file}/${certificate}`);
        if (revoked) assert.match(result.stdout, /REVOKED/);
      }
      const rawKey = run("-Q", "-f", join(root, file), join(root, "subject.pub"));
      assert.equal(rawKey.status, 0, "serial revocation must not revoke the raw subject key");
    }
  } finally {
    assert.equal(dirname(resolve(root)), parent);
    assert.ok(root.startsWith(join(parent, "scoplen-krl-openssh-")));
    await rm(root, { recursive: true, force: true });
  }
});
