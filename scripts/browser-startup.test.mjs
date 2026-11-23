// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { waitForBrowserPort } from "./browser-startup.mjs";

async function profile(t) {
  const directory = await mkdtemp(join(tmpdir(), "scoplen-port-test-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

function runningChild() {
  return Object.assign(new EventEmitter(), { stderr: new PassThrough(), exitCode: null, signalCode: null });
}

test("waits for a complete port line from the selected profile", async t => {
  const directory = await profile(t);
  const marker = join(directory, "DevToolsActivePort");
  await writeFile(marker, "54");
  const port = waitForBrowserPort(runningChild(), directory, "full");
  await delay(60);
  await writeFile(marker, "54321\r\n/devtools/browser/test-id");
  assert.equal(await port, 54321);
});

test("reports exit code and recognized stderr without exposing raw browser output", async t => {
  const directory = await profile(t);
  const child = spawn(process.execPath, ["-e",
    "process.stderr.write('No usable sandbox! private-detail\\nDevTools listening on ws://example.invalid/private-detail\\n'); process.exitCode = 17",
  ], { stdio: ["ignore", "ignore", "pipe"] });
  await assert.rejects(waitForBrowserPort(child, directory, "full"), {
    message: "Chromium startup failed (full): exited with code 17. no usable sandbox, browser announced DevTools.",
  });
});

test("reports a launch failure without revealing the executable path", async t => {
  const directory = await profile(t);
  const child = spawn(join(directory, "missing-browser"), [], { stdio: ["ignore", "ignore", "pipe"] });
  await assert.rejects(waitForBrowserPort(child, directory, "full"), {
    message: "Chromium startup failed (full): could not launch browser; check CHROME_BIN. No recognized startup diagnostic.",
  });
});

test("distinguishes a signalled process from a live process missing its port file", async t => {
  const directory = await profile(t);
  const signalled = runningChild();
  signalled.signalCode = "SIGTERM";
  await assert.rejects(waitForBrowserPort(signalled, directory, "randomness"), /terminated by SIGTERM/u);
  await assert.rejects(waitForBrowserPort(runningChild(), directory, "resource", 50),
    /timed out waiting for creation of DevToolsActivePort/u);
});
