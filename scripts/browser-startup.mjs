// SPDX-License-Identifier: Apache-2.0
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

// Raw Chromium output may contain profile paths and a live DevTools WebSocket URL.
const messages = [
  ["No usable sandbox", "no usable sandbox"],
  ["Running as root without --no-sandbox", "sandbox rejected current user"],
  ["error while loading shared libraries", "shared library unavailable"],
  ["Failed to create a ProcessSingleton", "profile lock unavailable"],
  ["DevTools listening on", "browser announced DevTools"],
];

export class BrowserStartupError extends Error {}

export async function waitForBrowserPort(child, profile, mode, timeoutMs = 20_000) {
  const hints = new Set();
  let suffix = "";
  const classify = chunk => {
    const text = suffix + chunk;
    for (const [marker, hint] of messages) if (text.includes(marker)) hints.add(hint);
    suffix = text.slice(-64);
  };
  child.stderr.setEncoding("utf8").on("data", classify);
  let launchFailed = false;
  child.once("error", () => { launchFailed = true; });
  const failure = reason => new BrowserStartupError(
    `Chromium startup failed (${mode}): ${reason}. ${[...hints].join(", ") || "No recognized startup diagnostic"}.`,
  );
  try {
    const deadline = performance.now() + timeoutMs;
    let incomplete = false;
    do {
      if (launchFailed) throw failure("could not launch browser; check CHROME_BIN");
      if (child.signalCode) throw failure(`terminated by ${child.signalCode}`);
      if (child.exitCode !== null) throw failure(`exited with code ${child.exitCode}`);
      try {
        const text = await readFile(join(profile, "DevToolsActivePort"), "utf8");
        const first = /^([1-9]\d{0,4})\r?\n/u.exec(text);
        if (first && Number(first[1]) <= 65535) return Number(first[1]);
        incomplete = true;
      } catch (error) {
        if (error.code !== "ENOENT") throw failure("could not read DevToolsActivePort");
      }
      await delay(50);
    } while (performance.now() < deadline);
    throw failure(`timed out waiting for ${incomplete ? "a valid port in" : "creation of"} DevToolsActivePort`);
  } finally {
    child.stderr.off("data", classify).resume();
  }
}
