// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

const root = fileURLToPath(new URL("../", import.meta.url));
const crate = join(root, "crates/scoplen-browser");
const packaged = join(crate, "pkg");
const build = JSON.parse(await readFile(join(packaged, "build.json"), "utf8"));
for (const [name, expected] of Object.entries(build.assets)) {
  assert.equal(basename(name), name);
  const bytes = await readFile(join(packaged, name));
  assert.equal(bytes.length, expected.bytes, `Asset size changed: ${name}`);
  assert.equal(createHash("sha256").update(bytes).digest("hex"), expected.sha256, `Asset hash changed: ${name}`);
}
const routes = new Map([
  ["/", [join(crate, "tests/browser/index.html"), "text/html; charset=utf-8"]],
  ...["browser-kat.mjs", "kat-worker.mjs", "failure-worker.mjs"].map(name => [`/${name}`, [join(crate, "tests/browser", name), "text/javascript; charset=utf-8"]]),
  ...Object.keys(build.assets).map(name => [`/pkg/${name}`, [join(packaged, name), name.endsWith(".wasm") ? "application/wasm" : "text/javascript; charset=utf-8"]]),
  ...["password-bootstrap", "team-invitation", "group-policy"].map(name => [`/vectors/${name}.json`, [join(root, "vectors", `${name}.json`), "application/json"]]),
]);
const server = createServer(async (request, response) => {
  const path = new URL(request.url, "http://localhost").pathname;
  const file = routes.get(path);
  if (request.method !== "GET" || (!file && path !== "/favicon.ico")) {
    response.writeHead(404).end();
    return;
  }
  if (path === "/favicon.ico") { response.writeHead(204).end(); return; }
  try {
    response.writeHead(200, {
      "Content-Type": file[1], "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
    });
    response.end(await readFile(file[0]));
  } catch { response.writeHead(500).end(); }
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;

async function chromeExecutable() {
  if (process.env.CHROME_BIN) return process.env.CHROME_BIN;
  if (process.platform === "win32") {
    for (const directory of [process.env.PROGRAMFILES, process.env["PROGRAMFILES(X86)"], process.env.LOCALAPPDATA].filter(Boolean)) {
      for (const browser of ["Google/Chrome/Application/chrome.exe", "Microsoft/Edge/Application/msedge.exe"]) {
        const candidate = join(directory, browser);
        try { await access(candidate); return candidate; } catch {}
      }
    }
  }
  return process.platform === "darwin" ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" : "google-chrome";
}

async function connectCdp(url) {
  const socket = new WebSocket(url);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
  let sequence = 0;
  const pending = new Map();
  const errors = [];
  socket.addEventListener("message", event => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const waiter = pending.get(message.id);
      if (!waiter) return;
      pending.delete(message.id);
      clearTimeout(waiter.timer);
      if (message.error) waiter.reject(new Error(message.error.message));
      else waiter.resolve(message.result);
    } else if (message.method === "Runtime.exceptionThrown" || message.method === "Network.loadingFailed" ||
      (message.method === "Log.entryAdded" && message.params.entry.level === "error")) errors.push(message.method);
  });
  socket.addEventListener("close", () => {
    for (const waiter of pending.values()) { clearTimeout(waiter.timer); waiter.reject(new Error("Browser closed before its contract check completed")); }
    pending.clear();
  });
  const call = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Browser command timed out: ${method}`)); }, 180000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params }));
  });
  return { call, errors, close: () => socket.close() };
}

async function runBrowser(mode, extraArguments = []) {
  const temporaryRoot = resolve(tmpdir());
  const profile = await mkdtemp(join(temporaryRoot, "scoplen-browser-kat-"));
  let child;
  let cdp;
  let launchError;
  try {
    child = spawn(await chromeExecutable(), [
      "--headless=new", "--remote-debugging-port=0", `--user-data-dir=${profile}`,
      "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update",
      "--disable-sync", "--disable-extensions", ...extraArguments, "about:blank",
    ], { stdio: "ignore", windowsHide: true });
    child.once("error", error => { launchError = error; });
    let port;
    for (let attempt = 0; attempt < 400; attempt += 1) {
      if (launchError) throw new Error("Chromium is unavailable; set CHROME_BIN to an installed Chrome/Edge executable", { cause: launchError });
      try { port = Number((await readFile(join(profile, "DevToolsActivePort"), "utf8")).split("\n")[0]); break; }
      catch { if (child.exitCode !== null) throw new Error("Chromium exited before opening its test endpoint"); }
      await delay(50);
    }
    assert.ok(port, "Chromium test endpoint did not start");
    const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    cdp = await connectCdp(targets.find(target => target.type === "page").webSocketDebuggerUrl);
    const version = await cdp.call("Browser.getVersion");
    for (const domain of ["Page", "Runtime", "Network", "Log"]) await cdp.call(`${domain}.enable`);
    await cdp.call("Page.navigate", { url: `${origin}/?mode=${mode}` });
    const evaluation = await cdp.call("Runtime.evaluate", {
      expression: "new Promise(resolve => { const poll = () => globalThis.__scoplenBrowserKat ? resolve(globalThis.__scoplenBrowserKat) : setTimeout(poll, 10); poll(); })",
      awaitPromise: true, returnByValue: true,
    });
    assert.equal(evaluation.exceptionDetails, undefined, "Browser evaluation failed");
    assert.equal(evaluation.result.value.ok, true, JSON.stringify(evaluation.result.value));
    assert.deepEqual(cdp.errors, [], "Browser reported console/runtime/network errors");
    console.log(JSON.stringify({ browser: version.product, ...evaluation.result.value }));
    await cdp.call("Browser.close").catch(() => {});
  } finally {
    cdp?.close();
    if (child && child.exitCode === null) {
      await Promise.race([new Promise(resolve => child.once("exit", resolve)), delay(3000)]);
      if (child.exitCode === null) child.kill();
    }
    assert.equal(dirname(resolve(profile)), temporaryRoot);
    assert.ok(basename(profile).startsWith("scoplen-browser-kat-"));
    await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
}

if (process.argv.includes("--serve")) {
  console.log(`Browser KAT fixture: ${origin}/`);
} else {
  try {
    await runBrowser("full");
    await runBrowser("randomness");
    await runBrowser("resource", ["--js-flags=--wasm-max-mem-pages=1024"]);
  } finally { await new Promise(resolve => server.close(resolve)); }
}
