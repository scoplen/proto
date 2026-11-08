// SPDX-License-Identifier: Apache-2.0
const result = document.getElementById("result");
let started = 0;
let terminated = 0;

async function workerRun(path, mode) {
  const worker = new Worker(path, { type: "module" });
  started += 1;
  let timer;
  try {
    return await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error("Browser contract Worker timed out")), 150000);
      worker.onmessage = event => event.data.ok ? resolve(event.data) : reject(new Error(event.data.error));
      worker.onerror = event => {
        event.preventDefault();
        reject(new Error("Browser contract Worker failed"));
      };
      worker.postMessage({ mode });
    });
  } finally {
    clearTimeout(timer);
    worker.terminate();
    terminated += 1;
  }
}

globalThis.__scoplenBrowserKat = (async () => {
  const mode = new URL(location.href).searchParams.get("mode") || "full";
  const summary = await workerRun("/kat-worker.mjs", mode);
  let workerFailure = false;
  try { await workerRun("/failure-worker.mjs", "failure"); }
  catch (error) { workerFailure = error.message === "Browser contract Worker failed"; }
  if (!workerFailure || started !== terminated) throw new Error("One-use Worker failure/termination check failed");
  return { ...summary, workerFailure, started, terminated };
})().catch(() => ({ ok: false, error: "Packaged browser contract checks failed", started, terminated }));

const summary = await globalThis.__scoplenBrowserKat;
result.textContent = JSON.stringify(summary, null, 2);
document.documentElement.dataset.status = summary.ok ? "passed" : "failed";
