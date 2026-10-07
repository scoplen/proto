// SPDX-License-Identifier: Apache-2.0
// Check generated TypeScript protobuf bindings and their source contract markers.
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));
const generator = path.join(root, "generate-proto.mjs");
const result = spawnSync(process.execPath, [generator, "--check"], { encoding: "utf8" });
if (result.status !== 0) {
  process.stderr.write(result.stderr || result.stdout);
  process.exit(result.status || 1);
}
const generated = await readFile(path.join(root, "internal-proto.ts"), "utf8");
for (const marker of [
  "export interface GatewayRegisterRequest",
  "export interface AgentEnrollRequest",
  "export type GatewayControlEventEvent",
  "export type AgentAgentEventEvent",
  '"spl.gateway.v1.Control"',
  '"spl.agent.v1.Agent"',
  'name: "Subscribe"',
]) {
  if (!generated.includes(marker)) throw new Error(`missing generated binding marker: ${marker}`);
}
if (generated.includes("TODO") || generated.includes("FIXME")) throw new Error("generated bindings contain a placeholder");
console.log("TypeScript protobuf bindings are current and contain both service contracts");
