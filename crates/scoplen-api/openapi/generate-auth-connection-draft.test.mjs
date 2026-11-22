// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { generateAuthDraftTypes } from "./generate-auth-connection-draft.mjs";

const doc = JSON.parse(await readFile(new URL("v1.yaml", import.meta.url), "utf8"));
const path = "/orgs/{org}/auth-connection-draft";
test("only the three role- and scope-bound draft operations are published", () => {
  assert.match(generateAuthDraftTypes(doc), /AuthConnectionDraftResource/);
  assert.deepEqual(Object.keys(doc.paths[path]), ["post", "get", "delete"]);
  for (const op of Object.values(doc.paths[path])) {
    assert.deepEqual(op.security, [{ accessToken: [], dpopProof: [] }, { accountBrowserAccess: [], dpopProof: [] }]);
    assert.deepEqual(op["x-scoplen-required-membership-roles-any"], ["owner", "administrator"]);
    assert.equal(op["x-scoplen-cedar-action"], "manage_organization");
    assert.equal(op["x-scoplen-required-device-scope"], "auth-drafts:manage");
    assert.equal(op["x-scoplen-required-browser-scope"], "auth-drafts:manage");
  }
  for (const mutate of [
    d => { delete d.paths[path].delete.parameters[2]; },
    d => { d.paths[path].get.security = []; },
    d => { delete d.paths[path].post.responses["201"].headers.ETag; },
    d => { d.components.schemas.AuthConnectionDraftCreate.properties.data.additionalProperties = true; },
    d => { d.components.schemas.AuthConnectionDraftResource["x-scoplen-max-bytes"]++; },
  ]) {
    const copy = structuredClone(doc);
    mutate(copy);
    assert.throws(() => generateAuthDraftTypes(copy), /D-166/);
  }
});
