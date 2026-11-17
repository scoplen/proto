// SPDX-License-Identifier: Apache-2.0
import type {
  AccountCommittedConfirmation,
  AccountPasswordChangeConfirmation,
  AccountPasswordChangeFields,
  AccountPasswordChangeRequest,
  AccountRequestChallengeRequest,
  components,
} from "./index";

declare const fields: AccountPasswordChangeFields;
declare const result: AccountPasswordChangeConfirmation;
declare const oldResult: AccountCommittedConfirmation;

const submit: AccountPasswordChangeRequest = { ...fields, intent: "submit", admission_token: "fixture" };
const confirm: AccountPasswordChangeRequest = { ...fields, intent: "confirm", admission_token: null };
const challenge: AccountRequestChallengeRequest = { kind: "password_change", intent: "confirm", operation_id: "fixture", device_id: "fixture" };
const generation: string = result.credential_generation;
const kind: "password_change" = result.kind;
const schema: components["schemas"]["AccountPasswordChangeRequest"] = submit;
const resultSchema: components["schemas"]["AccountPasswordChangeConfirmation"] = result;

// @ts-expect-error New submissions require the recent native password capability.
const noCapability: AccountPasswordChangeRequest = { ...fields, intent: "submit", admission_token: null };
// @ts-expect-error Confirmation cannot carry new mutation authority.
const confirmingCapability: AccountPasswordChangeRequest = { ...fields, intent: "confirm", admission_token: "fixture" };
// @ts-expect-error Capability is required even when its value is null.
const missingCapability: AccountPasswordChangeRequest = { ...fields, intent: "confirm" };
// @ts-expect-error Historical credential generations remain exact decimal strings.
const numericGeneration: AccountPasswordChangeConfirmation = { ...result, credential_generation: 2 };
// @ts-expect-error Registration/admission confirmation is a different receipt.
const oldConfirmation: AccountPasswordChangeConfirmation = oldResult;
// @ts-expect-error Password-change results are excluded from the old result's kind set.
const wrongKind: AccountCommittedConfirmation = { ...oldResult, kind: "password_change" };

void [submit, confirm, challenge, generation, kind, schema, resultSchema, noCapability,
  confirmingCapability, missingCapability, numericGeneration, oldConfirmation, wrongKind];
