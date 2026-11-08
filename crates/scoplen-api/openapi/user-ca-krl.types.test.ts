// SPDX-License-Identifier: Apache-2.0
import type {
  UserCaKrl, CertificateRevokedProblem, CertificateQuotaExceededProblem,
  CertificateBodyTooLargeProblem, components,
} from "./index";

const bytes: UserCaKrl = new Uint8Array([0x53, 0x53, 0x48]);
const schemaBytes: components["schemas"]["UserCaKrl"] = bytes;
void schemaBytes;
// @ts-expect-error KRL is a binary response rather than a JSON string.
const text: UserCaKrl = "SSHKRL";
void text;

declare const revoked: CertificateRevokedProblem;
declare const quota: CertificateQuotaExceededProblem;
declare const oversized: CertificateBodyTooLargeProblem;
const revokedStatus: 409 = revoked.status;
const quotaStatus: 413 = quota.status;
const quotaCode: "certificate.quota_exceeded" = quota.code;
const syntaxCode: "certificate.invalid_request" = oversized.code;
const revokedCode: "certificate.revoked" = revoked.code;
const changed: false = revoked.changed;
const retryable: false = quota.retryable;
void [revokedStatus, quotaStatus, quotaCode, syntaxCode, revokedCode, changed, retryable];
// @ts-expect-error Syntax refusal and issuance quota are distinct even with equal HTTP statuses.
const quotaFromSyntax: CertificateQuotaExceededProblem = oversized;
void quotaFromSyntax;
// @ts-expect-error An unknown-result 503 is not a definite revoked receipt.
const unknownStatus: 503 = revoked.status;
void unknownStatus;
