import { describe, expect, it } from "vitest";

import {
  appendSignatureBlock,
  canonicalizePgCommitV1,
  canonicalizePolicyObject,
  hashPgCommitV1,
  hashPolicy,
  parsePolicyMarkdown,
  pgCommitV1Bytes,
  sha256Hex,
  splitSignatureBlock,
} from "../../src/index.js";
import type { CryptoAdapter, JsonValue } from "../../src/types.js";
import launchScenarioFixture from "../vectors/launch-scenarios.json";
import commitmentFixture from "../vectors/pg-commit-v1.json";
import policyFixture from "../vectors/policy-fixtures.json";
import sigilSignParserParityFixture from "../vectors/sigil-sign-parser-parity.json";
import signatureFixture from "../vectors/signature-blocks.json";

function bytesFromBase64url(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const decoded = atob(padded);
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

function rejectionValue(id: string): unknown {
  if (id === "undefined") return { value: undefined };
  if (id === "non-finite-nan") return { value: Number.NaN };
  if (id === "non-finite-infinity") return { value: Number.POSITIVE_INFINITY };
  if (id === "bigint") return { value: 1n };
  if (id === "function") return { value: () => undefined };
  if (id === "symbol") return { value: Symbol("test") };
  if (id === "cyclic") { const value: { self?: unknown } = {}; value.self = value; return value; }
  if (id === "non-plain-object") return new Date();
  if (id === "symbol-keyed-object-property") { const value = { safe: true }; Object.defineProperty(value, Symbol("test"), { value: true }); return value; }
  if (id === "non-enumerable-object-property") { const value = { safe: true }; Object.defineProperty(value, "hidden", { value: true }); return value; }
  if (id === "accessor-property") { const value = {}; Object.defineProperty(value, "value", { enumerable: true, get: () => "never" }); return value; }
  if (id === "sparse-array") { const value: unknown[] = []; value[1] = "present"; return value; }
  if (id === "non-index-array-property") { const value: unknown[] = []; Object.defineProperty(value, "label", { enumerable: true, value: "bad" }); return value; }
  if (id === "non-enumerable-array-property") { const value = ["value"]; Object.defineProperty(value, "0", { enumerable: false, value: "value" }); return value; }
  if (id === "non-plain-array") { const value: unknown[] = []; Object.setPrototypeOf(value, {}); return value; }
  if (id === "symbol-keyed-array-property") { const value: unknown[] = []; Object.defineProperty(value, Symbol("test"), { value: true }); return value; }
  throw new Error(`Missing pg-commit-v1 rejection constructor for ${id}`);
}

export function defineSharedRuntimeVectorTests(runtime: string, adapter: CryptoAdapter): void {
  describe(`${runtime} shared policy, commitment, and signature vectors`, () => {
    for (const fixture of policyFixture.fixtures) {
      it(`matches the ${fixture.slug} policy vector`, async () => {
        await expect(sha256Hex(adapter, fixture.templateBody)).resolves.toBe(fixture.templateBodySha256);
        const parsed = parsePolicyMarkdown(fixture.templateBody);
        expect(parsed).toEqual(fixture.canonicalPolicy);
        expect(canonicalizePolicyObject(parsed)).toBe(fixture.canonicalPolicyJson);
        await expect(hashPolicy(adapter, parsed)).resolves.toBe(fixture.policyHashSha256);
      });
    }

    for (const parityCase of sigilSignParserParityFixture.cases) {
      it(`matches the ${parityCase.id} Sigil Sign parser vector`, () => {
        if (parityCase.outcome === "accept") {
          if (!("canonicalPolicy" in parityCase)) throw new Error(`Missing canonical policy for ${parityCase.id}`);
          expect(parsePolicyMarkdown(parityCase.markdown)).toEqual(parityCase.canonicalPolicy);
        } else {
          expect(() => parsePolicyMarkdown(parityCase.markdown)).toThrow();
        }
      });
    }

    for (const vector of commitmentFixture.vectors) {
      it(`matches the ${vector.id} commitment vector`, async () => {
        const intent = vector.intent as JsonValue;
        expect(canonicalizePgCommitV1(intent)).toBe(vector.canonicalJson);
        expect(new TextDecoder().decode(pgCommitV1Bytes(intent))).toBe(vector.canonicalJson);
        await expect(hashPgCommitV1(adapter, intent)).resolves.toBe(vector.sha256);
      });
    }

    for (const vector of launchScenarioFixture.vectors) {
      it(`matches the ${vector.id} launch commitment vector`, async () => {
        const intent = vector.request.intent as JsonValue;
        expect(canonicalizePgCommitV1(intent)).toBe(vector.canonicalIntentJson);
        expect(new TextDecoder().decode(pgCommitV1Bytes(intent))).toBe(vector.canonicalIntentJson);
        expect(vector.request.txCommit).toBe(vector.txCommitSha256);
        await expect(hashPgCommitV1(adapter, intent)).resolves.toBe(vector.txCommitSha256);
      });
    }

    for (const rejection of commitmentFixture.rejections) {
      it(`rejects the ${rejection.id} commitment vector`, () => {
        expect(() => canonicalizePgCommitV1(rejectionValue(rejection.id))).toThrow(rejection.error);
      });
    }

    for (const vector of signatureFixture.vectors) {
      it(`matches the ${vector.id} signature vector`, async () => {
        if (vector.messageUtf8 !== undefined) {
          const publicKey = bytesFromBase64url(signatureFixture.keys[vector.key as "rfc8032Test1"].rawPublicKeyBase64url);
          await expect(adapter.verifyEd25519!(publicKey, bytesFromBase64url(vector.signatureBase64url!), new TextEncoder().encode(vector.messageUtf8))).resolves.toBe(true);
        } else if (vector.signedMarkdown !== undefined) {
          expect(splitSignatureBlock(vector.signedMarkdown)).toEqual({ unsigned: vector.unsigned, signature: vector.signatureBase64url });
          expect(appendSignatureBlock(vector.unsigned!, vector.signatureBase64url!)).toBe(vector.signedMarkdown);
        } else {
          expect(() => splitSignatureBlock(vector.markdown!)).toThrow(vector.error);
        }
      });
    }
  });
}
