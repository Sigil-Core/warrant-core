import { describe, expect, it } from "vitest";

import {
  appendSignatureBlock,
  canonicalizePgCommitV1,
  canonicalizePolicyObject,
  hashPgCommitV1,
  hashPolicy,
  parsePolicyMarkdown,
  pgCommitV1Bytes,
  policyCanonicalBytes,
  sha256Hex,
  splitSignatureBlock,
} from "../../src/index.js";
import type { CryptoAdapter, JsonValue } from "../../src/types.js";
import launchScenarioFixture from "../vectors/launch-scenarios.json";
import commitmentFixture from "../vectors/pg-commit-v1.json";
import genericControlParityFixture from "../vectors/generic-control-parity.json";
import executionLimitsControlParityFixture from "../vectors/execution-limits-control-parity.json";
import parserHardeningFixture from "../vectors/parser-hardening.json";
import policyFixture from "../vectors/policy-fixtures.json";
import sigilSignParserParityFixture from "../vectors/sigil-sign-parser-parity.json";
import signatureFixture from "../vectors/signature-blocks.json";

function bytesFromBase64url(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const decoded = atob(padded);
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

const pgCommitRejectionValues = {
  undefined: () => ({ value: undefined }),
  nan: () => ({ value: Number.NaN }),
  infinity: () => ({ value: Number.POSITIVE_INFINITY }),
  bigint: () => ({ value: 1n }),
  function: () => ({ value: () => undefined }),
  symbol: () => ({ value: Symbol("test") }),
  cyclic: () => { const value: { self?: unknown } = {}; value.self = value; return value; },
  "non-plain-object": () => new Date(),
  "symbol-keyed-object-property": () => { const value = { safe: true }; Object.defineProperty(value, Symbol("test"), { value: true }); return value; },
  "non-enumerable-object-property": () => { const value = { safe: true }; Object.defineProperty(value, "hidden", { value: true }); return value; },
  "accessor-property": () => { const value = {}; Object.defineProperty(value, "value", { enumerable: true, get: () => "never" }); return value; },
  "sparse-array": () => { const value: unknown[] = []; value[1] = "present"; return value; },
  "non-index-array-property": () => { const value: unknown[] = []; Object.defineProperty(value, "label", { enumerable: true, value: "bad" }); return value; },
  "non-enumerable-array-property": () => { const value = ["value"]; Object.defineProperty(value, "0", { enumerable: false, value: "value" }); return value; },
  "non-plain-array": () => { const value: unknown[] = []; Object.setPrototypeOf(value, {}); return value; },
  "symbol-keyed-array-property": () => { const value: unknown[] = []; Object.defineProperty(value, Symbol("test"), { value: true }); return value; },
};

export function pgCommitRejectionValue(kind: string): unknown {
  const construct = pgCommitRejectionValues[kind as keyof typeof pgCommitRejectionValues];
  if (!construct) throw new Error(`Missing pg-commit-v1 rejection constructor for ${kind}`);
  return construct();
}

export function defineSharedRuntimeVectorTests(runtime: string, adapter: CryptoAdapter): void {
  it(`preserves established Warrant collation in ${runtime}`, () => {
    const policy = {
      chainActions: {
        "a-b": ["x"],
        ab: ["x"],
        "é": ["x"],
        e: ["x"],
        Z: ["x"],
        a: ["x"],
        "a_": ["x"],
        "a-": ["x"],
        "ä": ["x"],
        z: ["x"],
      },
    };
    expect(canonicalizePolicyObject(policy)).toBe(
      "{\"chainActions\":{\"a\":[\"x\"],\"ä\":[\"x\"],\"a_\":[\"x\"],\"a-\":[\"x\"],\"a-b\":[\"x\"],\"ab\":[\"x\"],\"e\":[\"x\"],\"é\":[\"x\"],\"z\":[\"x\"],\"Z\":[\"x\"]}}",
    );
  });

  it(`breaks collation ties by UTF-16 code units in ${runtime}`, async () => {
    const first = { "a\u00ad": ["x"], a: ["x"] };
    const reversed = { a: ["x"], "a\u00ad": ["x"] };
    const expected = "{\"a\":[\"x\"],\"a\u00ad\":[\"x\"]}";
    const expectedHash = "9bbb6d2584aa2b8574e3990dd811afb09789dca786b4b5d4ce62757ecd44e1be";

    expect("a\u00ad".localeCompare("a", "en-US")).toBe(0);
    expect(canonicalizePolicyObject(first)).toBe(expected);
    expect(canonicalizePolicyObject(reversed)).toBe(expected);
    expect(policyCanonicalBytes(first)).toEqual(new TextEncoder().encode(expected));
    expect(policyCanonicalBytes(reversed)).toEqual(new TextEncoder().encode(expected));
    await expect(hashPolicy(adapter, first)).resolves.toBe(expectedHash);
    await expect(hashPolicy(adapter, reversed)).resolves.toBe(expectedHash);
  });

  it(`pins en-US ordering for case-distinct Warrant keys in ${runtime}`, () => {
    expect(canonicalizePolicyObject({ caps: { I: 1, i: 1 } })).toBe(
      "{\"caps\":{\"i\":1,\"I\":1}}",
    );
  });

  it(`ignores signature-like headings inside closed HTML comments in ${runtime}`, () => {
    const unsigned = "version: 2.0.0\n\n<!--\n## signature\nsigil-sig: fake\n-->\n\n## tool_calls\nallowed: bash";
    expect(splitSignatureBlock(unsigned)).toEqual({ unsigned });
    const signed = appendSignatureBlock(unsigned, "abc_DEF-123");
    expect(splitSignatureBlock(signed)).toEqual({ unsigned, signature: "abc_DEF-123" });
    expect(parsePolicyMarkdown(signed)).toEqual({
      version: "2.0.0",
      tool_calls: { allowed: ["bash"] },
    });
    const unterminated = "version: 2.0.0\n<!--\n## signature";
    expect(() => splitSignatureBlock(unterminated)).toThrow("Unterminated HTML comment");
    expect(() => appendSignatureBlock(unterminated, "abc")).toThrow("Unterminated HTML comment");
    const splitHeading = "version: 2.0.0\n\n##\nsignature\nsigil-sig: abc";
    expect(splitSignatureBlock(splitHeading)).toEqual({ unsigned: splitHeading });
  });

  it(`validates version 2 daily EVM decimals before number conversion in ${runtime}`, () => {
    expect(parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\ndaily_evm_limit_eth: 1ETH").soft_limits?.dailyEvmLimitEth).toBe(1);
    expect(() => parsePolicyMarkdown('version: 2.0.0\n\n## soft_limits\ndaily_evm_limit_eth: "1"')).toThrow("positive decimal");
    expect(parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\ndaily_evm_limit_eth: 9000000000000.0000001").soft_limits?.dailyEvmLimitEth).toBe(9_000_000_000_000);
    expect(parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\ndaily_evm_limit_eth: 9223372036854.775807").soft_limits?.dailyEvmLimitEth).toBe(Number("9223372036854.775807"));
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\ndaily_evm_limit_eth: 9223372036854.775808")).toThrow("positive decimal");
    expect(parsePolicyMarkdown("version: 1.0.0\n\n## tool_calls\nallowed: bash\n\n## soft_limits\ndaily_evm_limit_eth: 1ETH").soft_limits?.dailyEvmLimitEth).toBe(1);
  });

  it(`matches generic approval and shim controls in ${runtime}`, () => {
    const parsed = parsePolicyMarkdown(genericControlParityFixture.markdown);
    expect(parsed).toEqual(genericControlParityFixture.canonicalPolicy);
    expect(canonicalizePolicyObject(parsed)).toBe(genericControlParityFixture.canonicalPolicyJson);
  });

  it(`does not drop execution-limit controls in ${runtime}`, () => {
    for (const controlCase of executionLimitsControlParityFixture.cases) {
      if (controlCase.outcome === "accept") {
        expect(parsePolicyMarkdown(controlCase.markdown).execution_limits).toEqual(controlCase.executionLimits);
      } else {
        expect(() => parsePolicyMarkdown(controlCase.markdown)).toThrow("at least one enforceable control");
      }
    }
  });

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

    for (const hardeningCase of parserHardeningFixture.cases) {
      it(`matches the ${hardeningCase.id} warrant-core parser-hardening vector`, () => {
        if (hardeningCase.outcome === "accept") {
          if (!("canonicalPolicy" in hardeningCase)) throw new Error(`Missing canonical policy for ${hardeningCase.id}`);
          expect(parsePolicyMarkdown(hardeningCase.markdown)).toEqual(hardeningCase.canonicalPolicy);
        } else {
          expect(() => parsePolicyMarkdown(hardeningCase.markdown)).toThrow();
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
        expect(() => canonicalizePgCommitV1(pgCommitRejectionValue(rejection.runtimeValueKind))).toThrow(rejection.error);
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
