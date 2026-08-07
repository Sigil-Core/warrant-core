import { describe, expect, it } from "vitest";

import {
  appendSignatureBlock,
  canonicalizePgCommitV1,
  canonicalizePolicyObject,
  canonicalizeCompiledResponsePolicyFormat1,
  compileResponsePolicyFormat1,
  compiledResponsePolicyFormat1Bytes,
  frameWarrantMarkdownBytes,
  emit,
  hashPgCommitV1,
  hashCompiledResponsePolicyFormat1,
  hashPolicy,
  lintPolicyAdvisories,
  parsePolicyMarkdown,
  pgCommitV1Bytes,
  policyCanonicalBytes,
  sha256Hex,
  serializePolicyMarkdown,
  signedEnvelopeParse,
  splitSignatureBlock,
  unsignedSigningPayload,
  WarrantEnvelopeError,
} from "../../src/index.js";
import type { CryptoAdapter, JsonValue } from "../../src/types.js";
import launchScenarioFixture from "../vectors/launch-scenarios.json";
import commitmentFixture from "../vectors/pg-commit-v1.json";
import genericControlParityFixture from "../vectors/generic-control-parity.json";
import executionLimitsControlParityFixture from "../vectors/execution-limits-control-parity.json";
import envelopeV1Fixture from "../vectors/sigil-envelope-v1.json";
import parserHardeningFixture from "../vectors/parser-hardening.json";
import parserPhase1Fixture from "../vectors/parser-phase1.json";
import policyFixture from "../vectors/policy-fixtures.json";
import sigilSignParserParityFixture from "../vectors/sigil-sign-parser-parity.json";
import signatureFixture from "../vectors/signature-blocks.json";
import responsePolicyFormat1Fixture from "../vectors/response-policy-format1.json";
import {
  assertKnownParityDivergencesCovered,
  defineConsumerCompatibilityVectorTests,
  KNOWN_PARITY_DIVERGENCES,
} from "./parser-compatibility.js";

function bytesFromBase64url(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const decoded = atob(padded);
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

const utf8 = (value: string): Uint8Array => new TextEncoder().encode(value);
const strictSignature = "A".repeat(86);
const decodeUtf8 = (value: Uint8Array): string => new TextDecoder("utf-8", { ignoreBOM: true }).decode(value);
const signedWarrant = (unsigned: string): Uint8Array =>
  utf8(`${unsigned.trimEnd()}\n\n## signature\nsigil-sig: ${strictSignature}\n`);
const bytesFromHex = (value: string): Uint8Array => {
  if (value.length % 2 !== 0) throw new Error("Hex fixture must contain complete bytes");
  return Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));
};

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

const defineSharedMcpToolOverlapTests = (runtime: string): void => {
  it(`rejects conflicting MCP tool allow and block patterns in ${runtime}`, () => {
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## mcp\nallowed_tools: github.delete\nblocked_tools: github.*")).toThrow("same tool");
  });
};

const FORMAT_1_DIGEST = "dd07aff020e1d03e08501105dc53bb6943ffbdb50629cac7c7b4b03d1bd7ce46";
const FORMAT_1_CATALOG_DIGEST = "3f77896cf5a15475c0e9847201ffaa41f4b117b4d8e5051d035f982f55d3098d";
const FORMAT_1_POLICY_HASH = "3".repeat(64);

const compileSharedFormat1Vector = (index: number) => compileResponsePolicyFormat1(
  parsePolicyMarkdown(responsePolicyFormat1Fixture.positive[index]!.markdown),
  {
    issuer: "https://sign.sigil.example",
    keyId: "sign-key-1",
    tenantId: "tenant-1",
    taskId: "task-1",
    policyHash: FORMAT_1_POLICY_HASH,
    issuedAt: 1_800_000_000,
    expiresAt: 1_800_000_300,
    revocationEpoch: 7,
    deterministicRulesetDigest: FORMAT_1_DIGEST,
    classCatalogDigest: FORMAT_1_CATALOG_DIGEST,
  },
);

const defineSharedResponsePolicyFormat1Tests = (runtime: string, adapter: CryptoAdapter): void => {
  for (const vector of responsePolicyFormat1Fixture.positive) {
    it(`matches the ${vector.id} Policy 2.2 parser vector in ${runtime}`, () => {
      const policy = parsePolicyMarkdown(vector.markdown);
      expect(policy).toEqual(vector.canonicalPolicy);
      expect(parsePolicyMarkdown(serializePolicyMarkdown(policy))).toEqual(policy);
    });
  }
  for (const vector of responsePolicyFormat1Fixture.negative) {
    it(`rejects the ${vector.id} Policy 2.2 parser vector in ${runtime}`, () => {
      expect(() => parsePolicyMarkdown(vector.markdown)).toThrow();
    });
  }
  it(`compiles canonical format 1 response policy bytes in ${runtime}`, async () => {
    const compiled = compileSharedFormat1Vector(2);
    const canonical = canonicalizeCompiledResponsePolicyFormat1(compiled);
    expect(canonical).toBe(responsePolicyFormat1Fixture.compiledFormat1.canonicalJson);
    expect(compiledResponsePolicyFormat1Bytes(compiled)).toEqual(
      new TextEncoder().encode(responsePolicyFormat1Fixture.compiledFormat1.canonicalJson),
    );
    await expect(hashCompiledResponsePolicyFormat1(adapter, compiled)).resolves.toBe(
      responsePolicyFormat1Fixture.compiledFormat1.sha256,
    );
  });
  it(`compiles fixed response deny literals in ${runtime}`, async () => {
    const compiled = compileSharedFormat1Vector(3);
    expect(compiled.policy.denyStrings).toEqual(["ignore previous instructions", "token:\\t"]);
    const canonical = canonicalizeCompiledResponsePolicyFormat1(compiled);
    expect(canonical).toBe(responsePolicyFormat1Fixture.compiledDenyFormat1.canonicalJson);
    expect(compiledResponsePolicyFormat1Bytes(compiled)).toEqual(
      new TextEncoder().encode(responsePolicyFormat1Fixture.compiledDenyFormat1.canonicalJson),
    );
    await expect(hashCompiledResponsePolicyFormat1(adapter, compiled)).resolves.toBe(
      responsePolicyFormat1Fixture.compiledDenyFormat1.sha256,
    );
  });
};

const defineSharedToolCallControlTests = (runtime: string): void => {
  it(`rejects a false-only Policy 2 tool-call shim control in ${runtime}`, () => {
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## tool_calls\nrequire_shim: false")).toThrow("at least one enforceable rule or control");
    expect(parsePolicyMarkdown("version: 2.0.0\n\n## tool_calls\nrequire_approval: bash").tool_calls).toEqual({ requireApproval: ["bash"] });
    expect(parsePolicyMarkdown("version: 2.0.0\n\n## tool_calls\nrequire_shim: true").tool_calls).toEqual({ requireShim: true });
  });

  it(`rejects empty explicit Policy 2 tool-call allows in ${runtime}`, () => {
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## tool_calls\nallowed: ,")).toThrow("allowed must contain at least one tool");
    expect(() => parsePolicyMarkdown('version: 2.0.0\n\n## tool_calls\nallowed: ""')).toThrow("allowed must contain at least one tool");
    expect(parsePolicyMarkdown("version: 1.0.0\n\n## tool_calls\nallowed: ,").tool_calls).toEqual({ allowed: [] });
  });

  it(`rejects a false-only Policy 2 email approval control in ${runtime}`, () => {
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## tool_calls\nemail.require_approval: false")).toThrow("at least one enforceable rule or control");
    expect(parsePolicyMarkdown("version: 2.0.0\n\n## tool_calls\nemail.require_approval: true").tool_calls).toEqual({ emailRequireApproval: true });
    expect(parsePolicyMarkdown("version: 1.0.0\n\n## tool_calls\nemail.require_approval: false").tool_calls).toEqual({ emailRequireApproval: false });
  });
};

const defineSharedPolicyFixtureTests = (adapter: CryptoAdapter): void => {
  for (const fixture of policyFixture.fixtures) {
    it(`matches the ${fixture.slug} policy vector`, async () => {
      await expect(sha256Hex(adapter, fixture.templateBody)).resolves.toBe(fixture.templateBodySha256);
      const parsed = parsePolicyMarkdown(fixture.templateBody);
      expect(parsed).toEqual(fixture.canonicalPolicy);
      expect(canonicalizePolicyObject(parsed)).toBe(fixture.canonicalPolicyJson);
      await expect(hashPolicy(adapter, parsed)).resolves.toBe(fixture.policyHashSha256);
    });
  }
};

const defineSharedSignParityTests = (): void => {
  assertKnownParityDivergencesCovered();
  for (const parityCase of sigilSignParserParityFixture.cases) {
    if (KNOWN_PARITY_DIVERGENCES.has(parityCase.id)) continue;
    it(`matches the ${parityCase.id} Sigil Sign parser vector`, () => {
      if (parityCase.outcome === "accept") {
        if (!("canonicalPolicy" in parityCase)) throw new Error(`Missing canonical policy for ${parityCase.id}`);
        expect(parsePolicyMarkdown(parityCase.markdown)).toEqual(parityCase.canonicalPolicy);
        return;
      }
      expect(() => parsePolicyMarkdown(parityCase.markdown)).toThrow();
    });
  }
};

const defineSharedParserHardeningTests = (): void => {
  for (const hardeningCase of parserHardeningFixture.cases) {
    it(`matches the ${hardeningCase.id} warrant-core parser-hardening vector`, () => {
      if (hardeningCase.outcome === "accept") {
        if (!("canonicalPolicy" in hardeningCase)) throw new Error(`Missing canonical policy for ${hardeningCase.id}`);
        expect(parsePolicyMarkdown(hardeningCase.markdown)).toEqual(hardeningCase.canonicalPolicy);
        return;
      }
      expect(() => parsePolicyMarkdown(hardeningCase.markdown)).toThrow();
    });
  }
};

const defineSharedPhase1ParserTests = (): void => {
  for (const parserCase of parserPhase1Fixture.cases) {
    it(`matches the ${parserCase.id} Phase 1 parser vector`, () => {
      if (parserCase.id === "newer-2-minor") {
        expect(parsePolicyMarkdown(parserCase.markdown)).toEqual({
          version: "2.2.0",
          tool_calls: { allowed: ["bash"] },
        });
        return;
      }
      if (parserCase.outcome === "accept") {
        if (!("canonicalPolicy" in parserCase)) throw new Error(`Missing canonical policy for ${parserCase.id}`);
        expect(parsePolicyMarkdown(parserCase.markdown)).toEqual(parserCase.canonicalPolicy);
        return;
      }
      if (!("error" in parserCase)) throw new Error(`Missing error for ${parserCase.id}`);
      expect(() => parsePolicyMarkdown(parserCase.markdown)).toThrow(parserCase.error);
    });
  }

  it("reports non-blocking resource-profile advisories", () => {
    const partial = parsePolicyMarkdown("version: 2.1.1\n\n## repository\nroots: .");
    expect(lintPolicyAdvisories(partial)).toEqual([
      {
        code: "WARRANT_PROFILE_FIELD_MISSING",
        path: "repository.blockOutsideWrites",
        message: "## repository omits recommended field blockOutsideWrites",
      },
      {
        code: "WARRANT_PROFILE_FIELD_MISSING",
        path: "repository.protectGitHistory",
        message: "## repository omits recommended field protectGitHistory",
      },
      {
        code: "WARRANT_PROFILE_FIELD_MISSING",
        path: "repository.protectSensitiveFiles",
        message: "## repository omits recommended field protectSensitiveFiles",
      },
      {
        code: "WARRANT_PROFILE_FIELD_MISSING",
        path: "repository.gitProviders",
        message: "## repository omits recommended field gitProviders",
      },
      {
        code: "WARRANT_PROFILE_FIELD_MISSING",
        path: "repository.requireShim",
        message: "## repository omits recommended field requireShim",
      },
      {
        code: "WARRANT_PROFILE_SHIM_NOT_REQUIRED",
        path: "repository.requireShim",
        message: "## repository does not require a trusted shim",
      },
    ]);

    const complete = parsePolicyMarkdown(
      "version: 2.1.1\n\n## repository\nroots: .\nblock_outside_writes: true\nprotect_git_history: true\nprotect_sensitive_files: true\ngit_providers: github\nrequire_shim: true",
    );
    expect(lintPolicyAdvisories(complete)).toEqual([]);
  });
};

const defineSharedCommitmentTests = (adapter: CryptoAdapter): void => {
  for (const vector of commitmentFixture.vectors) {
    it(`matches the ${vector.id} commitment vector`, async () => {
      const intent = vector.intent as JsonValue;
      expect(canonicalizePgCommitV1(intent)).toBe(vector.canonicalJson);
      expect(new TextDecoder().decode(pgCommitV1Bytes(intent))).toBe(vector.canonicalJson);
      await expect(hashPgCommitV1(adapter, intent)).resolves.toBe(vector.sha256);
    });
  }
};

const defineSharedLaunchScenarioTests = (adapter: CryptoAdapter): void => {
  for (const vector of launchScenarioFixture.vectors) {
    it(`matches the ${vector.id} launch commitment vector`, async () => {
      const intent = vector.request.intent as JsonValue;
      expect(canonicalizePgCommitV1(intent)).toBe(vector.canonicalIntentJson);
      expect(new TextDecoder().decode(pgCommitV1Bytes(intent))).toBe(vector.canonicalIntentJson);
      expect(vector.request.txCommit).toBe(vector.txCommitSha256);
      await expect(hashPgCommitV1(adapter, intent)).resolves.toBe(vector.txCommitSha256);
    });
  }
};

const defineSharedCommitmentRejectionTests = (): void => {
  for (const rejection of commitmentFixture.rejections) {
    it(`rejects the ${rejection.id} commitment vector`, () => {
      expect(() => canonicalizePgCommitV1(pgCommitRejectionValue(rejection.runtimeValueKind))).toThrow(rejection.error);
    });
  }
};

const requiredVectorString = (value: string | undefined, field: string): string => {
  if (value === undefined) throw new Error(`Missing ${field} in signature vector`);
  return value;
};
const requiredEd25519Verifier = (adapter: CryptoAdapter): NonNullable<CryptoAdapter["verifyEd25519"]> => {
  if (!adapter.verifyEd25519) throw new Error("Missing Ed25519 verifier in runtime adapter");
  return adapter.verifyEd25519;
};
const defineSharedSignatureTests = (adapter: CryptoAdapter): void => {
  for (const vector of signatureFixture.vectors) {
    it(`matches the ${vector.id} signature vector`, async () => {
      if (vector.messageUtf8 !== undefined) {
        const key = requiredVectorString(vector.key, "key");
        const publicKey = bytesFromBase64url(signatureFixture.keys[key as "rfc8032Test1"].rawPublicKeyBase64url);
        const signature = bytesFromBase64url(requiredVectorString(vector.signatureBase64url, "signatureBase64url"));
        await expect(requiredEd25519Verifier(adapter)(publicKey, signature, new TextEncoder().encode(vector.messageUtf8))).resolves.toBe(true);
      } else if (vector.signedMarkdown !== undefined) {
        const unsigned = requiredVectorString(vector.unsigned, "unsigned");
        const signature = requiredVectorString(vector.signatureBase64url, "signatureBase64url");
        expect(splitSignatureBlock(vector.signedMarkdown)).toEqual({ unsigned, signature });
        expect(appendSignatureBlock(unsigned, signature)).toBe(vector.signedMarkdown);
      } else {
        expect(() => splitSignatureBlock(requiredVectorString(vector.markdown, "markdown"))).toThrow(vector.error);
      }
    });
  }
};

const envelopeBytes = (vector: { rawUtf8?: string; rawHex?: string }): Uint8Array => {
  if (vector.rawHex !== undefined) return bytesFromHex(vector.rawHex);
  if (vector.rawUtf8 !== undefined) return utf8(vector.rawUtf8);
  throw new Error("Envelope vector must contain rawUtf8 or rawHex");
};

const strictEnvelopeBytes = (vector: { rawUtf8?: string; rawHex?: string; rawByteLength?: number }): Uint8Array => {
  if (vector.rawByteLength !== undefined) return new Uint8Array(vector.rawByteLength);
  return envelopeBytes(vector);
};

const assertStrictCc1Rejection = (vector: typeof envelopeV1Fixture.strictCc1.table[number]): void => {
  try {
    frameWarrantMarkdownBytes(strictEnvelopeBytes(vector), vector.options);
    throw new Error(`Expected ${vector.id} to reject`);
  } catch (error) {
    expect(error).toBeInstanceOf(WarrantEnvelopeError);
    expect(error).toMatchObject({ code: vector.code });
  }
};

const framePreimage = (frame: ReturnType<typeof frameWarrantMarkdownBytes>, kind: string): Uint8Array =>
  kind === "unsigned" ? frame.unsigned : frame.legacyUnsigned;

const assertStrictCc1Acceptance = async (
  vector: typeof envelopeV1Fixture.strictCc1.table[number],
  adapter: CryptoAdapter,
): Promise<void> => {
  const raw = strictEnvelopeBytes(vector);
  const framed = frameWarrantMarkdownBytes(raw, vector.options);
  expect(framed.raw).toEqual(raw);
  expect(decodeUtf8(framed.unsigned)).toBe(vector.unsignedUtf8);
  expect(decodeUtf8(framed.legacyUnsigned)).toBe(vector.legacyUnsignedUtf8);
  expect(framed.signature).toBe(vector.signature);
  if (!vector.verification) return;
  const signature = bytesFromBase64url(vector.signature);
  const publicKey = bytesFromBase64url(vector.verification.publicKeyBase64url);
  const verify = requiredEd25519Verifier(adapter);
  await expect(verify(publicKey, signature, framePreimage(framed, vector.verification.preimage))).resolves.toBe(true);
  await expect(verify(publicKey, signature, framePreimage(framed, vector.verification.rejectedPreimage))).resolves.toBe(false);
};

const assertStrictCc1Vector = (
  vector: typeof envelopeV1Fixture.strictCc1.table[number],
  adapter: CryptoAdapter,
): Promise<void> => {
  if (vector.outcome === "reject") {
    assertStrictCc1Rejection(vector);
    return Promise.resolve();
  }
  return assertStrictCc1Acceptance(vector, adapter);
};

const defineSharedEnvelopeTests = (adapter: CryptoAdapter): void => {
  for (const vector of envelopeV1Fixture.table) {
    it(`matches the ${vector.id} sigil-envelope-v1 vector`, () => {
      const raw = envelopeBytes(vector);
      if (vector.outcome === "reject") {
        try {
          signedEnvelopeParse(raw);
          throw new Error(`Expected ${vector.id} to reject`);
        } catch (error) {
          expect(error).toBeInstanceOf(WarrantEnvelopeError);
          expect((error as WarrantEnvelopeError).code).toBe(vector.code);
        }
        return;
      }
      const parsed = signedEnvelopeParse(raw);
      expect(decodeUtf8(parsed.payload)).toBe(vector.payloadUtf8);
      expect(parsed.signature).toBe(vector.signature);
    });
  }

  it("uses unsigned source bytes as the signing payload", () => {
    const vector = envelopeV1Fixture.families.unsignedSource;
    expect(decodeUtf8(unsignedSigningPayload(utf8(vector.rawUtf8)))).toBe(vector.payloadUtf8);
  });

  it("reduces an empty placeholder before signing", () => {
    const vector = envelopeV1Fixture.families.emptyPlaceholder;
    const placeholder = signedEnvelopeParse(utf8(vector.rawUtf8));
    expect(placeholder.signature).toBeUndefined();
    expect(decodeUtf8(placeholder.payload)).toBe(vector.payloadUtf8);
    const signed = emit(unsignedSigningPayload(placeholder.payload), "placeholder_signature");
    expect(decodeUtf8(signedEnvelopeParse(signed).payload)).toBe(vector.payloadUtf8);
  });

  it("obeys the signed envelope round-trip law", () => {
    const vector = envelopeV1Fixture.families.signedSource;
    const payload = unsignedSigningPayload(utf8(vector.sourceUtf8));
    const signed = emit(payload, vector.signature);
    expect(signedEnvelopeParse(signed)).toEqual({ payload, signature: vector.signature });
  });

  it("uses edited bytes when re-signing a detached envelope", () => {
    const vector = envelopeV1Fixture.families.resignAfterEdit;
    const payload = unsignedSigningPayload(utf8(vector.editedUtf8));
    const signed = emit(payload, vector.signature);
    expect(decodeUtf8(signedEnvelopeParse(signed).payload)).toBe(vector.payloadUtf8);
  });

  for (const vector of envelopeV1Fixture.strictCc1.table) {
    it(`matches the ${vector.id} strict CC-1 framing vector`, () => assertStrictCc1Vector(vector, adapter));
  }

  it("frames a current Warrant Builder signed output without changing its raw bytes", () => {
    // Captured from the current Warrant Builder serializer shape (sigilcore
    // origin/main e9aa7321f50952b9b8b66d57dc1895635d34996f). Builder signs
    // canonical policy text then writes the final block with two LF bytes.
    const builderUnsigned = [
      "version: 2.1.0",
      "",
      "## repository",
      "roots: .",
      "block_outside_writes: true",
      "protect_git_history: true",
      "protect_sensitive_files: true",
      "git_providers: generic, github",
      "require_shim: true",
      "",
      "## tool_calls",
      "allowed: web_fetch",
    ].join("\n");
    const raw = signedWarrant(builderUnsigned);
    const framed = frameWarrantMarkdownBytes(raw);
    expect(framed.raw).toEqual(raw);
    expect(decodeUtf8(framed.unsigned)).toBe(`${builderUnsigned}\n`);
    expect(parsePolicyMarkdown(decodeUtf8(framed.unsigned))).toEqual(parsePolicyMarkdown(builderUnsigned));
  });

  it("frames three current Manual Warrant templates without changing their raw bytes", () => {
    // These policy vectors are byte-pinned Manual template bodies. The three
    // distinct profiles exercise the Manual Warrant's repository, tool-call,
    // and EVM authoring paths after its normal final-block signing step.
    const expectedSlugs = ["claude-code-agent", "customer-support-agent", "stablecoin-treasury-agent"];
    const fixtures = expectedSlugs.map((slug) => {
      const fixture = policyFixture.fixtures.find((candidate) => candidate.slug === slug);
      if (!fixture) throw new Error(`Missing Manual Warrant fixture ${slug}`);
      return fixture;
    });
    expect(fixtures).toHaveLength(3);
    for (const fixture of fixtures) {
      const unsigned = fixture.templateBody.replace(/\n## signature\n[\s\S]*$/, "").trimEnd();
      const raw = signedWarrant(unsigned);
      const framed = frameWarrantMarkdownBytes(raw);
      expect(framed.raw).toEqual(raw);
      expect(decodeUtf8(framed.unsigned)).toBe(`${unsigned}\n`);
      expect(parsePolicyMarkdown(decodeUtf8(framed.unsigned))).toEqual(parsePolicyMarkdown(unsigned));
    }
  });

};

const defineSharedPhaseOneParserTests = (adapter: CryptoAdapter): void => {
  for (const vector of parserPhase1Fixture.cases) {
    it(`matches the ${vector.id} Phase 1 parser vector`, async () => {
      if (vector.id === "newer-2-minor") {
        const policy = parsePolicyMarkdown(vector.markdown);
        expect(policy).toEqual({ version: "2.2.0", tool_calls: { allowed: ["bash"] } });
        await expect(hashPolicy(adapter, policy)).resolves.toBe(
          responsePolicyFormat1Fixture.compiledFormat1.newer2MinorPolicySha256,
        );
        await expect(hashPolicy(adapter, {
          version: "2.2.0",
          tool_calls: { allowed: ["bash"] },
        })).resolves.toBe(responsePolicyFormat1Fixture.compiledFormat1.newer2MinorPolicySha256);
        return;
      }
      if (vector.outcome === "reject") {
        expect(() => parsePolicyMarkdown(vector.markdown)).toThrow(vector.error);
        return;
      }
      const policy = parsePolicyMarkdown(vector.markdown);
      expect(policy).toEqual(vector.canonicalPolicy);
      // The hash is part of the cross-runtime parse contract: every accepted
      // vector must produce the same canonical bytes before consumers cut over.
      expect(await hashPolicy(adapter, policy)).toBe(await hashPolicy(adapter, vector.canonicalPolicy));
    });
  }
};

const defineSharedPolicyCommitmentAndSignatureVectorTests = (runtime: string, adapter: CryptoAdapter): void => {
  describe(`${runtime} shared policy, commitment, and signature vectors`, () => {
    defineSharedPolicyFixtureTests(adapter);
    defineSharedSignParityTests();
    defineSharedParserHardeningTests();
    defineSharedPhase1ParserTests();
    defineSharedCommitmentTests(adapter);
    defineSharedLaunchScenarioTests(adapter);
    defineSharedCommitmentRejectionTests();
    defineSharedSignatureTests(adapter);
    defineSharedEnvelopeTests(adapter);
    defineSharedPhaseOneParserTests(adapter);
  });
};

export const defineSharedRuntimeVectorTests = (runtime: string, adapter: CryptoAdapter): void => {
  defineConsumerCompatibilityVectorTests(runtime);

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

  it(`serializes sparse policy arrays as null in ${runtime}`, async () => {
    const singleHole = Array<unknown>(1);
    const nested = Array<unknown>(3);
    nested[1] = Array<unknown>(2);
    const policy = { nested, singleHole };
    const expected = '{"nested":[null,[null,null],null],"singleHole":[null]}';

    expect(canonicalizePolicyObject([])).toBe("[]");
    expect(canonicalizePolicyObject(singleHole)).toBe("[null]");
    expect(canonicalizePolicyObject(singleHole)).not.toBe(canonicalizePolicyObject([]));
    expect(canonicalizePolicyObject(policy)).toBe(expected);
    expect(policyCanonicalBytes(policy)).toEqual(new TextEncoder().encode(expected));
    await expect(hashPolicy(adapter, policy)).resolves.toBe("326167890b93712a7dd21556591c1fed6389d6abb7da66f17947100274ead50e");
    await expect(hashPolicy(adapter, singleHole)).resolves.toBe("1d8fc6ceb1f94c6326d6d5483d258fcb2e179e9869325b245d105c2219bf69fd");
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
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\ndaily_evm_limit_eth: 9000000000000.0000001")).toThrow("positive decimal");
    expect(parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\ndaily_evm_limit_eth: 9223372036854.775807").soft_limits?.dailyEvmLimitEth).toBe(Number("9223372036854.775807"));
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\ndaily_evm_limit_eth: 9223372036854.775808")).toThrow("positive decimal");
    expect(parsePolicyMarkdown("version: 1.0.0\n\n## tool_calls\nallowed: bash\n\n## soft_limits\ndaily_evm_limit_eth: 1ETH").soft_limits?.dailyEvmLimitEth).toBe(1);
    for (const version of ["1.0.0", "2.0.0", "2.1.0"]) {
      expect(() => parsePolicyMarkdown(`version: ${version}\n\n## soft_limits\ndaily_evm_limit_eth: 1e-1`)).toThrow("positive decimal");
      expect(() => parsePolicyMarkdown(`version: ${version}\n\n## soft_limits\ndaily_evm_limit_eth: 1.0000001`)).toThrow("positive decimal");
    }
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
  defineSharedMcpToolOverlapTests(runtime);
  defineSharedResponsePolicyFormat1Tests(runtime, adapter);
  defineSharedToolCallControlTests(runtime);
  defineSharedPolicyCommitmentAndSignatureVectorTests(runtime, adapter);
};
