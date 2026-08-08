import { describe, expect, it } from "vitest";

import {
  canonicalizePgCommitV1,
  COMPILED_RESPONSE_POLICY_FORMAT_1_BOUNDS,
  COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS,
  compileResponsePolicyFormat1,
  compiledResponsePolicyFormat1Bytes,
  parsePolicyMarkdown,
  validateCompiledResponsePolicyFormat1,
  verifyCompiledResponsePolicyFormat1,
} from "../src/index.js";
import { createNodeCryptoAdapter } from "../src/crypto/node.js";
import responsePolicyFormat1Fixture from "./vectors/response-policy-format1.json";

const RULESET_DIGEST = "dd07aff020e1d03e08501105dc53bb6943ffbdb50629cac7c7b4b03d1bd7ce46";
const CLASS_CATALOG_DIGEST = "3f77896cf5a15475c0e9847201ffaa41f4b117b4d8e5051d035f982f55d3098d";
const POLICY_HASH = "3".repeat(64);
const encoder = new TextEncoder();
const base64url = (value: Uint8Array): string => Buffer.from(value).toString("base64url");
const COMPILE_INPUT = {
  issuer: "https://sign.sigil.example",
  keyId: "sign-key-1",
  tenantId: "tenant-1",
  taskId: "task-1",
  policyHash: POLICY_HASH,
  issuedAt: 1_800_000_000,
  expiresAt: 1_800_000_300,
  revocationEpoch: 7,
  deterministicRulesetDigest: RULESET_DIGEST,
  classCatalogDigest: CLASS_CATALOG_DIGEST,
} as const;

const compiledFixture = () => compileResponsePolicyFormat1(
  parsePolicyMarkdown([
    "version: 2.2.0",
    "",
    "## mcp",
    "allowed_tools: fetch.server.fetch, api.server.request",
    "response.web_fetch_tools: fetch.server.fetch",
    "response.http_tools: api.server.request",
    "response.deterministic_ruleset: sof-response-rules-v1",
    "response.block_classes: prompt_injection, secret",
    "",
    "## custom",
    "response.deny_string: \"ignore previous instructions\"",
  ].join("\n")),
  {
    issuer: "https://sign.sigil.example",
    keyId: "sign-key-1",
    tenantId: "tenant-1",
    taskId: "task-1",
    policyHash: POLICY_HASH,
    issuedAt: 1_800_000_000,
    expiresAt: 1_800_000_300,
    revocationEpoch: 7,
    deterministicRulesetDigest: RULESET_DIGEST,
    classCatalogDigest: CLASS_CATALOG_DIGEST,
  },
);

describe("CompiledResponsePolicy format 1", () => {
  it("rejects unknown payload fields and format-policy mismatches", () => {
    const compiled = compiledFixture();
    const source = parsePolicyMarkdown("version: 2.2.0\n\n## mcp\nallowed_tools: fetch.server.fetch\nresponse.web_fetch_tools: fetch.server.fetch\nresponse.deterministic_ruleset: sof-response-rules-v1");
    expect(() => compileResponsePolicyFormat1(source, COMPILE_INPUT)).not.toThrow();
    for (const unknownKey of ["redactClasses", "scanner"]) {
      expect(() => compileResponsePolicyFormat1({
        ...source,
        mcp: {
          ...source.mcp,
          response: { ...source.mcp?.response, [unknownKey]: ["secret"] },
        },
      }, COMPILE_INPUT)).toThrow(`mcp.response contains unknown field ${unknownKey}`);
    }
    const invalidToolLists: unknown[] = [
      "prefixfetch.server.fetchsuffix",
      [],
      ["fetch.server.fetch", 3],
      ["fetch.server.fetch", "fetch.server.fetch"],
      ["fetch.*.invalid"],
      ["fetch.server.fetch,other.server.tool"],
      ["fetch.server.fetch\nother.server.tool"],
      [" fetch.server.fetch"],
    ];
    for (const invalid of invalidToolLists) {
      for (const { key, mcp } of [
        {
          key: "allowedTools",
          mcp: {
            ...source.mcp,
            allowedTools: invalid as never,
            blockedTools: ["blocked.*"],
          },
        },
        {
          key: "blockedTools",
          mcp: {
            ...source.mcp,
            allowedTools: ["fetch.server.fetch", "other.*"],
            blockedTools: invalid as never,
          },
        },
      ] as const) {
        expect(() => compileResponsePolicyFormat1({
          ...source,
          mcp,
        }, COMPILE_INPUT)).toThrow(`mcp.${key} must contain unique exact values or one trailing * wildcard`);
      }
    }
    expect(() => compileResponsePolicyFormat1({
      ...source,
      mcp: {
        ...source.mcp,
        allowedTools: ["fetch.server.fetch", "other.*"],
        blockedTools: ["blocked.*"],
      },
    }, COMPILE_INPUT)).not.toThrow();
    expect(() => validateCompiledResponsePolicyFormat1({ ...compiled, scanner: {} })).toThrow("unknown field scanner");
    expect(() => validateCompiledResponsePolicyFormat1({ ...compiled, policyVersion: "2.3.0" })).toThrow("2.2.x");
    expect(() => validateCompiledResponsePolicyFormat1({
      ...compiled,
      coveredTools: [...compiled.coveredTools, "other.server.tool"],
    })).toThrow("exact sorted policy coverage union");
    expect(() => validateCompiledResponsePolicyFormat1({
      ...compiled,
      policy: {
        ...compiled.policy,
        denyStrings: ["x".repeat(COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.maxPolicyStringBytes + 1)],
      },
    })).toThrow("policy.denyStrings entry exceeds");
    expect(() => validateCompiledResponsePolicyFormat1({
      ...compiled,
      policy: { ...compiled.policy, denyStrings: ["z-last", "a-first"] },
    })).toThrow("policy.denyStrings must be lexicographically sorted");
    expect(() => compileResponsePolicyFormat1({
      ...parsePolicyMarkdown("version: 2.2.0\n\n## mcp\nallowed_tools: fetch.server.fetch\nresponse.web_fetch_tools: fetch.server.fetch\nresponse.deterministic_ruleset: sof-response-rules-v1"),
      mcp: {
        allowedTools: ["fetch.server.fetch"],
        response: {
          webFetchTools: "fetch.server.fetch",
          deterministicRuleset: "sof-response-rules-v1",
        },
      },
    }, {
      issuer: "https://sign.sigil.example",
      keyId: "sign-key-1",
      tenantId: "tenant-1",
      taskId: "task-1",
      policyHash: POLICY_HASH,
      issuedAt: 1_800_000_000,
      expiresAt: 1_800_000_300,
      revocationEpoch: 7,
      deterministicRulesetDigest: RULESET_DIGEST,
      classCatalogDigest: CLASS_CATALOG_DIGEST,
    })).toThrow("mcp.response.webFetchTools must be a nonempty string array");
    expect(() => compileResponsePolicyFormat1({
      ...parsePolicyMarkdown("version: 2.2.0\n\n## mcp\nallowed_tools: fetch.server.fetch\nresponse.web_fetch_tools: fetch.server.fetch\nresponse.deterministic_ruleset: sof-response-rules-v1"),
      mcp: {
        allowedTools: ["fetch.server.fetch"],
        response: {
          webFetchTools: ["fetch.server.fetch"],
          deterministicRuleset: "forged-ruleset",
        },
      },
    }, {
      issuer: "https://sign.sigil.example",
      keyId: "sign-key-1",
      tenantId: "tenant-1",
      taskId: "task-1",
      policyHash: POLICY_HASH,
      issuedAt: 1_800_000_000,
      expiresAt: 1_800_000_300,
      revocationEpoch: 7,
      deterministicRulesetDigest: RULESET_DIGEST,
      classCatalogDigest: CLASS_CATALOG_DIGEST,
    })).toThrow("mcp.response.deterministicRuleset must equal sof-response-rules-v1");
    expect(() => compileResponsePolicyFormat1({
      ...parsePolicyMarkdown("version: 2.2.0\n\n## mcp\nallowed_tools: fetch.server.fetch\nresponse.web_fetch_tools: fetch.server.fetch\nresponse.deterministic_ruleset: sof-response-rules-v1"),
      mcp: {
        allowedTools: ["other.server.tool"],
        response: {
          webFetchTools: ["fetch.server.fetch"],
          deterministicRuleset: "sof-response-rules-v1",
        },
      },
    }, {
      issuer: "https://sign.sigil.example",
      keyId: "sign-key-1",
      tenantId: "tenant-1",
      taskId: "task-1",
      policyHash: POLICY_HASH,
      issuedAt: 1_800_000_000,
      expiresAt: 1_800_000_300,
      revocationEpoch: 7,
      deterministicRulesetDigest: RULESET_DIGEST,
      classCatalogDigest: CLASS_CATALOG_DIGEST,
    })).toThrow("exact literal member of allowed_tools");
  });

  it("rejects duplicate source deny rules and oversized producer payloads", () => {
    const base = parsePolicyMarkdown(
      "version: 2.2.0\n\n## mcp\nallowed_tools: fetch.server.fetch\nresponse.web_fetch_tools: fetch.server.fetch\nresponse.deterministic_ruleset: sof-response-rules-v1",
    );
    expect(() => compileResponsePolicyFormat1({
      ...base,
      custom: {
        rules: [
          { name: "deny-one", type: "response_deny_string", value: "duplicate" },
          { name: "deny-two", type: "response_deny_string", value: "duplicate" },
        ],
      },
    }, COMPILE_INPUT)).toThrow("custom.response.deny_string values must be unique");

    const sortedDenyPolicy = compileResponsePolicyFormat1({
      ...base,
      custom: {
        rules: [
          { name: "deny-z", type: "response_deny_string", value: "z-last" },
          { name: "deny-a", type: "response_deny_string", value: "a-first" },
        ],
      },
    }, COMPILE_INPUT);
    expect(sortedDenyPolicy.policy.denyStrings).toEqual(["a-first", "z-last"]);

    const coveredTools = Array.from(
      { length: 300 },
      (_, index) => `server-${index.toString().padStart(3, "0")}.${"x".repeat(240)}`,
    );
    expect(() => compileResponsePolicyFormat1({
      ...base,
      mcp: {
        allowedTools: coveredTools,
        response: {
          webFetchTools: coveredTools,
          deterministicRuleset: "sof-response-rules-v1",
        },
      },
    }, COMPILE_INPUT)).toThrow("Compiled response policy payload exceeds 65536 bytes");

    const denyRules = Array.from({ length: 20 }, (_, index) => ({
      name: `deny-${index}`,
      type: "response_deny_string",
      value: `${"x".repeat(4000)}${index.toString().padStart(3, "0")}`,
    }));
    expect(() => compileResponsePolicyFormat1({
      ...base,
      custom: { rules: denyRules },
    }, COMPILE_INPUT)).toThrow("Compiled response policy payload exceeds 65536 bytes");
  });

  it("rejects non-literal compiled coverage across validation and signed verification", async () => {
    const compiled = compiledFixture();
    const adapter = createNodeCryptoAdapter();
    const signEd25519 = adapter.signEd25519;
    if (signEd25519 === undefined) throw new Error("format 1 regression requires an Ed25519 signer");
    const fixture = responsePolicyFormat1Fixture.jwsFormat1;
    const privateKey = new Uint8Array(Buffer.from(fixture.privateKeyPkcs8Base64url, "base64url"));
    const publicKey = new Uint8Array(Buffer.from(fixture.publicKeySpkiBase64url, "base64url"));
    const headerSegment = base64url(encoder.encode(fixture.protectedHeaderCanonicalJson));
    const context = {
      publicKey,
      issuer: compiled.issuer,
      keyId: compiled.keyId,
      tenantId: compiled.tenantId,
      taskId: compiled.taskId,
      policyHash: compiled.policyHash,
      revocationEpoch: compiled.revocationEpoch,
      deterministicRulesetDigest: RULESET_DIGEST,
      classCatalogDigest: CLASS_CATALOG_DIGEST,
      now: compiled.issuedAt,
    };

    for (const invalidTool of [
      "*.server.request",
      "api.server.request,other.server.request",
      "api.server.request\nother.server.request",
      " api.server.request",
    ]) {
      const invalidPolicy = {
        ...compiled,
        coveredTools: [invalidTool, "fetch.server.fetch"],
        policy: { ...compiled.policy, httpTools: [invalidTool] },
      };
      expect(() => validateCompiledResponsePolicyFormat1(invalidPolicy))
        .toThrow("coveredTools must contain exact literal tool names");

      const payloadSegment = base64url(encoder.encode(canonicalizePgCommitV1(invalidPolicy)));
      const signature = await signEd25519(
        privateKey,
        encoder.encode(`${headerSegment}.${payloadSegment}`),
      );
      await expect(verifyCompiledResponsePolicyFormat1(
        adapter,
        `${headerSegment}.${payloadSegment}.${base64url(signature)}`,
        context,
      )).rejects.toThrow("coveredTools must contain exact literal tool names");

      expect(() => validateCompiledResponsePolicyFormat1({
        ...invalidPolicy,
        coveredTools: compiled.coveredTools,
      })).toThrow("policy.httpTools must contain exact literal tool names");
    }
  });

  it("verifies canonical compact JWS bytes and trusted claims", async () => {
    const adapter = createNodeCryptoAdapter();
    const jwsFixture = responsePolicyFormat1Fixture.jwsFormat1;
    const privateKey = new Uint8Array(Buffer.from(jwsFixture.privateKeyPkcs8Base64url, "base64url"));
    const publicKey = new Uint8Array(Buffer.from(jwsFixture.publicKeySpkiBase64url, "base64url"));
    const payload = JSON.parse(responsePolicyFormat1Fixture.compiledFormat1.canonicalJson);
    const protectedHeader = JSON.parse(jwsFixture.protectedHeaderCanonicalJson);
    const headerSegment = base64url(encoder.encode(jwsFixture.protectedHeaderCanonicalJson));
    const payloadSegment = base64url(compiledResponsePolicyFormat1Bytes(payload));
    const compactJws = jwsFixture.compactJws;
    const signatureSegment = compactJws.split(".")[2];
    const signEd25519 = adapter.signEd25519;
    if (signatureSegment === undefined || signEd25519 === undefined) {
      throw new Error("format 1 signing fixture requires a signature segment and Ed25519 signer");
    }
    const signature = new Uint8Array(Buffer.from(signatureSegment, "base64url"));
    expect(compactJws.startsWith(`${headerSegment}.${payloadSegment}.`)).toBe(true);
    const context = {
      publicKey,
      issuer: payload.issuer,
      keyId: payload.keyId,
      tenantId: payload.tenantId,
      taskId: payload.taskId,
      policyHash: payload.policyHash,
      revocationEpoch: payload.revocationEpoch,
      deterministicRulesetDigest: RULESET_DIGEST,
      classCatalogDigest: CLASS_CATALOG_DIGEST,
      now: payload.issuedAt,
    };
    const verified = await verifyCompiledResponsePolicyFormat1(adapter, compactJws, context);
    expect(verified).toMatchObject(payload);
    expect(verified.compiledPolicyDigest).toBe(jwsFixture.expectedCompiledPolicyDigest);
    const { audience, ...payloadWithoutAudience } = payload;
    const nonCanonicalPayloadSegment = base64url(encoder.encode(JSON.stringify({
      ...payloadWithoutAudience,
      audience,
    })));
    const nonCanonicalPayloadSignature = await signEd25519(
      privateKey,
      encoder.encode(`${headerSegment}.${nonCanonicalPayloadSegment}`),
    );
    await expect(verifyCompiledResponsePolicyFormat1(
      adapter,
      `${headerSegment}.${nonCanonicalPayloadSegment}.${base64url(nonCanonicalPayloadSignature)}`,
      context,
    )).rejects.toThrow("payload must be pg-commit-v1 canonical JSON");
    const nonCanonicalHeaderSegment = base64url(encoder.encode(JSON.stringify({
      typ: protectedHeader.typ,
      kid: protectedHeader.kid,
      alg: protectedHeader.alg,
    })));
    const nonCanonicalHeaderSignature = await signEd25519(
      privateKey,
      encoder.encode(`${nonCanonicalHeaderSegment}.${payloadSegment}`),
    );
    await expect(verifyCompiledResponsePolicyFormat1(
      adapter,
      `${nonCanonicalHeaderSegment}.${payloadSegment}.${base64url(nonCanonicalHeaderSignature)}`,
      context,
    )).rejects.toThrow("protected header must be pg-commit-v1 canonical JSON");
    await expect(verifyCompiledResponsePolicyFormat1(
      adapter,
      jwsFixture.invalid.signatureCompactJws,
      context,
    )).rejects.toThrow();
    await expect(verifyCompiledResponsePolicyFormat1(adapter, compactJws, {
      ...context,
      taskId: jwsFixture.invalid.claimTaskId,
    })).rejects.toThrow("taskId mismatch");
    for (const [field, value, message] of [
      ["issuer", "https://wrong.example", "issuer mismatch"],
      ["keyId", "wrong-key", "keyId mismatch"],
      ["tenantId", "wrong-tenant", "tenantId mismatch"],
      ["policyHash", "4".repeat(64), "policyHash mismatch"],
      ["revocationEpoch", context.revocationEpoch + 1, "revocationEpoch mismatch"],
      ["deterministicRulesetDigest", "4".repeat(64), "ruleset digest mismatch"],
      ["classCatalogDigest", "4".repeat(64), "class catalog digest mismatch"],
    ] as const) {
      await expect(verifyCompiledResponsePolicyFormat1(adapter, compactJws, {
        ...context,
        [field]: value,
      })).rejects.toThrow(message);
    }
    await expect(verifyCompiledResponsePolicyFormat1(
      adapter,
      42 as never,
      context,
    )).rejects.toThrow("JWS must be a string");
    await expect(verifyCompiledResponsePolicyFormat1(
      adapter,
      "A".repeat(100_000),
      context,
    )).rejects.toThrow("JWS exceeds");
    await expect(verifyCompiledResponsePolicyFormat1(
      adapter,
      `${"A".repeat(Math.ceil(COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.maxProtectedHeaderBytes * 4 / 3) + 1)}.${payloadSegment}.${base64url(signature)}`,
      context,
    )).rejects.toThrow("protected header exceeds");
    await expect(verifyCompiledResponsePolicyFormat1(
      adapter,
      `${headerSegment}.${"A".repeat(Math.ceil(COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.maxPayloadBytes * 4 / 3) + 1)}.${base64url(signature)}`,
      context,
    )).rejects.toThrow("payload exceeds");
    await expect(verifyCompiledResponsePolicyFormat1(adapter, compactJws, {
      ...context,
      now: jwsFixture.invalid.notYetValidNow,
    })).rejects.toThrow("not yet valid");
    await expect(verifyCompiledResponsePolicyFormat1(adapter, compactJws, {
      ...context,
      now: jwsFixture.invalid.expiredNow,
    })).rejects.toThrow("expired");
    const { formatVersion: _formatVersion, ...payloadWithoutFormatVersion } = payload;
    const missingFormatVersionSegment = base64url(encoder.encode(
      canonicalizePgCommitV1(payloadWithoutFormatVersion),
    ));
    // skipcq: JS-0061 - Deliberately exercise inherited-field rejection, then restore the prototype in finally.
    Object.defineProperty(Object.prototype, "formatVersion", {
      configurable: true,
      value: 1,
    });
    try {
      await expect(verifyCompiledResponsePolicyFormat1(
        adapter,
        `${headerSegment}.${missingFormatVersionSegment}.${base64url(signature)}`,
        context,
      )).rejects.toThrow("missing required field formatVersion");
    } finally {
      delete (Object.prototype as { formatVersion?: number }).formatVersion;
    }
    let overDepth: Record<string, unknown> = {};
    for (let depth = 0; depth < COMPILED_RESPONSE_POLICY_FORMAT_1_BOUNDS.maxNestingDepth; depth += 1) {
      overDepth = { nested: overDepth };
    }
    const overDepthSegment = base64url(encoder.encode(canonicalizePgCommitV1(overDepth)));
    await expect(verifyCompiledResponsePolicyFormat1(
      adapter,
      `${headerSegment}.${overDepthSegment}.${base64url(signature)}`,
      context,
    )).rejects.toThrow("nesting levels");
  });
});
