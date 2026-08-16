import { describe, expect, it } from "vitest";

import {
  canonicalizeCompiledResponsePolicyFormat2,
  canonicalizePgCommitV1,
  compileResponsePolicyFormat1,
  compileResponsePolicyFormat2,
  compiledResponsePolicyFormat2Bytes,
  hashCompiledResponsePolicyFormat2,
  parsePolicyMarkdown,
  serializePolicyMarkdown,
  validateAndParsePolicyMarkdown,
  validateCompiledResponsePolicyFormat2,
  verifyCompiledResponsePolicyFormat1,
  verifyCompiledResponsePolicyFormat2,
} from "../src/index.js";
import { createNodeCryptoAdapter } from "../src/crypto/node.js";
import responsePolicyFormat1Fixture from "./vectors/response-policy-format1.json";

const RULESET_DIGEST = "dd07aff020e1d03e08501105dc53bb6943ffbdb50629cac7c7b4b03d1bd7ce46";
const CLASS_CATALOG_DIGEST = "3f77896cf5a15475c0e9847201ffaa41f4b117b4d8e5051d035f982f55d3098d";
const POLICY_HASH = "7".repeat(64);
const ISSUED_AT = Date.parse("2026-08-06T00:00:00Z") / 1000;
const encoder = new TextEncoder();
const base64url = (value: Uint8Array): string => Buffer.from(value).toString("base64url");
const COMPILE_INPUT = {
  issuer: "https://sign.sigil.example",
  keyId: "sign-key-1",
  tenantId: "tenant-1",
  taskId: "task-1",
  policyHash: POLICY_HASH,
  issuedAt: ISSUED_AT,
  expiresAt: ISSUED_AT + 300,
  revocationEpoch: 9,
  deterministicRulesetDigest: RULESET_DIGEST,
  classCatalogDigest: CLASS_CATALOG_DIGEST,
} as const;

const source = [
  "version: 2.3.0",
  "",
  "## custom",
  "response.deny_string: \"ignore previous instructions\"",
  "",
  "## mcp",
  "allowed_tools: fetch.server.fetch, api.server.request",
  "response.web_fetch_tools: fetch.server.fetch",
  "response.http_tools: api.server.request",
  "response.deterministic_ruleset: sof-response-rules-v1",
  "response.block_classes: prompt_injection",
  "response.redact_classes: pii, secret",
  "response.scanner.required: true",
  "response.scanner.profile: operator-presidio-v1",
  "response.scanner.classes: pii, prompt_injection",
  "response.scanner.min_confidence: 0.85",
  "response.observe_classes: prompt_injection",
  "response.observe_until: 2026-09-05T00:00:00Z",
].join("\n");

describe("CompiledResponsePolicy format 2", () => {
  it("accepts every closed Policy 2.3 response key at the structured authoring boundary", () => {
    const result = validateAndParsePolicyMarkdown(source);
    expect(result.errors).toEqual([]);
    expect(result.policy).toEqual(parsePolicyMarkdown(source));
  });

  it("still rejects an undeclared Policy 2.3 response key", () => {
    const result = validateAndParsePolicyMarkdown(
      source.replace(
        "response.scanner.profile: operator-presidio-v1",
        "response.scanner.endpoint: https://scanner.invalid",
      ),
    );
    expect(result.policy).toBeUndefined();
    expect(result.errors).toContainEqual(expect.objectContaining({
      code: "WARRANT_UNSUPPORTED_KEY",
      path: "mcp.response.scanner.endpoint",
    }));
  });

  it("parses, serializes, compiles, and hashes the closed Policy 2.3 contract", async () => {
    const parsed = parsePolicyMarkdown(source);
    expect(serializePolicyMarkdown(parsed)).toBe(source);
    const compiled = compileResponsePolicyFormat2(parsed, COMPILE_INPUT);
    expect(compiled).toMatchObject({
      formatVersion: 2,
      policyVersion: "2.3.0",
      policy: {
        redactClasses: ["pii", "secret"],
        scanner: {
          required: true,
          profile: "operator-presidio-v1",
          classes: ["pii", "prompt_injection"],
          minConfidence: 0.85,
        },
        observe: {
          classes: ["prompt_injection"],
          until: "2026-09-05T00:00:00Z",
        },
      },
    });
    expect(() => validateCompiledResponsePolicyFormat2(compiled)).not.toThrow();
    expect(new TextDecoder().decode(compiledResponsePolicyFormat2Bytes(compiled)))
      .toBe(canonicalizeCompiledResponsePolicyFormat2(compiled));
    await expect(hashCompiledResponsePolicyFormat2(createNodeCryptoAdapter(), compiled))
      .resolves.toMatch(/^[0-9a-f]{64}$/);
  });

  it("rejects downgrade, hostile fields, malformed scanner controls, and invalid observe windows", () => {
    const parsed = parsePolicyMarkdown(source);
    expect(() => compileResponsePolicyFormat1(parsed, COMPILE_INPUT)).toThrow("Policy 2.2.x");
    const compiled = compileResponsePolicyFormat2(parsed, COMPILE_INPUT);
    expect(() => validateCompiledResponsePolicyFormat2({ ...compiled, formatVersion: 1 }))
      .toThrow("formatVersion must equal 2");
    expect(() => validateCompiledResponsePolicyFormat2({ ...compiled, policyVersion: "2.2.9" }))
      .toThrow("policyVersion must match 2.3.x");
    expect(() => validateCompiledResponsePolicyFormat2({
      ...compiled,
      policy: { ...compiled.policy, scanner: { ...compiled.policy.scanner, endpoint: "https://scanner.invalid" } },
    })).toThrow("policy.scanner contains unknown field endpoint");
    expect(() => parsePolicyMarkdown(source.replace("0.85", "0.8500")))
      .toThrow("canonical decimal");
    expect(() => parsePolicyMarkdown(source.replace("operator-presidio-v1", "https://scanner.invalid")))
      .toThrow("not a URL");
    expect(() => parsePolicyMarkdown(source.replace("response.observe_until: 2026-09-05T00:00:00Z", "")))
      .toThrow("response.observe_until is required");
    expect(() => compileResponsePolicyFormat2(
      parsePolicyMarkdown(source.replace("2026-09-05T00:00:00Z", "2026-09-05T00:00:01Z")),
      COMPILE_INPUT,
    )).toThrow("no more than 30 days");
  });

  it("verifies a canonical Ed25519 format 2 envelope and rejects it as format 1", async () => {
    const adapter = createNodeCryptoAdapter();
    const signEd25519 = adapter.signEd25519;
    if (signEd25519 === undefined) throw new Error("Node test adapter must sign Ed25519");
    const compiled = compileResponsePolicyFormat2(parsePolicyMarkdown(source), COMPILE_INPUT);
    const fixture = responsePolicyFormat1Fixture.jwsFormat1;
    const privateKey = new Uint8Array(Buffer.from(fixture.privateKeyPkcs8Base64url, "base64url"));
    const publicKey = new Uint8Array(Buffer.from(fixture.publicKeySpkiBase64url, "base64url"));
    const header = canonicalizePgCommitV1({
      alg: "EdDSA",
      kid: compiled.keyId,
      typ: "sof-compiled-response-policy+jws",
    });
    const headerSegment = base64url(encoder.encode(header));
    const payloadSegment = base64url(compiledResponsePolicyFormat2Bytes(compiled));
    const signature = await signEd25519(privateKey, encoder.encode(`${headerSegment}.${payloadSegment}`));
    const compact = `${headerSegment}.${payloadSegment}.${base64url(signature)}`;
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
    await expect(verifyCompiledResponsePolicyFormat2(adapter, compact, context))
      .resolves.toMatchObject({ formatVersion: 2, policyVersion: "2.3.0" });
    await expect(verifyCompiledResponsePolicyFormat1(adapter, compact, context))
      .rejects.toThrow("formatVersion must equal 1");
  });
});
