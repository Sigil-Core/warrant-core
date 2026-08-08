import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  AUTHORING_CAPABILITY_MANIFEST,
  DEPLOY_FEATURE_KEYS,
  DEPLOY_FEATURE_PATHS,
  PARSER_CONTRACT_DIGEST,
  PARSER_CONTRACT_DIGEST_INPUT,
  POLICY_VERSION_RANGES,
  SIGN_CAPABILITIES_SCHEMA_VERSION,
  SIGN_CAPABILITY_DEPLOY_PATHS,
  SIGN_CAPABILITY_FEATURE_KEYS,
  SIGIL_SIGN_ENGINE_VERSION,
  parsePolicyMarkdown,
  runRepresentabilityConstraints,
  serializePolicyMarkdown,
  validateAndParsePolicyMarkdown,
} from "../src/index.js";

describe("Phase 1 authoring core", () => {
  it("maps every advertised deployment feature to manifest paths and vice versa", () => {
    for (const feature of DEPLOY_FEATURE_KEYS) expect(DEPLOY_FEATURE_PATHS[feature].length).toBeGreaterThan(0);
    for (const entry of Object.values(AUTHORING_CAPABILITY_MANIFEST)) {
      expect(DEPLOY_FEATURE_KEYS).toContain(entry.deploy_feature_key);
    }
  });

  it("keeps the complete Sign contract bidirectionally mapped to deployable authoring paths", () => {
    expect(SIGN_CAPABILITY_FEATURE_KEYS).toEqual(DEPLOY_FEATURE_KEYS);
    const mappedPaths = new Set(Object.values(SIGN_CAPABILITY_DEPLOY_PATHS).flat());
    for (const feature of SIGN_CAPABILITY_FEATURE_KEYS) {
      const paths = SIGN_CAPABILITY_DEPLOY_PATHS[feature];
      expect(paths.length).toBeGreaterThan(0);
    }
    for (const [path, capability] of Object.entries(AUTHORING_CAPABILITY_MANIFEST)) {
      const isDeployable = Object.values(capability.surfaces).some((surface) => surface.deploy);
      if (isDeployable) expect(mappedPaths).toContain(path);
    }
  });

  it("pins the shared Sign capability fixture", () => {
    const fixture = JSON.parse(readFileSync(new URL("./vectors/sigil-sign-capabilities-v1.json", import.meta.url), "utf8"));
    expect(fixture).toEqual({
      schema_version: SIGN_CAPABILITIES_SCHEMA_VERSION,
      engine_version: SIGIL_SIGN_ENGINE_VERSION,
      supported_policy_versions: POLICY_VERSION_RANGES,
      feature_keys: SIGN_CAPABILITY_FEATURE_KEYS,
    });
  });

  it("pins the parser-contract digest to the executable manifest", () => {
    const digest = createHash("sha256").update(PARSER_CONTRACT_DIGEST_INPUT).digest("hex");
    expect(PARSER_CONTRACT_DIGEST).toBe(`sha256:${digest}`);
  });

  it("executes surface representability constraints", () => {
    expect(runRepresentabilityConstraints("profile.repository.roots", "builder", [".", "/workspace"]))
      .toMatchObject([{ constraint_id: "single-repository-root" }]);
    expect(runRepresentabilityConstraints("profile.repository.git_providers", "builder", ["azure-devops"]))
      .toMatchObject([{ constraint_id: "repository-provider-enum" }]);
  });

  it("serializes a parsed policy into a canonical reparseable body", () => {
    const input = parsePolicyMarkdown("version: 2.1.1\n\n## evm\nallowed_actions: contract.call\nallowed_chains: 1\nrequire_calldata_enrichment: true\ncalldata_unknown_selector: deny\n\n## tool_calls\nallowed: http\nhttp.method_rules.PATCH.deny: true");
    const serialized = serializePolicyMarkdown(input);
    expect(parsePolicyMarkdown(serialized)).toEqual(input);
    expect(() => serializePolicyMarkdown({ version: "2.3.0" }))
      .toThrow("Policy version 2.3.0 is newer than this engine");
  });

  it("rejects invalid response-policy ASTs at the serializer boundary", () => {
    const valid = parsePolicyMarkdown([
      "version: 2.2.0",
      "",
      "## mcp",
      "allowed_tools: fetch.server.fetch",
      "response.web_fetch_tools: fetch.server.fetch",
      "response.deterministic_ruleset: sof-response-rules-v1",
      "",
      "## custom",
      "response.deny_string: \"ignore previous instructions\"",
    ].join("\n"));
    const responseRule = valid.custom?.rules[0];
    const validResponse = valid.mcp?.response;
    if (responseRule === undefined || validResponse === undefined) {
      throw new Error("valid response-policy fixture did not parse as expected");
    }
    expect(serializePolicyMarkdown(valid)).toContain("response.deterministic_ruleset: sof-response-rules-v1");
    for (const unknownKey of ["redactClasses", "scanner"]) {
      expect(() => serializePolicyMarkdown({
        ...valid,
        mcp: {
          ...valid.mcp,
          response: { ...validResponse, [unknownKey]: ["secret"] },
        },
      })).toThrow(`mcp.response contains unknown field ${unknownKey}`);
    }
    expect(() => serializePolicyMarkdown({ ...valid, version: "2.1.0" }))
      .toThrow("requires Policy 2.2.x");
    expect(() => serializePolicyMarkdown({
      ...valid,
      mcp: { ...valid.mcp, response: { webFetchTools: ["fetch.server.fetch"] } },
    })).toThrow("requires response.deterministic_ruleset");
    expect(() => serializePolicyMarkdown({
      ...valid,
      mcp: { ...valid.mcp, allowedTools: ["other.server.tool"] },
    })).toThrow("exact literal member of allowed_tools");
    expect(() => serializePolicyMarkdown({
      ...valid,
      mcp: { ...valid.mcp, response: undefined },
    })).toThrow("response.deny_string requires MCP response coverage");
    expect(() => serializePolicyMarkdown({
      version: "2.2.0",
      mcp: { requireShim: true },
    })).toThrow("at least one of allowedServers, allowedTools, or blockedTools");
    expect(() => serializePolicyMarkdown({
      ...valid,
      custom: { rules: [responseRule, responseRule] },
    })).toThrow("Duplicate response.deny_string literal");
    for (const blockClasses of [
      [],
      ["secret", "secret"],
      ["malware"],
      ["secret", "malicious_url"],
    ]) {
      expect(() => serializePolicyMarkdown({
        ...valid,
        mcp: {
          ...valid.mcp,
          response: { ...validResponse, blockClasses: blockClasses as never },
        },
      })).toThrow(/response class|lexicographically sorted/);
    }
    for (const responseKey of ["webFetchTools", "httpTools"] as const) {
      const unsortedTools = ["z.server.tool", "a.server.tool"];
      expect(() => serializePolicyMarkdown({
        ...valid,
        mcp: {
          ...valid.mcp,
          allowedTools: unsortedTools,
          response: {
            deterministicRuleset: "sof-response-rules-v1",
            [responseKey]: unsortedTools,
          },
        },
      })).toThrow(`${responseKey} must be lexicographically sorted`);
      for (const invalidTool of ["a.server.tool,b.server.tool", "a.server.tool\nb.server.tool", " a.server.tool"]) {
        expect(() => serializePolicyMarkdown({
          ...valid,
          mcp: {
            ...valid.mcp,
            allowedTools: [invalidTool],
            response: {
              deterministicRuleset: "sof-response-rules-v1",
              [responseKey]: [invalidTool],
            },
          },
        })).toThrow("unique nonempty literal tool names");
      }
    }
  });

  it("preserves named soft-limit caps, empty resource profiles, and quoted custom whitespace", () => {
    const input = parsePolicyMarkdown("version: 2.1.1\n\n## repository\n\n## custom\ndeny_string: \" leading \"\ndeny_if.intent.note equals \" trailing \"\n\n## soft_limits\ncap.requests.max_count: 5\ncap.requests.window: day\ncap.requests.action: email.send\ncap.budget.max_sum_usd: 1.25\ncap.budget.window: task\ncap.budget.action: worker.*\ncap.budget.amount_field: amount_usd");
    const serialized = serializePolicyMarkdown(input);
    expect(serialized).toContain("## repository");
    expect(serialized).toContain('deny_string: " leading "');
    expect(serialized).toContain('deny_if.note equals " trailing "');
    expect(serialized).toContain("cap.requests.max_count: 5");
    expect(serialized).toContain("cap.budget.amount_field: amount_usd");
    expect(parsePolicyMarkdown(serialized)).toEqual(input);
  });

  it("reports independent errors in stable order without returning a partial policy", () => {
    const result = validateAndParsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: contract.call\nallowed_chains: 1\ncalldata_unknown_selector: deny\n\n## tool_calls\nallowed: http\nhttp.method_rules.PATCH.deny: true\n\n## signature\nsigil-sig: bad\ntrailing");
    expect(result.policy).toBeUndefined();
    expect(result.errors.map((error) => error.code)).toContain("WARRANT_ENVELOPE_TRAILING_CONTENT");
    expect(result.errors.map((error) => error.path)).toContain("evm.calldata_unknown_selector");
    expect(result.errors.map((error) => error.path)).toContain("tool_calls.http.method_rules.PATCH.deny");
  });

  it("accepts an empty signature placeholder for authoring but not signed verification", () => {
    const raw = "version: 2.1.0\n\n## signature\n# operator signature will be added later\n";
    expect(validateAndParsePolicyMarkdown(raw).errors).toEqual([]);
    expect(validateAndParsePolicyMarkdown(raw, { envelope_mode: "signed" }).errors)
      .toMatchObject([{ code: "WARRANT_ENVELOPE_SIGNATURE_MISSING" }]);
  });

  it("does not turn Sign-optional resource profile fields into blocking validation errors", () => {
    const result = validateAndParsePolicyMarkdown("version: 2.1.1\n\n## repository\nroots: .\nrequire_shim: false");
    expect(result.errors).toEqual([]);
    expect(result.policy).toEqual({
      version: "2.1.1",
      repository: { roots: ["."], requireShim: false },
    });
  });

  it("routes signed envelopes away from surfaces that cannot import them", () => {
    const raw = "version: 2.1.1\n\n## signature\nsigil-sig: abc\n";
    expect(validateAndParsePolicyMarkdown(raw, { surface: "manual-form" }).errors)
      .toMatchObject([{ code: "WARRANT_SURFACE_CANNOT_IMPORT", path: "signature.sigil-envelope-v1" }]);
    expect(validateAndParsePolicyMarkdown(raw, { surface: "manual-advanced" }).errors).toEqual([]);
  });

  it("returns a validation diagnostic for an unterminated HTML comment", () => {
    const result = validateAndParsePolicyMarkdown("version: 2.1.1\n<!--");
    expect(result.policy).toBeUndefined();
    expect(result.errors).toMatchObject([{ code: "WARRANT_INVALID_POLICY", path: "document" }]);
  });

  it("routes empty resource profiles away from surfaces that cannot preserve them", () => {
    const result = validateAndParsePolicyMarkdown("version: 2.1.1\n\n## filesystem", {
      surface: "manual-form",
    });
    expect(result.policy).toBeUndefined();
    expect(result.errors).toMatchObject([{ code: "WARRANT_SURFACE_CANNOT_IMPORT", path: "profile.filesystem" }]);
  });
});
