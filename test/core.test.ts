import { readFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  appendSignatureBlock,
  canonicalizePgCommitV1,
  canonicalizePolicyObject,
  hashPgCommitV1,
  hashPolicy,
  parsePolicyMarkdown,
  splitSignatureBlock
} from "../src/index.js";
import { createWebCryptoAdapter } from "../src/crypto/browser.js";
import { createNodeCryptoAdapter } from "../src/crypto/node.js";
import { createWebCryptoAdapter as createWorkerCryptoAdapter } from "../src/crypto/workers.js";

interface Fixture {
  templateBody: string;
  canonicalPolicy: unknown;
  canonicalPolicyJson: string;
  policyHashSha256: string;
}

interface GenericControlParityVector {
  markdown: string;
  canonicalPolicy: unknown;
  canonicalPolicyJson: string;
}

interface SigilSignParserParityCase {
  id: string;
  markdown: string;
  outcome: "accept" | "reject";
  canonicalPolicy?: unknown;
}

const fixtureFile = new URL("./vectors/policy-fixtures.json", import.meta.url);
const fixtures = (JSON.parse(readFileSync(fixtureFile, "utf8")) as { fixtures: Fixture[] }).fixtures;
const genericControlVector = JSON.parse(readFileSync(new URL("./vectors/generic-control-parity.json", import.meta.url), "utf8")) as GenericControlParityVector;
const sigilSignParity = JSON.parse(readFileSync(new URL("./vectors/sigil-sign-parser-parity.json", import.meta.url), "utf8")) as {
  sigilSignCommit: string;
  cases: SigilSignParserParityCase[];
};

describe("warranty.md parser", () => {
  it("parses all canonical fixture policies and preserves their policy hashes", async () => {
    const adapter = createNodeCryptoAdapter();
    for (const fixture of fixtures) {
      const parsed = parsePolicyMarkdown(fixture.templateBody);
      expect(parsed).toEqual(fixture.canonicalPolicy);
      expect(canonicalizePolicyObject(parsed)).toBe(fixture.canonicalPolicyJson);
      await expect(hashPolicy(adapter, parsed)).resolves.toBe(fixture.policyHashSha256);
    }
  });

  it("accepts unversioned and 1.x policy forms, but rejects 2.x-only syntax", () => {
    expect(parsePolicyMarkdown("## tool_calls\nallowed: bash").version).toBe("0.0.0");
    expect(parsePolicyMarkdown("version: 1.8.4\n\n## tool_calls\nallowed: bash").version).toBe("1.8.4");
    expect(() => parsePolicyMarkdown("## tool_calls\nhttp.allowed_methods: GET")).toThrow("requires version 2.0.0");
    expect(() => parsePolicyMarkdown("version: 2.1.0\n\n## unexpected\nkey: value")).toThrow("Unknown policy block");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## filesystem\nactions: read\nwrite_roots: .\nread_roots: .\nallowed_effects: read\nrequire_shim: true")).toThrow("2.1 resource profiles");
  });

  it("supports 2.1 resource profiles and blocked MCP exceptions", () => {
    const profile = parsePolicyMarkdown("version: 2.1.0\n\n## repository\nroots: .\nblock_outside_writes: true\nprotect_git_history: true\nprotect_sensitive_files: true\ngit_providers: github\nrequire_shim: true\n\n## mcp\nallowed_tools: github.*\nblocked_tools: github.delete");
    expect(profile.repository).toMatchObject({ roots: ["."], requireShim: true });
    expect(profile.mcp).toMatchObject({ allowedTools: ["github.*"], blockedTools: ["github.delete"] });
    expect(() => parsePolicyMarkdown("version: 2.1.0\n\n## mcp\nallowed_tools: github.delete\nblocked_tools: github.delete")).toThrow("same tool");
  });

  it("matches Sigil Sign generic approval and shim control output across typed blocks", () => {
    const policy = parsePolicyMarkdown(genericControlVector.markdown);
    expect(policy).toEqual(genericControlVector.canonicalPolicy);
    expect(canonicalizePolicyObject(policy)).toBe(genericControlVector.canonicalPolicyJson);
  });

  for (const parityCase of sigilSignParity.cases) {
    it(`matches frozen Sigil Sign parser behavior for ${parityCase.id}`, () => {
      if (parityCase.outcome === "accept") {
        expect(parsePolicyMarkdown(parityCase.markdown)).toEqual(parityCase.canonicalPolicy);
      } else {
        expect(() => parsePolicyMarkdown(parityCase.markdown)).toThrow();
      }
    });
  }

  it("fails closed for malformed or legacy generic approval and shim controls", () => {
    expect(() => parsePolicyMarkdown("version: 1.0.0\n\n## tool_calls\nrequire_approval: bash")).toThrow("requires version 2.0.0");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## evm\nrequire_shim: yes")).toThrow("must be true or false");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## custom\nrequire_approval: bad*pattern* ")).toThrow("trailing * wildcard");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\nrequire_shim: true\nrequire_shim: false")).toThrow("Duplicate policy key");
  });

  it("matches Sigil Sign when execution controls have no numeric limit", () => {
    expect(parsePolicyMarkdown([
      "version: 2.0.0",
      "",
      "## tool_calls",
      "allowed: bash",
      "",
      "## execution_limits",
      "require_approval: bash",
      "require_shim: true",
    ].join("\n"))).toEqual({
      version: "2.0.0",
      tool_calls: { allowed: ["bash"] },
    });
  });

  it("fails closed for invalid execution limit values", () => {
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## execution_limits\nmax_tool_calls_per_task: 0")).toThrow("Unrecognized execution_limits");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## execution_limits\nmax_model_spend_usd_per_task: nope")).toThrow("Unrecognized execution_limits");
  });

  it("matches Sigil Sign by rejecting soft limit controls without an enforced limit", () => {
    expect(() => parsePolicyMarkdown([
      "version: 2.0.0",
      "",
      "## soft_limits",
      "require_approval: bash",
      "require_shim: true",
    ].join("\n"))).toThrow("must declare at least one enforced limit");
  });

  it("matches Sigil Sign EVM defaults and required allowlists", () => {
    expect(parsePolicyMarkdown([
      "version: 2.0.0",
      "",
      "## evm",
      "allowed_actions: wallet.transfer",
      "allowed_chains: 1",
    ].join("\n")).evm).toEqual({
      maxTransactionEth: 5,
      allowedActions: ["wallet.transfer"],
      allowedChains: [1],
    });
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## evm\nmax_transaction_eth: 1")).toThrow("allowed_action");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer")).toThrow("allowed_chain");
  });

  it("matches Sigil Sign by requiring tool_calls.allowed and an enforceable policy", () => {
    expect(() => parsePolicyMarkdown([
      "version: 2.0.0",
      "",
      "## custom",
      "deny_string: SECRET",
      "",
      "## tool_calls",
      "require_approval: bash",
    ].join("\n"))).toThrow("requires at least one allowed tool");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## execution_limits\nmax_tool_calls_per_task: 5")).toThrow("enforceable policy");
  });
});

describe("canonicalization and cryptographic adapters", () => {
  it("uses UTF-16 code-unit ordering for pg-commit-v1", async () => {
    const intent = { "\uE000": 2, "😀": 1, nested: { "\uE001": ["é", "東京"], "😁": -0 } };
    expect(canonicalizePgCommitV1(intent)).toBe('{"nested":{"😁":0,"":["é","東京"]},"😀":1,"":2}');
    await expect(hashPgCommitV1(createNodeCryptoAdapter(), intent)).resolves.toBe("8aaa49c97bcd8c1deae4bd9fb4c1803eeaa2505b2a743818a3350182a91dd1c6");
  });

  it("rejects every non-JSON pg-commit-v1 input class", () => {
    const cyclic: { self?: unknown } = {}; cyclic.self = cyclic;
    const rejected: unknown[] = [undefined, Number.NaN, Number.POSITIVE_INFINITY, 1n, () => undefined, Symbol("x"), cyclic];
    for (const value of rejected) expect(() => canonicalizePgCommitV1(value)).toThrow("pg-commit-v1 rejects");
  });

  it("rejects sparse arrays, exotic objects, symbols, and accessors without invoking getters", () => {
    const sparse: unknown[] = []; sparse[1] = "present";
    const symbolKeyed = { safe: true }; Object.defineProperty(symbolKeyed, Symbol("secret"), { value: "hidden" });
    let getterCalls = 0;
    const accessor = {};
    Object.defineProperty(accessor, "value", { enumerable: true, get: () => { getterCalls += 1; return "never"; } });
    const rejected: unknown[] = [sparse, symbolKeyed, new Date(), new Map(), new Set(), new Uint8Array([1]), accessor];
    for (const value of rejected) expect(() => canonicalizePgCommitV1(value)).toThrow("pg-commit-v1 rejects");
    expect(getterCalls).toBe(0);
  });

  it("permits shared acyclic references and null-prototype plain objects", () => {
    const shared = { label: "shared", values: [1, 2] };
    const nullPrototype = Object.create(null) as Record<string, unknown>;
    nullPrototype.z = true;
    nullPrototype.a = shared;
    expect(canonicalizePgCommitV1({ left: shared, right: shared, nullPrototype })).toBe('{"left":{"label":"shared","values":[1,2]},"nullPrototype":{"a":{"label":"shared","values":[1,2]},"z":true},"right":{"label":"shared","values":[1,2]}}');
  });

  it("provides equivalent browser and Worker WebCrypto adapters", async () => {
    const crypto = globalThis.crypto;
    const browser = createWebCryptoAdapter(crypto);
    const worker = createWorkerCryptoAdapter(crypto);
    const data = new TextEncoder().encode("sigil");
    await expect(browser.sha256(data)).resolves.toEqual(await worker.sha256(data));
  });

  it("signs and verifies Ed25519 across Node and WebCrypto adapters", async () => {
    const pair = generateKeyPairSync("ed25519");
    const privateKey = new Uint8Array(pair.privateKey.export({ format: "der", type: "pkcs8" }));
    const publicKey = new Uint8Array(pair.publicKey.export({ format: "der", type: "spki" }));
    const data = new TextEncoder().encode("cross-runtime Ed25519");
    const node = createNodeCryptoAdapter();
    const web = createWebCryptoAdapter(globalThis.crypto);
    const nodeSignature = await node.signEd25519!(privateKey, data);
    expect(await web.verifyEd25519!(publicKey, nodeSignature, data)).toBe(true);
    const webSignature = await web.signEd25519!(privateKey, data);
    expect(await node.verifyEd25519!(publicKey, webSignature, data)).toBe(true);
  });
});

describe("signature blocks", () => {
  it("splits and appends the canonical final signature block", () => {
    const signed = appendSignatureBlock("version: 2.1.0\n", "abc_DEF-123");
    expect(signed).toBe("version: 2.1.0\n\n## signature\nsigil-sig: abc_DEF-123\n");
    expect(splitSignatureBlock(signed)).toEqual({ unsigned: "version: 2.1.0", signature: "abc_DEF-123" });
    expect(splitSignatureBlock("version: 2.1.0\n\n## signature\n  sigil-sig:\tABC_def-123  \n\n")).toEqual({ unsigned: "version: 2.1.0", signature: "ABC_def-123" });
    expect(() => splitSignatureBlock("## signature\nsigil-sig: abc\n\n## evm\nmax_transaction_eth: 1")).toThrow("must be final");
    expect(() => splitSignatureBlock("## signature\nsigil-sig: abc\nextra")).toThrow("only sigil-sig");
    expect(() => splitSignatureBlock("## signature\nSIGIL-SIG: abc")).toThrow("only sigil-sig");
    expect(() => splitSignatureBlock("## signature\nsigil-sig: abc.def")).toThrow("only sigil-sig");
    expect(() => splitSignatureBlock("## signature\nsigil-sig: ")).toThrow("only sigil-sig");
  });
});
