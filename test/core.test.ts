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
  policyCanonicalBytes,
  splitSignatureBlock
} from "../src/index.js";
import { createWebCryptoAdapter } from "../src/crypto/browser.js";
import { createNodeCryptoAdapter } from "../src/crypto/node.js";
import { createWebCryptoAdapter as createWorkerCryptoAdapter } from "../src/crypto/workers.js";
import { assertKnownParityDivergencesCovered, KNOWN_PARITY_DIVERGENCES } from "./shared/parser-compatibility.js";

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
  it("preserves established Warrant collation in Node", () => {
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

  it("breaks collation ties by UTF-16 code units independent of insertion order", async () => {
    const first = { "a\u00ad": ["x"], a: ["x"] };
    const reversed = { a: ["x"], "a\u00ad": ["x"] };
    const expected = "{\"a\":[\"x\"],\"a\u00ad\":[\"x\"]}";
    const expectedHash = "9bbb6d2584aa2b8574e3990dd811afb09789dca786b4b5d4ce62757ecd44e1be";
    const adapter = createNodeCryptoAdapter();

    expect("a\u00ad".localeCompare("a", "en-US")).toBe(0);
    expect(canonicalizePolicyObject(first)).toBe(expected);
    expect(canonicalizePolicyObject(reversed)).toBe(expected);
    expect(policyCanonicalBytes(first)).toEqual(new TextEncoder().encode(expected));
    expect(policyCanonicalBytes(reversed)).toEqual(new TextEncoder().encode(expected));
    await expect(hashPolicy(adapter, first)).resolves.toBe(expectedHash);
    await expect(hashPolicy(adapter, reversed)).resolves.toBe(expectedHash);
  });

  it("pins en-US ordering for case-distinct policy keys", () => {
    expect(canonicalizePolicyObject({ caps: { I: 1, i: 1 } })).toBe(
      "{\"caps\":{\"i\":1,\"I\":1}}",
    );
  });

  it("serializes sparse policy arrays as null with stable bytes and hashes", async () => {
    const singleHole = Array<unknown>(1);
    const nested = Array<unknown>(3);
    nested[1] = Array<unknown>(2);
    const policy = { nested, singleHole };
    const expected = '{"nested":[null,[null,null],null],"singleHole":[null]}';
    const expectedHash = "326167890b93712a7dd21556591c1fed6389d6abb7da66f17947100274ead50e";

    expect(canonicalizePolicyObject([])).toBe("[]");
    expect(canonicalizePolicyObject(singleHole)).toBe("[null]");
    expect(canonicalizePolicyObject(singleHole)).not.toBe(canonicalizePolicyObject([]));
    expect(canonicalizePolicyObject(policy)).toBe(expected);
    expect(policyCanonicalBytes(policy)).toEqual(new TextEncoder().encode(expected));
    await expect(hashPolicy(createNodeCryptoAdapter(), policy)).resolves.toBe(expectedHash);
    await expect(hashPolicy(createNodeCryptoAdapter(), singleHole)).resolves.toBe("1d8fc6ceb1f94c6326d6d5483d258fcb2e179e9869325b245d105c2219bf69fd");
  });

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
    expect(parsePolicyMarkdown("  version: 2.0.0\n\n## tool_calls\nallowed: bash").version).toBe("2.0.0");
    expect(() => parsePolicyMarkdown("## tool_calls\nhttp.allowed_methods: GET")).toThrow("requires version 2.0.0");
    expect(() => parsePolicyMarkdown("version: 2.1.0\n\n## unexpected\nkey: value")).toThrow("Unknown policy block");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## filesystem\nactions: read\nwrite_roots: .\nread_roots: .\nallowed_effects: read\nrequire_shim: true")).toThrow("2.1 resource profiles");
  });

  it("accepts valid CRLF Policy 2.0 and signed Policy 2.1 documents", () => {
    const policy20 = "version: 2.0.0\r\n\r\n## tool_calls\r\nallowed: bash";
    expect(parsePolicyMarkdown(policy20)).toEqual({
      version: "2.0.0",
      tool_calls: { allowed: ["bash"] },
    });

    const policy21 = [
      "version: 2.1.0",
      "",
      "## repository",
      "roots: .",
      "block_outside_writes: true",
      "protect_git_history: true",
      "protect_sensitive_files: true",
      "git_providers: github",
      "require_shim: true",
    ].join("\r\n");
    const signedPolicy21 = `${policy21}\r\n\r\n## signature\r\nsigil-sig: abc_DEF-123\r\n`;
    expect(splitSignatureBlock(signedPolicy21)).toEqual({ unsigned: policy21, signature: "abc_DEF-123" });
    expect(parsePolicyMarkdown(signedPolicy21)).toEqual({
      version: "2.1.0",
      repository: {
        roots: ["."],
        blockOutsideWrites: true,
        protectGitHistory: true,
        protectSensitiveFiles: true,
        gitProviders: ["github"],
        requireShim: true,
      },
    });
  });

  it("fails closed instead of downgrading malformed root version declarations", () => {
    const permissiveLegacyBody = "\n\n## tool_calls\nallowed: email.send\nemail.require_approval: maybe";
    expect(() => parsePolicyMarkdown(`versoin: 2.0.0${permissiveLegacyBody}`)).toThrow("Unrecognized root policy field");
    expect(() => parsePolicyMarkdown(`versoin=2.0.0${permissiveLegacyBody}`)).toThrow("Unrecognized root policy field");
    expect(() => parsePolicyMarkdown(`versoin 2.0.0${permissiveLegacyBody}`)).toThrow("Unrecognized root policy field");
    for (const declaration of ["version:", "version : 2.0.0", "version=2.0.0", "version", "- version: 2.0.0", "> version: 2.0.0"]) {
      expect(() => parsePolicyMarkdown(`${declaration}${permissiveLegacyBody}`)).toThrow("Invalid root version declaration");
    }
    for (const declaration of ["version.: 2.0.0", "version--: 2.0.0", "version_: 2.0.0", "version-- 2.0.0"]) {
      expect(() => parsePolicyMarkdown(`${declaration}${permissiveLegacyBody}`)).toThrow("Unrecognized root policy field");
    }
    for (const declaration of [
      "version .: 2.0.0",
      "version . : 2.0.0",
      "version / = 2.0.0",
      "version -- 2.0.0",
    ]) {
      expect(() => parsePolicyMarkdown(`${declaration}${permissiveLegacyBody}`)).toThrow("Invalid root version declaration");
    }
    expect(() => parsePolicyMarkdown(`version: 2.0.0\nversion: 2.0.0${permissiveLegacyBody}`)).toThrow("Duplicate version");
    expect(() => parsePolicyMarkdown(`version: 2.0${permissiveLegacyBody}`)).toThrow("Invalid policy version");
    for (const malformed of [
      `versoin: 2.0.0\r\n${permissiveLegacyBody.trimStart()}`,
      `version=2.0.0\r\n${permissiveLegacyBody.trimStart()}`,
      `version: 2.0\r\n${permissiveLegacyBody.trimStart()}`,
      `version: 2.0.0\r\nversion=2.0.0\n${permissiveLegacyBody.trimStart()}`,
    ]) {
      expect(() => parsePolicyMarkdown(malformed)).toThrow();
    }
    expect(parsePolicyMarkdown(`# Warranty Policy\nNote: copy this policy before use.\n> This policy description is documentation.\n<!--\n## notes\npolicy metadata\n-->\nversion: 2.0.0\n\n## tool_calls\nallowed: bash`).version).toBe("2.0.0");
    expect(parsePolicyMarkdown(`Versioning: draft\nSession: current\nVersions vary between deployments.\nVersions 2 and 3 are supported.\nVersioningDocumentationKeyThatMustNotReachTypoDistance: notes\nversion: 2.0.0\n\n## tool_calls\nallowed: bash`).version).toBe("2.0.0");
    expect(parsePolicyMarkdown(permissiveLegacyBody).tool_calls?.emailRequireApproval).toBe(false);
    expect(() => parsePolicyMarkdown(`version: 2.0.0${permissiveLegacyBody}`)).toThrow("must be true or false");
  });

  it("rejects policy controls and security fields placed at document root", () => {
    const validBlock = "\n\n## tool_calls\nallowed: bash";
    for (const field of [
      "require_approval: bash",
      "require_shim: true",
      "max_tool_calls_per_task: 1",
      "blocked_operations: force_push",
      "protect_git_history: true",
      "token.USDC.decimals: 6",
      "cap.requests.max_count: 1",
      "deny_string: SECRET",
      "allow_only.intent.environment: production",
      "deny_if.intent.environment equals production",
    ]) {
      expect(() => parsePolicyMarkdown(`version: 2.0.0\n${field}${validBlock}`)).toThrow("must be inside a policy block");
    }
  });

  it("keeps legitimate root prose, headings, comments, and blockquotes", () => {
    const policy = [
      "# Warrant policy",
      "   # Indented documentation heading",
      "  This indented prose remains documentation.",
      "Versioning: draft",
      "Session: current",
      "Note: require_shim belongs in a policy block.",
      "# require_shim: true",
      "> require_approval: bash",
      "<!-- require_shim: true -->",
      "version: 2.0.0",
      "",
      "## tool_calls",
      "allowed: bash",
    ].join("\n");
    expect(parsePolicyMarkdown(policy)).toEqual({ version: "2.0.0", tool_calls: { allowed: ["bash"] } });
  });

  it("supports 2.1 resource profiles and blocked MCP exceptions", () => {
    const profile = parsePolicyMarkdown("version: 2.1.0\n\n## repository\nroots: .\nblock_outside_writes: true\nprotect_git_history: true\nprotect_sensitive_files: true\ngit_providers: github\nrequire_shim: true\n\n## mcp\nallowed_tools: github.*\nblocked_tools: github.delete");
    expect(profile.repository).toMatchObject({ roots: ["."], requireShim: true });
    expect(profile.mcp).toMatchObject({ allowedTools: ["github.*"], blockedTools: ["github.delete"] });
    expect(() => parsePolicyMarkdown("version: 2.1.0\n\n## mcp\nallowed_tools: github.delete\nblocked_tools: github.delete")).toThrow("same tool");
  });

  it("enforces the Policy 2.1 resource schemas used by Sigil Sign", () => {
    expect(() => parsePolicyMarkdown("version: 2.1.0\n\n## repository\nroots: .\nblock_outside_writes: true\nprotect_git_history: true\nprotect_sensitive_files: true\ngit_providers: unknown\nrequire_shim: true")).toThrow("unsupported value");
    expect(() => parsePolicyMarkdown("version: 2.1.0\n\n## filesystem\nactions: filesystem.write\nwrite_roots: relative\nread_roots: .\nallowed_effects: overwrite\nrequire_shim: true")).toThrow("canonical absolute paths");
    expect(() => parsePolicyMarkdown("version: 2.1.0\n\n## git\nactions: git.push\nfilesystem_actions: filesystem.write\nproviders: github\nallowed_remote_schemes: https\nallowed_operations: status\nrequire_approval: force_push\nblocked_operations: force_push\nprotected_refs: refs/heads/main\nrequire_shim: true")).toThrow("subset of allowed_operations");
    expect(() => parsePolicyMarkdown("version: 2.1.0\n\n## database\nactions: database.query\nprotected_environments: production\nallowed_operations: select\nallowed_resources: *\nroutine_catalog: catalog-v1\nrequire_read_only_for_select: true\ndeny_unreviewed_indirect_effects: true\nrequire_shim: true")).toThrow("bare *");
  });

  it("rejects every present empty optional Policy 2.1 resource list", () => {
    const filesystem = "version: 2.1.0\n\n## filesystem\nactions: filesystem.write\nwrite_roots: /workspace\nread_roots: /workspace\nallowed_effects: overwrite\nrequire_shim: true";
    for (const field of ["blocked_paths", "protected_file_classes", "protected_effects"]) {
      expect(() => parsePolicyMarkdown(`${filesystem}\n${field}: ,`)).toThrow("must contain at least one entry");
    }
    expect(() => parsePolicyMarkdown("version: 2.1.0\n\n## filesystem\nactions: filesystem.write\nwrite_roots: /workspace\nallowed_effects: overwrite\nprotected_file_classes: ,\nrequire_shim: true")).toThrow("must contain at least one entry");

    const git = "version: 2.1.0\n\n## git\nactions: git.push\nfilesystem_actions: filesystem.write\nproviders: github\nallowed_remote_schemes: https\nallowed_operations: push_fast_forward\nblocked_operations: force_push\nprotected_refs: refs/heads/main\nrequire_shim: true";
    expect(() => parsePolicyMarkdown(`${git}\nrequire_approval: ,`)).toThrow("must contain at least one entry");

    const database = "version: 2.1.0\n\n## database\nactions: database.query\nprotected_environments: production\nallowed_operations: select\nallowed_resources: public.*\nroutine_catalog: catalog-v1\nrequire_read_only_for_select: true\ndeny_unreviewed_indirect_effects: true\nrequire_shim: true";
    expect(() => parsePolicyMarkdown(`${database}\nrequire_approval: ,`)).toThrow("must contain at least one entry");
  });

  it("matches Sigil Sign generic approval and shim control output across typed blocks", () => {
    const policy = parsePolicyMarkdown(genericControlVector.markdown);
    expect(policy).toEqual(genericControlVector.canonicalPolicy);
    expect(canonicalizePolicyObject(policy)).toBe(genericControlVector.canonicalPolicyJson);
  });

  it("parses generic EVM controls after chain_actions instead of treating them as chain names", () => {
    const policy = parsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer, contract.call\nallowed_chains: 1, 8453\nchain_actions:\n  \"1\": wallet.transfer\n  \"8453\": contract.call\n  require_approval: wallet.transfer\n  require_shim: true");
    expect(policy.evm).toMatchObject({
      chainActions: {
        "1": ["wallet.transfer"],
        "8453": ["contract.call"],
      },
      requireApproval: ["wallet.transfer"],
      requireShim: true,
    });
    expect(policy.evm?.chainActions).not.toHaveProperty("require_approval");
    expect(policy.evm?.chainActions).not.toHaveProperty("require_shim");

    const boundary = parsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: *\nallowed_chains: 1\nchain_actions:\n  \"1\": wallet.transfer\nrequire_approval: wallet.transfer");
    expect(boundary.evm?.chainActions).toEqual({ "1": ["wallet.transfer"] });
    expect(boundary.evm?.requireApproval).toEqual(["wallet.transfer"]);
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: *\nallowed_chains: 1\nchain_actions:\n  \"1\": wallet.transfer\nrequire_approval: wallet.transfer\n  \"1\": *")).toThrow("Dangling chain_actions mapping");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: *\nallowed_chains: 1\nchain_actions:\n  \"1\": wallet.transfer\n  require_approval: wallet.transfer\n  \"1\": *")).toThrow("Dangling chain_actions mapping");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: *\nallowed_chains: 1\nchain_actions:\n  \"1\": wallet.transfer\n  require_shim: true\n  \"1\": *")).toThrow("Dangling chain_actions mapping");
  });

  it("rejects duplicate normalized EVM chain action IDs", () => {
    expect(parsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1\nchain_actions:\n  \"01\": wallet.transfer").evm?.chainActions).toEqual({ "1": ["wallet.transfer"] });
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer, contract.call\nallowed_chains: 1\nchain_actions:\n  1: wallet.transfer\n  \"1\": contract.call")).toThrow("Duplicate chain_actions chain ID: 1");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer, contract.call\nallowed_chains: 1\nchain_actions:\n  \"01\": wallet.transfer\n  1: contract.call")).toThrow("Duplicate chain_actions chain ID: 1");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1\nchain_actions:\n  1: ,\n  01: wallet.transfer")).toThrow("Duplicate chain_actions chain ID: 1");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1\nchain_actions:\n  01: ,")).toThrow("chain_actions entry for chain 1 must contain at least one action");
  });

  it("accepts chain action mappings with any indentation and rejects empty entries", () => {
    for (const indentation of [" ", "  ", "\t"]) {
      expect(parsePolicyMarkdown(`version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1\nchain_actions:\n${indentation}1: wallet.transfer`).evm?.chainActions).toEqual({
        "1": ["wallet.transfer"],
      });
    }
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1\nchain_actions:\n  1:")).toThrow("chain_actions entry for chain 1 must contain at least one action");
  });

  it("rejects immediate unindented chain action mappings without rejecting ordinary boundaries", () => {
    for (const chainId of ["1", '"1"']) {
      expect(() => parsePolicyMarkdown(`version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1\nchain_actions:\n${chainId}: wallet.transfer`)).toThrow("chain_actions mappings must be indented");
    }
    expect(parsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1\nchain_actions:\n  1: wallet.transfer\nmax_transaction_eth: 2").evm).toMatchObject({
      chainActions: { "1": ["wallet.transfer"] },
      maxTransactionEth: 2,
    });
  });

  it("rejects numeric mappings before or without a chain_actions block", () => {
    for (const chainId of ["1", '"1"']) {
      for (const indentation of ["", "  "]) {
        expect(() => parsePolicyMarkdown(`version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1\n${indentation}${chainId}: wallet.transfer\nchain_actions:\n  1: wallet.transfer`)).toThrow("Unknown top-level numeric mapping in ## evm");
        expect(() => parsePolicyMarkdown(`version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1\n${indentation}${chainId}: wallet.transfer`)).toThrow("Unknown top-level numeric mapping in ## evm");
      }
    }
  });

  it("rejects numeric mappings after a chain_actions boundary", () => {
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1\nchain_actions:\n  1: wallet.transfer\nrequire_shim: true\n  8453:")).toThrow("Dangling chain_actions mapping after the block boundary");
    for (const chainId of ["8453", '"8453"']) {
      expect(() => parsePolicyMarkdown(`version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1\nchain_actions:\n  1: wallet.transfer\nconsensus_threshold_eth: 3\n${chainId}: contract.call`)).toThrow("Unknown top-level numeric mapping in ## evm");
    }
  });

  it("rejects malformed and out-of-range token decimals in every policy version", () => {
    for (const version of ["1.0.0", "2.0.0", "2.1.0"]) {
      const markdown = (decimals: string) => `version: ${version}\n\n## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1\ntoken.USDC.max_transaction: 100\ntoken.USDC.decimals: ${decimals}`;
      expect(parsePolicyMarkdown(markdown("0")).evm?.tokenRules).toEqual({ USDC: { maxTransaction: "100", decimals: 0 } });
      expect(parsePolicyMarkdown(markdown("36")).evm?.tokenRules).toEqual({ USDC: { maxTransaction: "100", decimals: 36 } });
      for (const decimals of ["6units", "nope", "-1", "37", "1.5"]) {
        expect(() => parsePolicyMarkdown(markdown(decimals))).toThrow("token.USDC.decimals must be an integer from 0 through 36");
      }
    }
  });

  it("rejects policy headings with Markdown indentation instead of omitting their controls", () => {
    for (const indent of [" ", "  ", "   "]) {
      const markdown = `version: 2.0.0\n\n${indent}## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1\n\n## tool_calls\nallowed: bash`;
      expect(() => parsePolicyMarkdown(markdown)).toThrow("Indented policy headings are not supported");
    }
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n ## execution_limits\nmax_tool_calls_per_task: 1\n\n## tool_calls\nallowed: bash")).toThrow("Indented policy headings are not supported");
  });

  it("rejects duplicate ordinary EVM declarations", () => {
    const base = "version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1";
    for (const duplicate of [
      "max_transaction_eth: 1\nmax_transaction_eth: 2",
      "allowed_actions: wallet.transfer\nallowed_actions: contract.call",
      "allowed_chains: 1\nallowed_chains: 8453",
      "consensus_threshold_eth: 1\nconsensus_threshold_eth: 2",
      "consensus_require_hold: true\nconsensus_require_hold: false",
    ]) {
      expect(() => parsePolicyMarkdown(`${base}\n${duplicate}`)).toThrow("Duplicate EVM policy key");
    }
  });

  it("rejects duplicate chain-action headers and scalar token declarations", () => {
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1\nchain_actions:\n  1: wallet.transfer\nchain_actions:\n  8453: contract.call")).toThrow("Duplicate EVM policy key: chain_actions");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1\ntoken.USDC.max_transaction: 100\ntoken.usdc.max_transaction: 200")).toThrow("Duplicate EVM token policy key: token.USDC.max_transaction");
    expect(parsePolicyMarkdown("version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1\ntoken.USDC.max_transaction: 100\ntoken.USDC.addresses: 0xA\ntoken.usdc.addresses: 0xB").evm?.tokenRules).toEqual({
      USDC: {
        maxTransaction: "100",
        addresses: ["0xa", "0xb"],
      },
    });
  });

  it("preserves numeric-prefix parsing and rejects nonnumeric consensus thresholds", () => {
    const markdown = (threshold: string) => `version: 2.0.0\n\n## evm\nallowed_actions: wallet.transfer\nallowed_chains: 1\nconsensus_threshold_eth: ${threshold}`;
    expect(parsePolicyMarkdown(markdown("1.5ETH")).evm?.consensusThresholdEth).toBe(1.5);
    expect(() => parsePolicyMarkdown(markdown("nope"))).toThrow("consensus_threshold_eth must be numeric");
    for (const threshold of ["0", "-1"]) {
      expect(() => parsePolicyMarkdown(markdown(threshold))).toThrow("consensus_threshold_eth must be greater than zero");
    }
  });

  assertKnownParityDivergencesCovered();
  for (const parityCase of sigilSignParity.cases) {
    if (KNOWN_PARITY_DIVERGENCES.has(parityCase.id)) continue;
    it(`matches frozen Sigil Sign parser behavior for ${parityCase.id}`, () => {
      if (parityCase.outcome === "accept") {
        if (!("canonicalPolicy" in parityCase)) throw new Error(`Missing canonical policy for ${parityCase.id}`);
        expect(parsePolicyMarkdown(parityCase.markdown)).toEqual(parityCase.canonicalPolicy);
      } else {
        expect(() => parsePolicyMarkdown(parityCase.markdown)).toThrow();
      }
    });
  }

  it("fails closed for malformed or legacy generic approval and shim controls", () => {
    expect(() => parsePolicyMarkdown("version: 1.0.0\n\n## tool_calls\nrequire_approval: bash")).toThrow("requires version 2.0.0");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## evm\nrequire_shim: yes")).toThrow("must be true or false");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## custom\nrequire_approval: bad*pattern* ")).toThrow("must contain exact values or one trailing * wildcard");
    expect(parsePolicyMarkdown("version: 2.0.0\n\n## custom\nrequire_approval: bash, bash").custom?.requireApproval).toEqual(["bash"]);
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\nrequire_shim: true\nrequire_shim: false")).toThrow("Duplicate soft_limits policy key");
  });

  it("preserves empty custom policies and rejects invalid HTTP DNS labels", () => {
    expect(parsePolicyMarkdown("version: 2.0.0\n\n## custom\n# no rules")).toEqual({ version: "2.0.0" });
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## custom\nrequire_shim: false")).toThrow("at least one enforceable rule or control");
    const falseAlongsideRule = parsePolicyMarkdown("version: 2.0.0\n\n## custom\ndeny_string: SECRET\nrequire_shim: false");
    expect(falseAlongsideRule.custom).toEqual({
      rules: [{ name: "deny_string:SECRET", type: "deny_string", value: "SECRET" }],
      requireShim: false,
    });
    expect(canonicalizePolicyObject(falseAlongsideRule)).toContain('"requireShim":false');
    const falseAlongsideApproval = parsePolicyMarkdown("version: 2.0.0\n\n## custom\nrequire_approval: bash\nrequire_shim: false");
    expect(falseAlongsideApproval.custom).toEqual({
      rules: [],
      requireApproval: ["bash"],
      requireShim: false,
    });
    expect(canonicalizePolicyObject(falseAlongsideApproval)).toContain('"requireShim":false');
    expect(() => parsePolicyMarkdown("## tool_calls\nallowed: bash\n\n## custom\ndeny_strng: SECRET")).toThrow("Unrecognized custom rule");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## custom\nallow_only.intent.: safe")).toThrow("allow_only field path must not be empty");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## custom\ndeny_if.intent. equals unsafe")).toThrow("deny_if field path must not be empty");
    expect(parsePolicyMarkdown("version: 2.0.0\n\n## tool_calls\nallowed: bash\n\n## custom\n# no rules")).toEqual({
      version: "2.0.0",
      tool_calls: { allowed: ["bash"] },
    });
    for (const host of ["api..example.com", "api-.example.com", "-api.example.com"]) {
      expect(() => parsePolicyMarkdown(`version: 2.0.0\n\n## tool_calls\nallowed: http\nhttp.allowed_hosts: ${host}`)).toThrow("valid lowercase host names");
    }
    expect(parsePolicyMarkdown("version: 2.0.0\n\n## tool_calls\nallowed: http\nhttp.allowed_hosts: API.Example.Com., *.example.com").tool_calls?.httpAllowedHosts).toEqual(["api.example.com", "*.example.com"]);
  });

  it("preserves comma-separated matches values for the CMS authoring contract", () => {
    const values = (markdown: string) => parsePolicyMarkdown(markdown).custom?.rules[0]?.values;
    const prefix = "version: 2.0.0\n\n## custom\n";
    expect(values(`${prefix}allow_only.intent.code matches: ^[0-9]{1,3}$`)).toEqual(["^[0-9]{1", "3}$"]);
    expect(values(`${prefix}allow_only.intent.code matches: \"^[0-9]{1,3}$\"`)).toEqual(['"^[0-9]{1', '3}$"']);
    expect(values(`${prefix}allow_only.intent.code matches: ^yes$\nallow_only.intent.code matches: ^no$`)).toEqual(["^yes$", "^no$"]);
    expect(values(`${prefix}allow_only.intent.environment: production, staging`)).toEqual(["production", "staging"]);
  });

  it("treats standalone HTML comment closers as policy text and still rejects unclosed openers", () => {
    const markdown = "version: 2.0.0\n\n<!-- deny_string: HIDDEN -->\n## custom\ndeny_string: -->";
    expect(parsePolicyMarkdown(markdown).custom?.rules).toEqual([
      { name: "deny_string:-->", type: "deny_string", value: "-->" },
    ]);
    expect(() => parsePolicyMarkdown(`${markdown}\n<!-- unclosed`)).toThrow("Unterminated HTML comment");
  });

  it("preserves every enforceable execution control without a numeric limit", () => {
    expect(parsePolicyMarkdown([
      "version: 2.0.0",
      "",
      "## execution_limits",
      "require_approval: bash",
      "require_shim: true",
    ].join("\n"))).toEqual({
      version: "2.0.0",
      execution_limits: {
        requireApproval: ["bash"],
        requireShim: true,
      },
    });
  });

  it("does not drop execution controls in the release gate", () => {
    const approvalOnly = parsePolicyMarkdown("version: 2.0.0\n\n## execution_limits\nrequire_approval: bash");
    expect(approvalOnly.execution_limits).toEqual({ requireApproval: ["bash"] });
    expect(canonicalizePolicyObject(approvalOnly)).toContain('"requireApproval":["bash"]');

    const shimOnly = parsePolicyMarkdown("version: 2.0.0\n\n## execution_limits\nrequire_shim: true");
    expect(shimOnly.execution_limits).toEqual({ requireShim: true });
    expect(canonicalizePolicyObject(shimOnly)).toContain('"requireShim":true');

    const falseAlongsideApproval = parsePolicyMarkdown("version: 2.0.0\n\n## execution_limits\nrequire_approval: bash\nrequire_shim: false");
    expect(falseAlongsideApproval.execution_limits).toEqual({ requireApproval: ["bash"], requireShim: false });
    expect(canonicalizePolicyObject(falseAlongsideApproval)).toContain('"requireShim":false');

    const falseAlongsideLimit = parsePolicyMarkdown("version: 2.0.0\n\n## execution_limits\nmax_tool_calls_per_task: 1\nrequire_shim: false");
    expect(falseAlongsideLimit.execution_limits).toEqual({ maxToolCallsPerTask: 1, requireShim: false });
    expect(canonicalizePolicyObject(falseAlongsideLimit)).toContain('"requireShim":false');

    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## execution_limits\nrequire_shim: false")).toThrow("at least one enforceable control");
  });

  it("fails closed for invalid execution limit values", () => {
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## execution_limits\nmax_tool_calls_per_task: 0")).toThrow("must be a positive integer");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## execution_limits\nmax_model_spend_usd_per_task: nope")).toThrow("must be a positive decimal");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## execution_limits\nunknown_limit: 1")).toThrow("Unrecognized execution_limits policy key");
  });

  it("matches Sigil Sign by rejecting soft limit controls without an enforced limit", () => {
    expect(() => parsePolicyMarkdown([
      "version: 2.0.0",
      "",
      "## soft_limits",
      "require_approval: bash",
      "require_shim: true",
    ].join("\n"))).toThrow("must declare at least one enforced limit");
    const overflowingDecimal = `1${"0".repeat(400)}`;
    expect(() => parsePolicyMarkdown(`version: 2.0.0\n\n## soft_limits\ndaily_evm_limit_eth: ${overflowingDecimal}`)).toThrow("positive decimal");
    expect(() => parsePolicyMarkdown('version: 2.0.0\n\n## soft_limits\ndaily_evm_limit_eth: "1"')).toThrow("positive decimal");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\ndaily_evm_limit_eth: '1'")).toThrow("positive decimal");
    expect(parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\ndaily_evm_limit_eth: 1ETH").soft_limits?.dailyEvmLimitEth).toBe(1);
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\ndaily_evm_limit_eth: 9000000000000.0000001")).toThrow("positive decimal");
    expect(parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\ndaily_evm_limit_eth: 9223372036854.775807").soft_limits?.dailyEvmLimitEth).toBe(Number("9223372036854.775807"));
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\ndaily_evm_limit_eth: 9223372036854.775808")).toThrow("positive decimal");
    expect(() => parsePolicyMarkdown("version: 1.0.0\n\n## tool_calls\nallowed: bash\n\n## soft_limits\ndaily_tool_calls: nope")).toThrow("daily_tool_calls must be a positive integer");
    expect(() => parsePolicyMarkdown("version: 1.0.0\n\n## tool_calls\nallowed: bash\n\n## soft_limits\ndaily_evm_limit_eth: nope")).toThrow("daily_evm_limit_eth must be a positive decimal");
    for (const version of ["1.0.0", "2.0.0", "2.1.0"]) {
      expect(() => parsePolicyMarkdown(`version: ${version}\n\n## soft_limits\ndaily_evm_limit_eth: 1e-1`)).toThrow("positive decimal");
      expect(() => parsePolicyMarkdown(`version: ${version}\n\n## soft_limits\ndaily_evm_limit_eth: 1.0000001`)).toThrow("positive decimal");
    }
    expect(parsePolicyMarkdown("version: 1.0.0\n\n## tool_calls\nallowed: bash\n\n## soft_limits\ndaily_tool_calls: 1calls").soft_limits?.dailyToolCalls).toBe(1);
    expect(parsePolicyMarkdown("version: 1.0.0\n\n## tool_calls\nallowed: bash\n\n## soft_limits\ndaily_evm_limit_eth: 1ETH").soft_limits?.dailyEvmLimitEth).toBe(1);
    expect(() => parsePolicyMarkdown("version: 1.0.0\n\n## tool_calls\nallowed: bash\n\n## soft_limits\ndaily_evm_limit_eth: 1.0000001")).toThrow("positive decimal");
    const inheritedCapPolicy = parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\ncap.toString.max_count: 1\ncap.toString.window: day\ncap.toString.action: email.send");
    const inheritedCaps = inheritedCapPolicy.soft_limits?.caps as Record<string, Record<string, unknown>>;
    expect(Object.getPrototypeOf(inheritedCaps)).toBeNull();
    expect(inheritedCaps.toString).toEqual({ maxCount: 1, window: "day", action: "email.send" });
    expect(() => parsePolicyMarkdown('version: 2.0.0\n\n## soft_limits\ncap.requests.max_count: "1"\ncap.requests.window: day\ncap.requests.action: email.send')).toThrow("max_count must be a positive integer");
    expect(parsePolicyMarkdown('version: 2.0.0\n\n## soft_limits\ncap.budget.max_sum_usd: "1.25"\ncap.budget.window: day\ncap.budget.action: email.send\ncap.budget.amount_field: amount_usd').soft_limits?.caps).toEqual({
      budget: {
        maxSumUsd: "1.25",
        window: "day",
        action: "email.send",
        amountField: "amount_usd",
      },
    });
    for (const name of ["__proto__", "constructor", "prototype"]) {
      expect(() => parsePolicyMarkdown(`version: 2.0.0\n\n## soft_limits\ncap.${name}.max_count: 1\ncap.${name}.window: day\ncap.${name}.action: email.send`)).toThrow("Reserved soft_limits cap name");
    }
    expect(inheritedCaps.missing).toBeUndefined();
    expect(Object.prototype).not.toHaveProperty("maxCount");
  });

  it("rejects duplicate soft limits without overwrite-order dependence", () => {
    for (const values of [["1", "100"], ["100", "1"]]) {
      expect(() => parsePolicyMarkdown(`version: 2.0.0\n\n## soft_limits\ndaily_tool_calls: ${values[0]}\ndaily_tool_calls: ${values[1]}`)).toThrow("Duplicate soft_limits policy key: daily_tool_calls");
    }
    for (const values of [["0.1", "1000"], ["1000", "0.1"]]) {
      expect(() => parsePolicyMarkdown(`version: 2.0.0\n\n## soft_limits\ndaily_evm_limit_eth: ${values[0]}\ndaily_evm_limit_eth: ${values[1]}`)).toThrow("Duplicate soft_limits policy key: daily_evm_limit_eth");
    }
    for (const values of [["1", "100"], ["100", "1"]]) {
      expect(() => parsePolicyMarkdown(`version: 2.0.0\n\n## soft_limits\ncap.requests.max_count: ${values[0]}\ncap.requests.max_count: ${values[1]}\ncap.requests.window: day\ncap.requests.action: email.send`)).toThrow("Duplicate soft_limits cap key: requests.max_count");
    }
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\ncap.requests.max_count: 1\ncap.requests.window: day\ncap.requests.action: email.send\ncap.requests.group_by: metadata.first\ncap.requests.group_by: metadata.second")).toThrow("Duplicate soft_limits cap key: requests.group_by");
    expect(() => parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\ndaily_tool_calls: 1\nrequire_approval: bash\nrequire_approval: email.send")).toThrow("Duplicate soft_limits policy key: require_approval");

    expect(parsePolicyMarkdown("version: 2.0.0\n\n## soft_limits\ncap.requests.max_count: 10\ncap.requests.window: day\ncap.requests.action: email.send\ncap.requests.group_by: metadata.campaign\ncap.background.max_count: 5\ncap.background.window: task\ncap.background.action: worker.*").soft_limits?.caps).toEqual({
      requests: { maxCount: 10, window: "day", action: "email.send", groupBy: "metadata.campaign" },
      background: { maxCount: 5, window: "task", action: "worker.*" },
    });
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

  it("preserves Sigilcore tool-call controls without an allowed list", () => {
    expect(parsePolicyMarkdown([
      "version: 2.0.0",
      "",
      "## custom",
      "deny_string: SECRET",
      "",
      "## tool_calls",
      "require_approval: bash",
    ].join("\n"))).toEqual({
      version: "2.0.0",
      custom: { rules: [{ name: "deny_string:SECRET", type: "deny_string", value: "SECRET" }] },
      tool_calls: { requireApproval: ["bash"] },
    });
    expect(parsePolicyMarkdown("version: 2.0.0\n\n## execution_limits\nmax_tool_calls_per_task: 5")).toEqual({
      version: "2.0.0",
      execution_limits: { maxToolCallsPerTask: 5 },
    });
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

  it("ignores signature-like headings inside closed HTML comments", () => {
    const unsigned = "version: 2.0.0\n\n<!--\n## signature\nsigil-sig: fake\n-->\n\n## tool_calls\nallowed: bash";
    expect(splitSignatureBlock(unsigned)).toEqual({ unsigned });
    const signed = appendSignatureBlock(unsigned, "abc_DEF-123");
    expect(splitSignatureBlock(signed)).toEqual({ unsigned, signature: "abc_DEF-123" });
    expect(parsePolicyMarkdown(signed)).toEqual({
      version: "2.0.0",
      tool_calls: { allowed: ["bash"] },
    });

    const commentAfterSignature = "version: 2.0.0\n\n## signature\nsigil-sig: abc\n\n<!--\n## evm\nallowed_actions: *\n-->";
    expect(splitSignatureBlock(commentAfterSignature)).toEqual({
      unsigned: "version: 2.0.0",
      signature: "abc",
    });
    expect(() => splitSignatureBlock("version: 2.0.0\n<!--\n## signature")).toThrow("Unterminated HTML comment");
    expect(() => appendSignatureBlock("version: 2.0.0\n<!--\n## signature", "abc")).toThrow("Unterminated HTML comment");
  });

  it("does not treat a heading split across lines as a signature block", () => {
    const markdown = "version: 2.0.0\n\n##\nsignature\nsigil-sig: abc";
    expect(splitSignatureBlock(markdown)).toEqual({ unsigned: markdown });
    expect(appendSignatureBlock(markdown, "real_signature")).toBe(
      `${markdown}\n\n## signature\nsigil-sig: real_signature\n`,
    );
  });
});
