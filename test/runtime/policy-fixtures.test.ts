import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  canonicalizePolicyObject,
  hashPolicy,
  parsePolicyMarkdown,
} from "../../src/index.js";
import { createNodeCryptoAdapter } from "../../src/crypto/node.js";

interface PolicyFixture {
  slug: string;
  templateBody: string;
  templateBodySha256: string;
  canonicalPolicy: unknown;
  canonicalPolicyJson: string;
  policyHashSha256: string;
}

const vectorFile = new URL("../vectors/policy-fixtures.json", import.meta.url);
const fixtures = (JSON.parse(readFileSync(vectorFile, "utf8")) as { fixtures: PolicyFixture[] }).fixtures;
const nodeCrypto = createNodeCryptoAdapter();

function unsignedPolicy(templateBody: string): string {
  return templateBody.replace(/\n## signature[\s\S]*$/i, "").trimEnd();
}

describe("pinned SOF policy fixtures", () => {
  it("contains all six pinned source bodies", () => {
    expect(fixtures.map((fixture) => fixture.slug)).toEqual([
      "defi-agent",
      "claude-code-agent",
      "outbound-email-agent",
      "stablecoin-treasury-agent",
      "customer-support-agent",
      "mcp-server-agent",
    ]);
  });

  for (const fixture of fixtures) {
    it(`${fixture.slug} matches its source body, canonical JSON, and hash`, async () => {
      expect(createHash("sha256").update(fixture.templateBody, "utf8").digest("hex"))
        .toBe(fixture.templateBodySha256);

      const parsed = parsePolicyMarkdown(unsignedPolicy(fixture.templateBody));
      expect(parsed).toEqual(fixture.canonicalPolicy);
      expect(canonicalizePolicyObject(parsed)).toBe(fixture.canonicalPolicyJson);
      await expect(hashPolicy(nodeCrypto, parsed)).resolves.toBe(fixture.policyHashSha256);
    });
  }
});
