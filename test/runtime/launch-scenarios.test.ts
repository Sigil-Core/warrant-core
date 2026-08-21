import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  canonicalizePgCommitV1,
  hashPgCommitV1,
  pgCommitV1Bytes,
} from "../../src/index.js";
import { createNodeCryptoAdapter } from "../../src/crypto/node.js";
import type { JsonValue } from "../../src/types.js";

interface ExpectedDecision {
  status: "ALLOWED" | "PENDING" | "DENIED";
  matchedRule: string | null;
  errorCode: string | null;
}

interface LaunchScenario {
  id: string;
  templateId: "defi-agent" | "claude-code-agent" | "outbound-email-agent";
  endpoint: "/v1/authorize" | "/v1/authorize/test-run";
  signedClearance: boolean;
  request: { txCommit: string; intent: JsonValue };
  canonicalIntentJson: string;
  txCommitSha256: string;
  expected: ExpectedDecision;
  expectedEvaluator: {
    decision: ExpectedDecision["status"];
    violatedRule: string | null;
    lexErrorCode: string | null;
  };
  expectedPrecedence?: {
    evaluatedRule: string;
    declaredButPreemptedRule: string;
  };
}

const vectorFile = new URL("../vectors/launch-scenarios.json", import.meta.url);
const fixture = JSON.parse(readFileSync(vectorFile, "utf8")) as {
  evaluatorValidation: {
    sigilSignBaseCommit: string;
    decisionVocabularyRevision: number;
    parser: string;
    evaluator: string;
  };
  vectors: LaunchScenario[];
};
const nodeCrypto = createNodeCryptoAdapter();

describe("Proving Ground launch scenarios", () => {
  it("records the Wave 2 expectation provenance", () => {
    expect(fixture.evaluatorValidation).toMatchObject({
      sigilSignBaseCommit: "3b1f420ae037ac9550ea4986274c218f68f69d39",
      decisionVocabularyRevision: 6,
      parser: "parseWarrantyContent",
      evaluator: "evaluateStrict",
    });
  });

  it("contains the fixed three-by-three launch matrix", () => {
    expect(fixture.vectors).toHaveLength(9);
    expect(fixture.vectors.filter((vector) => vector.signedClearance)).toHaveLength(3);
    expect(fixture.vectors.filter((vector) => vector.endpoint === "/v1/authorize/test-run")).toHaveLength(6);
  });

  for (const vector of fixture.vectors) {
    it(`${vector.id} has a stable request binding`, async () => {
      expect(canonicalizePgCommitV1(vector.request.intent)).toBe(vector.canonicalIntentJson);
      expect(new TextDecoder().decode(pgCommitV1Bytes(vector.request.intent))).toBe(vector.canonicalIntentJson);
      expect(vector.request.txCommit).toBe(vector.txCommitSha256);
      await expect(hashPgCommitV1(nodeCrypto, vector.request.intent)).resolves.toBe(vector.txCommitSha256);
    });

    it(`${vector.id} declares a complete expected live outcome`, () => {
      expect(["ALLOWED", "PENDING", "DENIED"]).toContain(vector.expected.status);
      if (vector.expected.status === "ALLOWED") {
        expect(vector.expected.matchedRule).toBeNull();
        expect(vector.expected.errorCode).toBeNull();
      } else {
        expect(vector.expected.matchedRule).toEqual(expect.any(String));
        expect(vector.expected.errorCode).toEqual(expect.any(String));
      }
    });

    it(`${vector.id} pins the Wave 2 evaluator result`, () => {
      expect(vector.expectedEvaluator.decision).toBe(vector.expected.status);
      expect(vector.expectedEvaluator.violatedRule).toBe(vector.expected.matchedRule);
    });

    if (vector.expectedPrecedence) {
      it(`${vector.id} preserves the Policy 2.1 precedence contract`, () => {
        expect(vector.expected.matchedRule).toBe(vector.expectedPrecedence.evaluatedRule);
        expect(vector.expected.matchedRule).not.toBe(vector.expectedPrecedence.declaredButPreemptedRule);
      });
    }
  }
});
