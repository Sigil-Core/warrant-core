import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  canonicalizePgCommitV1,
  hashPgCommitV1,
  pgCommitV1Bytes,
} from "../../src/index.js";
import { createNodeCryptoAdapter } from "../../src/crypto/node.js";
import type { JsonValue } from "../../src/types.js";
import { pgCommitRejectionValue } from "../shared/runtime-vectors.js";

interface CommitmentVector {
  id: string;
  intent: JsonValue;
  canonicalJson: string;
  sha256: string;
}

interface RejectionVector { id: string; runtimeValueKind: string; error: string; }

const vectorFile = new URL("../vectors/pg-commit-v1.json", import.meta.url);
const fixture = JSON.parse(readFileSync(vectorFile, "utf8")) as {
  vectors: CommitmentVector[];
  rejections: RejectionVector[];
};
const vectors = fixture.vectors;
const nodeCrypto = createNodeCryptoAdapter();

describe("pg-commit-v1", () => {
  for (const vector of vectors) {
    it(`${vector.id} has the pinned canonical JSON and hash`, async () => {
      expect(canonicalizePgCommitV1(vector.intent)).toBe(vector.canonicalJson);
      if (vector.id === "json-scalars") expect(Object.is((vector.intent as { negativeZero: number }).negativeZero, -0)).toBe(true);
      expect(new TextDecoder().decode(pgCommitV1Bytes(vector.intent))).toBe(vector.canonicalJson);
      await expect(hashPgCommitV1(nodeCrypto, vector.intent)).resolves.toBe(vector.sha256);
    });
  }

  for (const vector of fixture.rejections) {
    it(`${vector.id} rejects with the pinned error`, () => {
      expect(() => canonicalizePgCommitV1(pgCommitRejectionValue(vector.runtimeValueKind))).toThrow(vector.error);
    });
  }
});
