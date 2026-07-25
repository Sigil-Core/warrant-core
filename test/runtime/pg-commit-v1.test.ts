import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  canonicalizePgCommitV1,
  hashPgCommitV1,
  pgCommitV1Bytes,
} from "../../src/index.js";
import { createNodeCryptoAdapter } from "../../src/crypto/node.js";
import type { JsonValue } from "../../src/types.js";

interface CommitmentVector {
  id: string;
  intent: JsonValue;
  canonicalJson: string;
  sha256: string;
}

interface RejectionVector {
  id: string;
  runtimeValueKind: keyof typeof rejectionValues;
  error: string;
}

const vectorFile = new URL("../vectors/pg-commit-v1.json", import.meta.url);
const fixture = JSON.parse(readFileSync(vectorFile, "utf8")) as {
  vectors: CommitmentVector[];
  rejections: RejectionVector[];
};
const vectors = fixture.vectors;
const nodeCrypto = createNodeCryptoAdapter();

const rejectionValues = {
  undefined: () => ({ value: undefined }),
  nan: () => ({ value: Number.NaN }),
  infinity: () => ({ value: Number.POSITIVE_INFINITY }),
  bigint: () => ({ value: 1n }),
  function: () => ({ value: () => undefined }),
  symbol: () => ({ value: Symbol("test") }),
  cyclic: () => {
    const value: { self?: unknown } = {};
    value.self = value;
    return value;
  },
  "non-plain-object": () => new Date(),
  "symbol-keyed-object-property": () => {
    const value = { safe: true };
    Object.defineProperty(value, Symbol("test"), { value: true });
    return value;
  },
  "non-enumerable-object-property": () => {
    const value = { safe: true };
    Object.defineProperty(value, "hidden", { value: true });
    return value;
  },
  "accessor-property": () => {
    const value = {};
    Object.defineProperty(value, "value", {
      enumerable: true,
      get: () => "never",
    });
    return value;
  },
  "sparse-array": () => {
    const value: unknown[] = [];
    value[1] = "present";
    return value;
  },
  "non-index-array-property": () => {
    const value: unknown[] = [];
    Object.defineProperty(value, "label", {
      enumerable: true,
      value: "bad",
    });
    return value;
  },
  "non-enumerable-array-property": () => {
    const value = ["value"];
    Object.defineProperty(value, "0", {
      enumerable: false,
      value: "value",
    });
    return value;
  },
  "non-plain-array": () => {
    const value: unknown[] = [];
    Object.setPrototypeOf(value, {});
    return value;
  },
  "symbol-keyed-array-property": () => {
    const value: unknown[] = [];
    Object.defineProperty(value, Symbol("test"), { value: true });
    return value;
  },
};

describe("pg-commit-v1", () => {
  for (const vector of vectors) {
    it(`${vector.id} has the pinned canonical JSON and hash`, async () => {
      expect(canonicalizePgCommitV1(vector.intent)).toBe(vector.canonicalJson);
      expect(new TextDecoder().decode(pgCommitV1Bytes(vector.intent))).toBe(vector.canonicalJson);
      await expect(hashPgCommitV1(nodeCrypto, vector.intent)).resolves.toBe(vector.sha256);
    });
  }

  for (const vector of fixture.rejections) {
    it(`${vector.id} rejects with the pinned error`, () => {
      expect(() => canonicalizePgCommitV1(rejectionValues[vector.runtimeValueKind]())).toThrow(vector.error);
    });
  }
});
