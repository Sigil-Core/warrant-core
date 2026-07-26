import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { appendSignatureBlock, splitSignatureBlock } from "../../src/index.js";
import { createWebCryptoAdapter } from "../../src/crypto/browser.js";
import { createNodeCryptoAdapter } from "../../src/crypto/node.js";
import { createWebCryptoAdapter as createWorkersCryptoAdapter } from "../../src/crypto/workers.js";

interface SignatureVector {
  id: string;
  key?: string;
  messageUtf8?: string;
  signatureBase64url?: string;
  unsigned?: string;
  signedMarkdown?: string;
  markdown?: string;
  error?: string;
}

interface SignatureVectors {
  testOnly: true;
  keys: { rfc8032Test1: { rawPublicKeyBase64url: string; spkiDerBase64url: string } };
  vectors: SignatureVector[];
}

const vectorFile = new URL("../vectors/signature-blocks.json", import.meta.url);
const fixture = JSON.parse(readFileSync(vectorFile, "utf8")) as SignatureVectors;
const key = fixture.keys.rfc8032Test1;
const bytes = (value: string) => new Uint8Array(Buffer.from(value, "base64url"));
const text = new TextEncoder();

describe("signature block and test-only Ed25519 vectors", () => {
  it("marks this corpus as test-only", () => {
    expect(fixture.testOnly).toBe(true);
  });

  it("verifies the RFC 8032 empty-message vector through Node, browser, and Workers adapters", async () => {
    const vector = fixture.vectors.find((entry) => entry.id === "rfc8032-test-1-empty-message")!;
    const message = text.encode(vector.messageUtf8!);
    const signature = bytes(vector.signatureBase64url!);
    const rawPublicKey = bytes(key.rawPublicKeyBase64url);

    await expect(createNodeCryptoAdapter().verifyEd25519!(rawPublicKey, signature, message)).resolves.toBe(true);
    await expect(createWebCryptoAdapter(globalThis.crypto).verifyEd25519!(rawPublicKey, signature, message)).resolves.toBe(true);
    await expect(createWorkersCryptoAdapter(globalThis.crypto).verifyEd25519!(rawPublicKey, signature, message)).resolves.toBe(true);
  });

  it("splits and reassembles the known test-only signature block", () => {
    const vector = fixture.vectors.find((entry) => entry.id === "signature-block-test-only-policy")!;
    expect(splitSignatureBlock(vector.signedMarkdown!)).toEqual({
      unsigned: vector.unsigned,
      signature: vector.signatureBase64url,
    });
    expect(appendSignatureBlock(vector.unsigned!, vector.signatureBase64url!)).toBe(vector.signedMarkdown);
  });

  it("rejects malformed signature blocks", () => {
    for (const vector of fixture.vectors.filter((entry) => entry.error)) {
      expect(() => splitSignatureBlock(vector.markdown!)).toThrow(vector.error);
    }
  });
});
