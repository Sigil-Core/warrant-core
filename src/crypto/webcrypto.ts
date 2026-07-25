import type { CryptoAdapter } from "../types.js";

/**
 * Minimal Web Crypto boundary kept local so the platform-neutral core does
 * not pull DOM ambient types into its compilation contract.
 */
export interface WebCryptoKey {}

export interface WebCryptoSubtle {
  digest(algorithm: string, data: ArrayBuffer): Promise<ArrayBuffer>;
  importKey(
    format: "pkcs8" | "spki",
    keyData: ArrayBuffer,
    algorithm: { name: "Ed25519" },
    extractable: boolean,
    usages: Array<"sign" | "verify">,
  ): Promise<WebCryptoKey>;
  sign(algorithm: string, key: WebCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer>;
  verify(algorithm: string, key: WebCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean>;
}

export interface WebCryptoLike {
  subtle: WebCryptoSubtle;
}

function bufferSource(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

export function createWebCryptoAdapter(crypto: WebCryptoLike): CryptoAdapter {
  return {
    async sha256(data) {
      return new Uint8Array(await crypto.subtle.digest("SHA-256", bufferSource(data)));
    },
    async signEd25519(privateKeyPkcs8, data) {
      const key = await crypto.subtle.importKey("pkcs8", bufferSource(privateKeyPkcs8), { name: "Ed25519" }, false, ["sign"]);
      return new Uint8Array(await crypto.subtle.sign("Ed25519", key, bufferSource(data)));
    },
    async verifyEd25519(publicKeySpkiOrRaw, signature, data) {
      const bytes = publicKeySpkiOrRaw.byteLength === 32
        ? new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, ...publicKeySpkiOrRaw])
        : publicKeySpkiOrRaw;
      const key = await crypto.subtle.importKey("spki", bufferSource(bytes), { name: "Ed25519" }, false, ["verify"]);
      return crypto.subtle.verify("Ed25519", key, bufferSource(signature), bufferSource(data));
    }
  };
}
