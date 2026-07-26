import { createHash, sign, verify } from "node:crypto";
import type { CryptoAdapter } from "../types.js";

/** Node adapter is isolated behind the ./crypto/node export and never imported by core. */
export function createNodeCryptoAdapter(): CryptoAdapter {
  return {
    async sha256(data) {
      return new Uint8Array(createHash("sha256").update(data).digest());
    },
    async signEd25519(privateKeyPkcs8, data) {
      return new Uint8Array(sign(null, data, { key: Buffer.from(privateKeyPkcs8), format: "der", type: "pkcs8" }));
    },
    async verifyEd25519(publicKeySpkiOrRaw, signature, data) {
      const spki = publicKeySpkiOrRaw.byteLength === 32
        ? Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, ...publicKeySpkiOrRaw])
        : Buffer.from(publicKeySpkiOrRaw);
      return verify(null, data, { key: spki, format: "der", type: "spki" }, signature);
    }
  };
}
