import { createWebCryptoAdapter } from "../../src/crypto/workers.js";
import { defineSharedRuntimeVectorTests } from "../shared/runtime-vectors.js";

defineSharedRuntimeVectorTests("Cloudflare Workers (workerd)", createWebCryptoAdapter(globalThis.crypto));
