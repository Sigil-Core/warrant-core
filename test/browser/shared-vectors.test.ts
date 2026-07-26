import { createWebCryptoAdapter } from "../../src/crypto/browser.js";
import { defineSharedRuntimeVectorTests } from "../shared/runtime-vectors.js";

defineSharedRuntimeVectorTests("browser (Chromium)", createWebCryptoAdapter(globalThis.crypto));
