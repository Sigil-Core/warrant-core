import { createNodeCryptoAdapter } from "../../src/crypto/node.js";
import { defineSharedRuntimeVectorTests } from "../shared/runtime-vectors.js";

defineSharedRuntimeVectorTests("Node.js", createNodeCryptoAdapter());
