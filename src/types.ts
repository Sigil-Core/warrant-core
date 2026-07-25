export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export interface ParsedPolicy {
  version: string;
  evm?: Record<string, unknown>;
  tool_calls?: Record<string, unknown>;
  custom?: { rules: Array<Record<string, unknown>>; requireApproval?: string[]; requireShim?: boolean };
  mcp?: Record<string, unknown>;
  soft_limits?: Record<string, unknown>;
  execution_limits?: Record<string, unknown>;
  repository?: Record<string, unknown>;
  filesystem?: Record<string, unknown>;
  git?: Record<string, unknown>;
  database?: Record<string, unknown>;
}

export interface CryptoAdapter {
  sha256(data: Uint8Array): Promise<Uint8Array>;
  signEd25519?(privateKeyPkcs8: Uint8Array, data: Uint8Array): Promise<Uint8Array>;
  verifyEd25519?(publicKeySpkiOrRaw: Uint8Array, signature: Uint8Array, data: Uint8Array): Promise<boolean>;
}

export interface SplitSignatureBlock {
  unsigned: string;
  signature?: string;
}
