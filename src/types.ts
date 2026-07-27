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

export type WarrantEnvelopeErrorCode =
  | "WARRANT_ENVELOPE_INVALID_UTF8"
  | "WARRANT_ENVELOPE_DUPLICATE_HEADER"
  | "WARRANT_ENVELOPE_TRAILING_CONTENT"
  | "WARRANT_ENVELOPE_DUPLICATE_SIGNATURE"
  | "WARRANT_ENVELOPE_UNEXPECTED_HEADER"
  | "WARRANT_ENVELOPE_EMPTY_POLICY";

export interface SignedEnvelope {
  payload: Uint8Array;
  signature?: string;
}

export interface PolicyAdvisory {
  code: "WARRANT_PROFILE_FIELD_MISSING" | "WARRANT_PROFILE_SHIM_NOT_REQUIRED";
  path: string;
  message: string;
}
