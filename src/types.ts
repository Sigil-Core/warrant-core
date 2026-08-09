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

export type ResponsePolicyClass =
  | "malicious_url"
  | "pii"
  | "prompt_injection"
  | "secret";

export interface ParsedMcpResponsePolicy {
  webFetchTools?: string[];
  httpTools?: string[];
  deterministicRuleset: "sof-response-rules-v1";
  blockClasses?: ResponsePolicyClass[];
}

export interface CompiledResponsePolicyBounds {
  maxProjectionBytes: 16777216;
  maxNestingDepth: 16;
  maxFindings: 256;
  maxScannerResponseBytes: 1048576;
  scannerDeadlineMs: 2000;
  maxEnvelopeLifetimeSeconds: 300;
  clockSkewSeconds: 30;
  maxObserveWindowSeconds: 2592000;
}

export interface CompiledResponsePolicyFormat1Policy {
  deterministicRuleset: "sof-response-rules-v1";
  webFetchTools?: string[];
  httpTools?: string[];
  blockClasses?: ResponsePolicyClass[];
  denyStrings?: string[];
}

export interface CompiledResponsePolicyFormat1 {
  kind: "CompiledResponsePolicy";
  formatVersion: 1;
  issuer: string;
  keyId: string;
  audience: "sigil-agent-hooks";
  scope: "mcp:result-inspect";
  tenantId: string;
  taskId: string;
  policyVersion: string;
  policyHash: string;
  issuedAt: number;
  expiresAt: number;
  revocationEpoch: number;
  coveredTools: string[];
  deterministicRuleset: {
    id: "sof-response-rules-v1";
    digest: string;
  };
  classCatalog: {
    id: "sof-response-classes-v1";
    digest: string;
  };
  bounds: CompiledResponsePolicyBounds;
  policy: CompiledResponsePolicyFormat1Policy;
}

export interface CompiledResponsePolicyFormat1Input {
  issuer: string;
  keyId: string;
  tenantId: string;
  taskId: string;
  policyHash: string;
  issuedAt: number;
  expiresAt: number;
  revocationEpoch: number;
  deterministicRulesetDigest: string;
  classCatalogDigest: string;
}

export interface CompiledResponsePolicyVerificationContext {
  publicKey: Uint8Array;
  issuer: string;
  keyId: string;
  tenantId: string;
  taskId: string;
  policyHash: string;
  revocationEpoch: number;
  deterministicRulesetDigest: string;
  classCatalogDigest: string;
  now: number;
}

export interface VerifiedCompiledResponsePolicyFormat1 extends CompiledResponsePolicyFormat1 {
  compiledPolicyDigest: string;
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
  | "WARRANT_ENVELOPE_EMPTY_POLICY"
  | "WARRANT_ENVELOPE_STRICT_BOM"
  | "WARRANT_ENVELOPE_STRICT_SIZE"
  | "WARRANT_ENVELOPE_STRICT_CR"
  | "WARRANT_ENVELOPE_STRICT_NUL"
  | "WARRANT_ENVELOPE_STRICT_HEADER"
  | "WARRANT_ENVELOPE_STRICT_SIGNATURE";

export interface SignedEnvelope {
  payload: Uint8Array;
  signature?: string;
}

/**
 * Strict raw-byte Warrant framing for CC-1 callers. This deliberately differs
 * from the legacy helpers: it forbids a BOM, CR, and NUL; requires one literal
 * LF before the final signature header. It preserves the raw input and derives
 * the signable preimage by collapsing only the permitted trailing whitespace
 * before that header to exactly one LF.
 */
export interface WarrantMarkdownFrame {
  raw: Uint8Array;
  markdown: string;
  /** CC-1 signing and verification preimage: policy bytes with one final LF. */
  unsigned: Uint8Array;
  /**
   * Legacy envelope verification preimage. This preserves the bytes that the
   * published `emit()` helper signed before writing its two-LF separator.
   * New CC-1 signing and verification must use `unsigned` instead.
   */
  legacyUnsigned: Uint8Array;
  signature: string;
}

/** Optional lower caller limit for strict framing. The hard ceiling is 256 KiB. */
export interface StrictWarrantFramingOptions {
  maxBytes?: number;
}

export interface PolicyAdvisory {
  code: "WARRANT_PROFILE_FIELD_MISSING" | "WARRANT_PROFILE_SHIM_NOT_REQUIRED";
  path: string;
  message: string;
}
