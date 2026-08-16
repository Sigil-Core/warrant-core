import { canonicalizePgCommitV1 } from "./commitment.js";
import { validateCustomRules } from "./custom-rules.js";
import { assertMcpResponseExactKeys, mcpResponseCoverageProblem } from "./policy.js";
import type {
  CompiledResponsePolicyBounds,
  CompiledResponsePolicyFormat1,
  CompiledResponsePolicyFormat1Input,
  CompiledResponsePolicyFormat1Policy,
  CompiledResponsePolicyFormat2,
  CompiledResponsePolicyFormat2Input,
  CompiledResponsePolicyFormat2Observe,
  CompiledResponsePolicyFormat2Policy,
  CompiledResponsePolicyFormat2Scanner,
  CompiledResponsePolicyVerificationContext,
  CryptoAdapter,
  JsonValue,
  ParsedPolicy,
  ResponsePolicyClass,
  VerifiedCompiledResponsePolicyFormat1,
  VerifiedCompiledResponsePolicyFormat2,
} from "./types.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const HEX_64 = /^[0-9a-f]{64}$/;
const RESPONSE_CLASSES = new Set<ResponsePolicyClass>([
  "malicious_url",
  "pii",
  "prompt_injection",
  "secret",
]);
const BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BASE64URL_VALUES = new Map<string, number>(
  Array.from(BASE64URL, (character, index) => [character, index]),
);
const base64urlMaximumLength = (bytes: number): number => Math.ceil(bytes * 4 / 3);
const COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_COMPONENT_LIMITS = {
  maxProtectedHeaderBytes: 4096,
  maxPayloadBytes: 65536,
  signatureBytes: 64,
  maxPolicyStringBytes: 4096,
} as const;
export const COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS = Object.freeze({
  ...COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_COMPONENT_LIMITS,
  maxCompactJwsLength:
    base64urlMaximumLength(COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_COMPONENT_LIMITS.maxProtectedHeaderBytes)
    + base64urlMaximumLength(COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_COMPONENT_LIMITS.maxPayloadBytes)
    + base64urlMaximumLength(COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_COMPONENT_LIMITS.signatureBytes)
    + 2,
});

export const COMPILED_RESPONSE_POLICY_FORMAT_1_BOUNDS: CompiledResponsePolicyBounds = Object.freeze({
  maxProjectionBytes: 16777216,
  maxNestingDepth: 16,
  maxFindings: 256,
  maxScannerResponseBytes: 1048576,
  scannerDeadlineMs: 2000,
  maxEnvelopeLifetimeSeconds: 300,
  clockSkewSeconds: 30,
  maxObserveWindowSeconds: 2592000,
});

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const requireExactKeys = (
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
  path = "value",
): void => {
  const allowed = new Set([...required, ...optional]);
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length > 0) throw new TypeError(`${path} contains unknown field ${unknown[0]}`);
  const missing = required.filter((key) => !Object.hasOwn(value, key));
  if (missing.length > 0) throw new TypeError(`${path} is missing required field ${missing[0]}`);
  const inherited = optional.find((key) => key in value && !Object.hasOwn(value, key));
  if (inherited !== undefined) throw new TypeError(`${path} field ${inherited} must be an own property`);
  const explicitlyUndefined = optional.find(
    (key) => Object.hasOwn(value, key) && value[key] === undefined,
  );
  if (explicitlyUndefined !== undefined) {
    throw new TypeError(`${path} field ${explicitlyUndefined} must not be undefined`);
  }
};

const requireString = (value: unknown, path: string): string => {
  if (typeof value !== "string" || value.length === 0) throw new TypeError(`${path} must be a nonempty string`);
  if (encoder.encode(value).length > COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.maxPolicyStringBytes) {
    throw new TypeError(`${path} exceeds ${COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.maxPolicyStringBytes} UTF-8 bytes`);
  }
  return value;
};

const requireHexDigest = (value: unknown, path: string): string => {
  if (typeof value !== "string" || !HEX_64.test(value)) throw new TypeError(`${path} must be 64 lowercase hexadecimal characters`);
  return value;
};

const requireSafeInteger = (value: unknown, path: string, minimum = 0): number => {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) throw new TypeError(`${path} must be a safe integer at least ${minimum}`);
  return value as number;
};

const requireSortedUniqueStrings = (
  value: unknown,
  path: string,
  allowed?: ReadonlySet<string>,
): string[] => {
  if (!Array.isArray(value) || value.length === 0 || value.some((entry) => typeof entry !== "string" || entry.length === 0)) {
    throw new TypeError(`${path} must be a nonempty string array`);
  }
  const strings = value as string[];
  for (const entry of strings) requireString(entry, `${path} entry`);
  if (new Set(strings).size !== strings.length) throw new TypeError(`${path} must contain unique values`);
  const sorted = [...strings].sort();
  if (strings.some((entry, index) => entry !== sorted[index])) {
    throw new TypeError(`${path} must be lexicographically sorted`);
  }
  if (allowed && strings.some((entry) => !allowed.has(entry))) throw new TypeError(`${path} contains an unknown value`);
  return strings;
};

const requireSortedUniqueLiteralToolNames = (value: unknown, path: string): string[] => {
  const strings = requireSortedUniqueStrings(value, path);
  if (strings.some((entry) => entry.trim() !== entry || /[*,\r\n]/.test(entry))) {
    throw new TypeError(`${path} must contain exact literal tool names`);
  }
  return strings;
};

const validateBounds = (value: unknown): void => {
  if (!isRecord(value)) throw new TypeError("bounds must be an object");
  const keys = Object.keys(COMPILED_RESPONSE_POLICY_FORMAT_1_BOUNDS);
  requireExactKeys(value, keys, [], "bounds");
  for (const key of keys) {
    if (value[key] !== COMPILED_RESPONSE_POLICY_FORMAT_1_BOUNDS[key as keyof CompiledResponsePolicyBounds]) {
      throw new TypeError(`bounds.${key} must equal the format 1 ceiling`);
    }
  }
};

const validateCatalogBinding = (
  value: unknown,
  path: string,
  expectedId: string,
): void => {
  if (!isRecord(value)) throw new TypeError(`${path} must be an object`);
  requireExactKeys(value, ["id", "digest"], [], path);
  if (value.id !== expectedId) throw new TypeError(`${path}.id must equal ${expectedId}`);
  requireHexDigest(value.digest, `${path}.digest`);
};

const validateFormat1Policy = (value: unknown): CompiledResponsePolicyFormat1Policy => {
  if (!isRecord(value)) throw new TypeError("policy must be an object");
  requireExactKeys(
    value,
    ["deterministicRuleset"],
    ["webFetchTools", "httpTools", "blockClasses", "denyStrings"],
    "policy",
  );
  if (value.deterministicRuleset !== "sof-response-rules-v1") {
    throw new TypeError("policy.deterministicRuleset must equal sof-response-rules-v1");
  }
  const web = value.webFetchTools === undefined ? [] : requireSortedUniqueLiteralToolNames(value.webFetchTools, "policy.webFetchTools");
  const http = value.httpTools === undefined ? [] : requireSortedUniqueLiteralToolNames(value.httpTools, "policy.httpTools");
  if (web.length + http.length === 0) throw new TypeError("policy must contain response coverage");
  if (new Set([...web, ...http]).size !== web.length + http.length) {
    throw new TypeError("policy response coverage must be globally unique");
  }
  if (value.blockClasses !== undefined) requireSortedUniqueStrings(value.blockClasses, "policy.blockClasses", RESPONSE_CLASSES);
  if (value.denyStrings !== undefined) requireSortedUniqueStrings(value.denyStrings, "policy.denyStrings");
  return value as unknown as CompiledResponsePolicyFormat1Policy;
};

export function validateCompiledResponsePolicyFormat1(
  value: unknown,
): asserts value is CompiledResponsePolicyFormat1 {
  if (!isRecord(value)) throw new TypeError("Compiled response policy must be an object");
  requireExactKeys(value, [
    "kind", "formatVersion", "issuer", "keyId", "audience", "scope",
    "tenantId", "taskId", "policyVersion", "policyHash", "issuedAt",
    "expiresAt", "revocationEpoch", "coveredTools", "deterministicRuleset",
    "classCatalog", "bounds", "policy",
  ], [], "compiled response policy");
  if (value.kind !== "CompiledResponsePolicy") throw new TypeError("kind must equal CompiledResponsePolicy");
  if (value.formatVersion !== 1) throw new TypeError("formatVersion must equal 1");
  requireString(value.issuer, "issuer");
  requireString(value.keyId, "keyId");
  if (value.audience !== "sigil-agent-hooks") throw new TypeError("audience must equal sigil-agent-hooks");
  if (value.scope !== "mcp:result-inspect") throw new TypeError("scope must equal mcp:result-inspect");
  requireString(value.tenantId, "tenantId");
  requireString(value.taskId, "taskId");
  if (typeof value.policyVersion !== "string" || !/^2\.2\.\d+$/.test(value.policyVersion)) {
    throw new TypeError("policyVersion must match 2.2.x");
  }
  requireHexDigest(value.policyHash, "policyHash");
  const issuedAt = requireSafeInteger(value.issuedAt, "issuedAt");
  const expiresAt = requireSafeInteger(value.expiresAt, "expiresAt");
  if (expiresAt <= issuedAt || expiresAt - issuedAt > COMPILED_RESPONSE_POLICY_FORMAT_1_BOUNDS.maxEnvelopeLifetimeSeconds) {
    throw new TypeError("expiresAt must be after issuedAt by no more than 300 seconds");
  }
  requireSafeInteger(value.revocationEpoch, "revocationEpoch");
  const coveredTools = requireSortedUniqueLiteralToolNames(value.coveredTools, "coveredTools");
  validateCatalogBinding(value.deterministicRuleset, "deterministicRuleset", "sof-response-rules-v1");
  validateCatalogBinding(value.classCatalog, "classCatalog", "sof-response-classes-v1");
  validateBounds(value.bounds);
  const policy = validateFormat1Policy(value.policy);
  const expectedCoveredTools = [...(policy.webFetchTools ?? []), ...(policy.httpTools ?? [])].sort();
  if (coveredTools.length !== expectedCoveredTools.length || coveredTools.some((entry, index) => entry !== expectedCoveredTools[index])) {
    throw new TypeError("coveredTools must equal the exact sorted policy coverage union");
  }
};

const responseFromPolicy = (policy: ParsedPolicy): Record<string, unknown> => {
  if (!/^2\.2\.\d+$/.test(policy.version)) throw new TypeError("Format 1 requires a Policy 2.2.x AST");
  if ("mcp" in policy && !Object.hasOwn(policy, "mcp")) {
    throw new TypeError("Policy 2.2.x AST field mcp must be an own property");
  }
  const mcp = policy.mcp;
  if (!isRecord(mcp)) throw new TypeError("Policy 2.2.x AST does not declare MCP response coverage");
  if ("response" in mcp && !Object.hasOwn(mcp, "response")) {
    throw new TypeError("mcp field response must be an own property");
  }
  const response = mcp.response;
  if (!isRecord(response)) throw new TypeError("Policy 2.2.x AST does not declare MCP response coverage");
  assertMcpResponseExactKeys(response);
  const format2Key = ["redactClasses", "scanner", "observe"]
    .find((key) => Object.hasOwn(response, key));
  if (format2Key !== undefined) throw new TypeError(`mcp.response contains unknown field ${format2Key}`);
  const explicitlyUndefined = ["webFetchTools", "httpTools", "blockClasses"]
    .find((key) => Object.hasOwn(response, key) && response[key] === undefined);
  if (explicitlyUndefined !== undefined) {
    throw new TypeError(`mcp.response field ${explicitlyUndefined} must not be undefined`);
  }
  return response;
};

export function compileResponsePolicyFormat1(
  policy: ParsedPolicy,
  input: CompiledResponsePolicyFormat1Input,
): CompiledResponsePolicyFormat1 {
  const response = responseFromPolicy(policy);
  if (response.deterministicRuleset !== "sof-response-rules-v1") {
    throw new TypeError("mcp.response.deterministicRuleset must equal sof-response-rules-v1");
  }
  const webFetchTools = response.webFetchTools === undefined
    ? undefined
    : requireSortedUniqueLiteralToolNames(response.webFetchTools, "mcp.response.webFetchTools");
  const httpTools = response.httpTools === undefined
    ? undefined
    : requireSortedUniqueLiteralToolNames(response.httpTools, "mcp.response.httpTools");
  const blockClasses = response.blockClasses === undefined
    ? undefined
    : requireSortedUniqueStrings(response.blockClasses, "mcp.response.blockClasses", RESPONSE_CLASSES) as ResponsePolicyClass[];
  const mcp = policy.mcp as Record<string, unknown>;
  const coverageProblem = mcpResponseCoverageProblem(mcp, {
    ...(webFetchTools ? { webFetchTools } : {}),
    ...(httpTools ? { httpTools } : {}),
    deterministicRuleset: response.deterministicRuleset,
  });
  if (coverageProblem) throw new TypeError(coverageProblem);
  const denyStrings = validateCustomRules(policy.custom)
    .filter((rule) => rule.type === "response_deny_string")
    .map((rule) => requireString(rule.value, "custom.response.deny_string"))
    .sort();
  if (new Set(denyStrings).size !== denyStrings.length) {
    throw new TypeError("custom.response.deny_string values must be unique");
  }
  const compiledPolicy: CompiledResponsePolicyFormat1Policy = {
    deterministicRuleset: "sof-response-rules-v1",
    ...(webFetchTools ? { webFetchTools: [...webFetchTools] } : {}),
    ...(httpTools ? { httpTools: [...httpTools] } : {}),
    ...(blockClasses ? { blockClasses: [...blockClasses] } : {}),
    ...(denyStrings && denyStrings.length > 0 ? { denyStrings } : {}),
  };
  const coveredTools = [
    ...(compiledPolicy.webFetchTools ?? []),
    ...(compiledPolicy.httpTools ?? []),
  ].sort();
  const value: CompiledResponsePolicyFormat1 = {
    kind: "CompiledResponsePolicy",
    formatVersion: 1,
    issuer: input.issuer,
    keyId: input.keyId,
    audience: "sigil-agent-hooks",
    scope: "mcp:result-inspect",
    tenantId: input.tenantId,
    taskId: input.taskId,
    policyVersion: policy.version,
    policyHash: input.policyHash,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    revocationEpoch: input.revocationEpoch,
    coveredTools,
    deterministicRuleset: {
      id: "sof-response-rules-v1",
      digest: input.deterministicRulesetDigest,
    },
    classCatalog: {
      id: "sof-response-classes-v1",
      digest: input.classCatalogDigest,
    },
    bounds: { ...COMPILED_RESPONSE_POLICY_FORMAT_1_BOUNDS },
    policy: compiledPolicy,
  };
  validateCompiledResponsePolicyFormat1(value);
  compiledResponsePolicyFormat1Bytes(value);
  return value;
}

export function canonicalizeCompiledResponsePolicyFormat1(
  value: CompiledResponsePolicyFormat1,
): string {
  validateCompiledResponsePolicyFormat1(value);
  return canonicalizePgCommitV1(value as unknown as JsonValue);
}

export function compiledResponsePolicyFormat1Bytes(
  value: CompiledResponsePolicyFormat1,
): Uint8Array {
  const bytes = encoder.encode(canonicalizeCompiledResponsePolicyFormat1(value));
  if (bytes.length > COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.maxPayloadBytes) {
    throw new TypeError(
      `Compiled response policy payload exceeds ${COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.maxPayloadBytes} bytes`,
    );
  }
  return bytes;
}

const digestHex = async (adapter: CryptoAdapter, bytes: Uint8Array): Promise<string> => {
  const digest = await adapter.sha256(bytes);
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
};

export function hashCompiledResponsePolicyFormat1(
  adapter: CryptoAdapter,
  value: CompiledResponsePolicyFormat1,
): Promise<string> {
  return Promise.resolve().then(() => digestHex(adapter, compiledResponsePolicyFormat1Bytes(value)));
}

const validateScanner = (value: unknown): CompiledResponsePolicyFormat2Scanner => {
  if (!isRecord(value)) throw new TypeError("policy.scanner must be an object");
  requireExactKeys(value, ["required", "profile", "classes", "minConfidence"], [], "policy.scanner");
  if (typeof value.required !== "boolean") throw new TypeError("policy.scanner.required must be a boolean");
  const profile = requireString(value.profile, "policy.scanner.profile");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(profile) || profile.includes("://")) {
    throw new TypeError("policy.scanner.profile must be an opaque operator profile identifier, not a URL");
  }
  requireSortedUniqueStrings(value.classes, "policy.scanner.classes", RESPONSE_CLASSES);
  if (typeof value.minConfidence !== "number" || !Number.isFinite(value.minConfidence)
    || value.minConfidence < 0 || value.minConfidence > 1
    || Number(value.minConfidence.toFixed(4)) !== value.minConfidence) {
    throw new TypeError("policy.scanner.minConfidence must be a canonical decimal from 0 through 1 with at most four fractional digits");
  }
  return value as unknown as CompiledResponsePolicyFormat2Scanner;
};

const canonicalObserveTimestamp = (value: unknown, path: string): string => {
  if (typeof value !== "string"
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)
    || Number.isNaN(Date.parse(value))
    || new Date(value).toISOString().replace(".000Z", "Z") !== value) {
    throw new TypeError(`${path} must be canonical UTC RFC 3339 seconds`);
  }
  return value;
};

const validateObserve = (
  value: unknown,
  issuedAt: number,
): CompiledResponsePolicyFormat2Observe => {
  if (!isRecord(value)) throw new TypeError("policy.observe must be an object");
  requireExactKeys(value, ["classes", "until"], [], "policy.observe");
  requireSortedUniqueStrings(value.classes, "policy.observe.classes", RESPONSE_CLASSES);
  const until = canonicalObserveTimestamp(value.until, "policy.observe.until");
  const untilSeconds = Date.parse(until) / 1000;
  if (untilSeconds <= issuedAt
    || untilSeconds - issuedAt > COMPILED_RESPONSE_POLICY_FORMAT_1_BOUNDS.maxObserveWindowSeconds) {
    throw new TypeError("policy.observe.until must be after issuedAt by no more than 30 days");
  }
  return value as unknown as CompiledResponsePolicyFormat2Observe;
};

const validateFormat2Policy = (
  value: unknown,
  issuedAt: number,
): CompiledResponsePolicyFormat2Policy => {
  if (!isRecord(value)) throw new TypeError("policy must be an object");
  requireExactKeys(
    value,
    ["deterministicRuleset"],
    ["webFetchTools", "httpTools", "blockClasses", "denyStrings", "redactClasses", "scanner", "observe"],
    "policy",
  );
  if (value.deterministicRuleset !== "sof-response-rules-v1") {
    throw new TypeError("policy.deterministicRuleset must equal sof-response-rules-v1");
  }
  const web = value.webFetchTools === undefined ? [] : requireSortedUniqueLiteralToolNames(value.webFetchTools, "policy.webFetchTools");
  const http = value.httpTools === undefined ? [] : requireSortedUniqueLiteralToolNames(value.httpTools, "policy.httpTools");
  if (web.length + http.length === 0) throw new TypeError("policy must contain response coverage");
  if (new Set([...web, ...http]).size !== web.length + http.length) {
    throw new TypeError("policy response coverage must be globally unique");
  }
  if (value.blockClasses !== undefined) requireSortedUniqueStrings(value.blockClasses, "policy.blockClasses", RESPONSE_CLASSES);
  if (value.denyStrings !== undefined) requireSortedUniqueStrings(value.denyStrings, "policy.denyStrings");
  if (value.redactClasses !== undefined) requireSortedUniqueStrings(value.redactClasses, "policy.redactClasses", RESPONSE_CLASSES);
  if (value.scanner !== undefined) validateScanner(value.scanner);
  if (value.observe !== undefined) validateObserve(value.observe, issuedAt);
  return value as unknown as CompiledResponsePolicyFormat2Policy;
};

export function validateCompiledResponsePolicyFormat2(
  value: unknown,
): asserts value is CompiledResponsePolicyFormat2 {
  if (!isRecord(value)) throw new TypeError("Compiled response policy must be an object");
  requireExactKeys(value, [
    "kind", "formatVersion", "issuer", "keyId", "audience", "scope",
    "tenantId", "taskId", "policyVersion", "policyHash", "issuedAt",
    "expiresAt", "revocationEpoch", "coveredTools", "deterministicRuleset",
    "classCatalog", "bounds", "policy",
  ], [], "compiled response policy");
  if (value.kind !== "CompiledResponsePolicy") throw new TypeError("kind must equal CompiledResponsePolicy");
  if (value.formatVersion !== 2) throw new TypeError("formatVersion must equal 2");
  requireString(value.issuer, "issuer");
  requireString(value.keyId, "keyId");
  if (value.audience !== "sigil-agent-hooks") throw new TypeError("audience must equal sigil-agent-hooks");
  if (value.scope !== "mcp:result-inspect") throw new TypeError("scope must equal mcp:result-inspect");
  requireString(value.tenantId, "tenantId");
  requireString(value.taskId, "taskId");
  if (typeof value.policyVersion !== "string" || !/^2\.3\.\d+$/.test(value.policyVersion)) {
    throw new TypeError("policyVersion must match 2.3.x");
  }
  requireHexDigest(value.policyHash, "policyHash");
  const issuedAt = requireSafeInteger(value.issuedAt, "issuedAt");
  const expiresAt = requireSafeInteger(value.expiresAt, "expiresAt");
  if (expiresAt <= issuedAt || expiresAt - issuedAt > COMPILED_RESPONSE_POLICY_FORMAT_1_BOUNDS.maxEnvelopeLifetimeSeconds) {
    throw new TypeError("expiresAt must be after issuedAt by no more than 300 seconds");
  }
  requireSafeInteger(value.revocationEpoch, "revocationEpoch");
  const coveredTools = requireSortedUniqueLiteralToolNames(value.coveredTools, "coveredTools");
  validateCatalogBinding(value.deterministicRuleset, "deterministicRuleset", "sof-response-rules-v1");
  validateCatalogBinding(value.classCatalog, "classCatalog", "sof-response-classes-v1");
  validateBounds(value.bounds);
  const policy = validateFormat2Policy(value.policy, issuedAt);
  const expectedCoveredTools = [...(policy.webFetchTools ?? []), ...(policy.httpTools ?? [])].sort();
  if (coveredTools.length !== expectedCoveredTools.length
    || coveredTools.some((entry, index) => entry !== expectedCoveredTools[index])) {
    throw new TypeError("coveredTools must equal the exact sorted policy coverage union");
  }
}

const responseFromPolicyFormat2 = (policy: ParsedPolicy): Record<string, unknown> => {
  if (!/^2\.3\.\d+$/.test(policy.version)) throw new TypeError("Format 2 requires a Policy 2.3.x AST");
  if ("mcp" in policy && !Object.hasOwn(policy, "mcp")) {
    throw new TypeError("Policy 2.3.x AST field mcp must be an own property");
  }
  const mcp = policy.mcp;
  if (!isRecord(mcp)) throw new TypeError("Policy 2.3.x AST does not declare MCP response coverage");
  if ("response" in mcp && !Object.hasOwn(mcp, "response")) {
    throw new TypeError("mcp field response must be an own property");
  }
  const response = mcp.response;
  if (!isRecord(response)) throw new TypeError("Policy 2.3.x AST does not declare MCP response coverage");
  assertMcpResponseExactKeys(response);
  const explicitlyUndefined = ["webFetchTools", "httpTools", "blockClasses", "redactClasses", "scanner", "observe"]
    .find((key) => Object.hasOwn(response, key) && response[key] === undefined);
  if (explicitlyUndefined !== undefined) {
    throw new TypeError(`mcp.response field ${explicitlyUndefined} must not be undefined`);
  }
  return response;
};

export function compileResponsePolicyFormat2(
  policy: ParsedPolicy,
  input: CompiledResponsePolicyFormat2Input,
): CompiledResponsePolicyFormat2 {
  const response = responseFromPolicyFormat2(policy);
  if (response.deterministicRuleset !== "sof-response-rules-v1") {
    throw new TypeError("mcp.response.deterministicRuleset must equal sof-response-rules-v1");
  }
  const webFetchTools = response.webFetchTools === undefined
    ? undefined
    : requireSortedUniqueLiteralToolNames(response.webFetchTools, "mcp.response.webFetchTools");
  const httpTools = response.httpTools === undefined
    ? undefined
    : requireSortedUniqueLiteralToolNames(response.httpTools, "mcp.response.httpTools");
  const classes = (value: unknown, path: string): ResponsePolicyClass[] | undefined => value === undefined
    ? undefined
    : requireSortedUniqueStrings(value, path, RESPONSE_CLASSES) as ResponsePolicyClass[];
  const blockClasses = classes(response.blockClasses, "mcp.response.blockClasses");
  const redactClasses = classes(response.redactClasses, "mcp.response.redactClasses");
  const scanner = response.scanner === undefined ? undefined : validateScanner(response.scanner);
  const observe = response.observe === undefined ? undefined : validateObserve(response.observe, input.issuedAt);
  const mcp = policy.mcp as Record<string, unknown>;
  const coverageProblem = mcpResponseCoverageProblem(mcp, {
    ...(webFetchTools ? { webFetchTools } : {}),
    ...(httpTools ? { httpTools } : {}),
    deterministicRuleset: response.deterministicRuleset,
  });
  if (coverageProblem) throw new TypeError(coverageProblem);
  const denyStrings = validateCustomRules(policy.custom)
    .filter((rule) => rule.type === "response_deny_string")
    .map((rule) => requireString(rule.value, "custom.response.deny_string"))
    .sort();
  if (new Set(denyStrings).size !== denyStrings.length) {
    throw new TypeError("custom.response.deny_string values must be unique");
  }
  const compiledPolicy: CompiledResponsePolicyFormat2Policy = {
    deterministicRuleset: "sof-response-rules-v1",
    ...(webFetchTools ? { webFetchTools: [...webFetchTools] } : {}),
    ...(httpTools ? { httpTools: [...httpTools] } : {}),
    ...(blockClasses ? { blockClasses: [...blockClasses] } : {}),
    ...(denyStrings.length > 0 ? { denyStrings } : {}),
    ...(redactClasses ? { redactClasses: [...redactClasses] } : {}),
    ...(scanner ? { scanner: { ...scanner, classes: [...scanner.classes] } } : {}),
    ...(observe ? { observe: { ...observe, classes: [...observe.classes] } } : {}),
  };
  const coveredTools = [
    ...(compiledPolicy.webFetchTools ?? []),
    ...(compiledPolicy.httpTools ?? []),
  ].sort();
  const value: CompiledResponsePolicyFormat2 = {
    kind: "CompiledResponsePolicy",
    formatVersion: 2,
    issuer: input.issuer,
    keyId: input.keyId,
    audience: "sigil-agent-hooks",
    scope: "mcp:result-inspect",
    tenantId: input.tenantId,
    taskId: input.taskId,
    policyVersion: policy.version,
    policyHash: input.policyHash,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    revocationEpoch: input.revocationEpoch,
    coveredTools,
    deterministicRuleset: { id: "sof-response-rules-v1", digest: input.deterministicRulesetDigest },
    classCatalog: { id: "sof-response-classes-v1", digest: input.classCatalogDigest },
    bounds: { ...COMPILED_RESPONSE_POLICY_FORMAT_1_BOUNDS },
    policy: compiledPolicy,
  };
  validateCompiledResponsePolicyFormat2(value);
  compiledResponsePolicyFormat2Bytes(value);
  return value;
}

export function canonicalizeCompiledResponsePolicyFormat2(
  value: CompiledResponsePolicyFormat2,
): string {
  validateCompiledResponsePolicyFormat2(value);
  return canonicalizePgCommitV1(value as unknown as JsonValue);
}

export function compiledResponsePolicyFormat2Bytes(
  value: CompiledResponsePolicyFormat2,
): Uint8Array {
  const bytes = encoder.encode(canonicalizeCompiledResponsePolicyFormat2(value));
  if (bytes.length > COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.maxPayloadBytes) {
    throw new TypeError(`Compiled response policy payload exceeds ${COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.maxPayloadBytes} bytes`);
  }
  return bytes;
}

export function hashCompiledResponsePolicyFormat2(
  adapter: CryptoAdapter,
  value: CompiledResponsePolicyFormat2,
): Promise<string> {
  return Promise.resolve().then(() => digestHex(adapter, compiledResponsePolicyFormat2Bytes(value)));
}

const encodeBase64url = (bytes: Uint8Array): string => {
  let output = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index];
    if (first === undefined) break;
    const second = bytes[index + 1];
    const third = bytes[index + 2];
    output += BASE64URL[first >> 2];
    output += BASE64URL[((first & 3) << 4) | ((second ?? 0) >> 4)];
    if (second !== undefined) output += BASE64URL[((second & 15) << 2) | ((third ?? 0) >> 6)];
    if (third !== undefined) output += BASE64URL[third & 63];
  }
  return output;
};

const decodeBase64url = (value: string, path: string, maximumBytes: number): Uint8Array => {
  if (value.length > base64urlMaximumLength(maximumBytes)) {
    throw new TypeError(`${path} exceeds ${maximumBytes} decoded bytes`);
  }
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new TypeError(`${path} must be canonical unpadded base64url`);
  }
  const bytes: number[] = [];
  let accumulator = 0;
  let bits = 0;
  for (const character of value) {
    const digit = BASE64URL_VALUES.get(character);
    if (digit === undefined) throw new TypeError(`${path} must be canonical unpadded base64url`);
    accumulator = (accumulator << 6) | digit;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((accumulator >> bits) & 0xff);
      accumulator &= (1 << bits) - 1;
    }
  }
  const decoded = Uint8Array.from(bytes);
  if (encodeBase64url(decoded) !== value) throw new TypeError(`${path} must be canonical unpadded base64url`);
  return decoded;
};

const parseCanonicalJson = (bytes: Uint8Array, path: string): unknown => {
  let source: string;
  try {
    source = decoder.decode(bytes);
  } catch {
    throw new TypeError(`${path} must be strict UTF-8`);
  }
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    throw new TypeError(`${path} must be JSON`);
  }
  const assertDepth = (entry: unknown, depth: number): void => {
    if (depth > COMPILED_RESPONSE_POLICY_FORMAT_1_BOUNDS.maxNestingDepth) {
      throw new TypeError(`${path} exceeds ${COMPILED_RESPONSE_POLICY_FORMAT_1_BOUNDS.maxNestingDepth} nesting levels`);
    }
    if (Array.isArray(entry)) {
      for (const item of entry) assertDepth(item, depth + 1);
    } else if (isRecord(entry)) {
      for (const item of Object.values(entry)) assertDepth(item, depth + 1);
    }
  };
  assertDepth(value, 1);
  if (canonicalizePgCommitV1(value) !== source) throw new TypeError(`${path} must be pg-commit-v1 canonical JSON`);
  return value;
};

const validateProtectedHeader = (
  value: unknown,
): { alg: "EdDSA"; kid: string; typ: "sof-compiled-response-policy+jws" } => {
  if (!isRecord(value)) throw new TypeError("protected header must be an object");
  requireExactKeys(value, ["alg", "kid", "typ"], [], "protected header");
  if (value.alg !== "EdDSA") throw new TypeError("protected header alg must equal EdDSA");
  const kid = requireString(value.kid, "protected header kid");
  if (value.typ !== "sof-compiled-response-policy+jws") {
    throw new TypeError("protected header typ must equal sof-compiled-response-policy+jws");
  }
  return { alg: "EdDSA", kid, typ: "sof-compiled-response-policy+jws" };
};

const verifyTrustedContext = (
  payload: CompiledResponsePolicyFormat1 | CompiledResponsePolicyFormat2,
  header: { kid: string },
  context: CompiledResponsePolicyVerificationContext,
): void => {
  if (header.kid !== payload.keyId || payload.keyId !== context.keyId) throw new TypeError("Compiled response policy keyId mismatch");
  if (payload.issuer !== context.issuer) throw new TypeError("Compiled response policy issuer mismatch");
  if (payload.tenantId !== context.tenantId) throw new TypeError("Compiled response policy tenantId mismatch");
  if (payload.taskId !== context.taskId) throw new TypeError("Compiled response policy taskId mismatch");
  if (payload.policyHash !== context.policyHash) throw new TypeError("Compiled response policy policyHash mismatch");
  if (payload.revocationEpoch !== context.revocationEpoch) throw new TypeError("Compiled response policy revocationEpoch mismatch");
  if (payload.deterministicRuleset.digest !== context.deterministicRulesetDigest) throw new TypeError("Compiled response policy ruleset digest mismatch");
  if (payload.classCatalog.digest !== context.classCatalogDigest) throw new TypeError("Compiled response policy class catalog digest mismatch");
  if (!Number.isSafeInteger(context.now)) throw new TypeError("Verification time must be Unix seconds");
  if (payload.issuedAt > context.now + COMPILED_RESPONSE_POLICY_FORMAT_1_BOUNDS.clockSkewSeconds) {
    throw new TypeError("Compiled response policy is not yet valid");
  }
  if (payload.expiresAt < context.now - COMPILED_RESPONSE_POLICY_FORMAT_1_BOUNDS.clockSkewSeconds) {
    throw new TypeError("Compiled response policy is expired");
  }
};

export async function verifyCompiledResponsePolicyFormat1(
  adapter: CryptoAdapter,
  compactJws: string,
  context: CompiledResponsePolicyVerificationContext,
): Promise<VerifiedCompiledResponsePolicyFormat1> {
  if (typeof compactJws !== "string") {
    throw new TypeError("Compiled response policy JWS must be a string");
  }
  if (compactJws.length > COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.maxCompactJwsLength) {
    throw new TypeError(`Compiled response policy JWS exceeds ${COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.maxCompactJwsLength} characters`);
  }
  const segments = compactJws.split(".");
  if (segments.length !== 3 || segments.some((segment) => segment.length === 0)) {
    throw new TypeError("Compiled response policy JWS must contain exactly three segments");
  }
  const [headerSegment, payloadSegment, signatureSegment] = segments as [string, string, string];
  const headerBytes = decodeBase64url(
    headerSegment,
    "protected header",
    COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.maxProtectedHeaderBytes,
  );
  const payloadBytes = decodeBase64url(
    payloadSegment,
    "payload",
    COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.maxPayloadBytes,
  );
  const signature = decodeBase64url(
    signatureSegment,
    "signature",
    COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.signatureBytes,
  );
  const header = validateProtectedHeader(parseCanonicalJson(headerBytes, "protected header"));
  if (header.kid !== context.keyId) throw new TypeError("Compiled response policy keyId mismatch");
  if (signature.length !== COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.signatureBytes) {
    throw new TypeError("Compiled response policy signature must be 64 Ed25519 bytes");
  }
  const payloadValue = parseCanonicalJson(payloadBytes, "payload");
  validateCompiledResponsePolicyFormat1(payloadValue);
  if (!adapter.verifyEd25519) throw new TypeError("Crypto adapter does not support Ed25519 verification");
  const signingInput = encoder.encode(`${headerSegment}.${payloadSegment}`);
  if (!await adapter.verifyEd25519(context.publicKey, signature, signingInput)) {
    throw new TypeError("Compiled response policy signature is invalid");
  }
  verifyTrustedContext(payloadValue, header, context);
  return {
    ...payloadValue,
    compiledPolicyDigest: await digestHex(adapter, payloadBytes),
  };
}

export async function verifyCompiledResponsePolicyFormat2(
  adapter: CryptoAdapter,
  compactJws: string,
  context: CompiledResponsePolicyVerificationContext,
): Promise<VerifiedCompiledResponsePolicyFormat2> {
  if (typeof compactJws !== "string") {
    throw new TypeError("Compiled response policy JWS must be a string");
  }
  if (compactJws.length > COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.maxCompactJwsLength) {
    throw new TypeError(`Compiled response policy JWS exceeds ${COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.maxCompactJwsLength} characters`);
  }
  const segments = compactJws.split(".");
  if (segments.length !== 3 || segments.some((segment) => segment.length === 0)) {
    throw new TypeError("Compiled response policy JWS must contain exactly three segments");
  }
  const [headerSegment, payloadSegment, signatureSegment] = segments as [string, string, string];
  const headerBytes = decodeBase64url(
    headerSegment,
    "protected header",
    COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.maxProtectedHeaderBytes,
  );
  const payloadBytes = decodeBase64url(
    payloadSegment,
    "payload",
    COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.maxPayloadBytes,
  );
  const signature = decodeBase64url(
    signatureSegment,
    "signature",
    COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.signatureBytes,
  );
  const header = validateProtectedHeader(parseCanonicalJson(headerBytes, "protected header"));
  if (header.kid !== context.keyId) throw new TypeError("Compiled response policy keyId mismatch");
  if (signature.length !== COMPILED_RESPONSE_POLICY_FORMAT_1_JWS_LIMITS.signatureBytes) {
    throw new TypeError("Compiled response policy signature must be 64 Ed25519 bytes");
  }
  const payloadValue = parseCanonicalJson(payloadBytes, "payload");
  validateCompiledResponsePolicyFormat2(payloadValue);
  if (!adapter.verifyEd25519) throw new TypeError("Crypto adapter does not support Ed25519 verification");
  const signingInput = encoder.encode(`${headerSegment}.${payloadSegment}`);
  if (!await adapter.verifyEd25519(context.publicKey, signature, signingInput)) {
    throw new TypeError("Compiled response policy signature is invalid");
  }
  verifyTrustedContext(payloadValue, header, context);
  return {
    ...payloadValue,
    compiledPolicyDigest: await digestHex(adapter, payloadBytes),
  };
}
