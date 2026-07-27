import type { ParsedPolicy } from "./types.js";

export const AUTHORING_SURFACES = ["manual-form", "manual-advanced", "builder"] as const;
export type AuthoringSurface = (typeof AUTHORING_SURFACES)[number];

export const POLICY_VERSION_RANGES = ["0.x", "1.x", "2.0.x", "2.1.x"] as const;
export type PolicyVersionRange = (typeof POLICY_VERSION_RANGES)[number];

/** The versioned, service-owned capability registry shared with Sigil Sign. */
export const SIGN_CAPABILITIES_SCHEMA_VERSION = 1 as const;
export const SIGIL_SIGN_ENGINE_VERSION = "0.1.0" as const;

export const DEPLOY_FEATURE_KEYS = [
  "policy.version",
  "signature.sigil-envelope-v1",
  "profile.repository",
  "profile.filesystem",
  "profile.git",
  "profile.database",
  "evm",
  "evm.chain_actions",
  "evm.token",
  "evm.token.consensus_threshold",
  "evm.require_calldata_enrichment",
  "evm.calldata_unknown_selector",
  "tool_calls",
  "tool_calls.http",
  "tool_calls.http.method_rules",
  "mcp",
  "custom",
  "soft_limits",
  "soft_limits.cap",
  "execution_limits",
  "execution_limits.require_approval",
  "execution_limits.require_shim",
] as const;
export type DeployFeatureKey = (typeof DEPLOY_FEATURE_KEYS)[number];
export const SIGN_CAPABILITY_FEATURE_KEYS = DEPLOY_FEATURE_KEYS;
export type SignCapabilityFeatureKey = DeployFeatureKey;

export type CapabilityDimension = "author" | "import" | "preserve" | "deploy";

export interface AuthoringCapabilityDimensions {
  readonly author: boolean;
  readonly import: boolean;
  readonly preserve: boolean;
  readonly deploy: boolean;
}

export interface MaxItemsConstraint {
  readonly id: string;
  readonly kind: "max-items";
  readonly max: number;
}

export interface AllowedValuesConstraint {
  readonly id: string;
  readonly kind: "allowed-values";
  readonly values: readonly (string | number)[];
}

export interface RequiredValueConstraint {
  readonly id: string;
  readonly kind: "required-value";
  readonly value: string | number | boolean;
}

export type RepresentabilityConstraint =
  | MaxItemsConstraint
  | AllowedValuesConstraint
  | RequiredValueConstraint;

export interface SurfaceCapability extends AuthoringCapabilityDimensions {
  readonly constraints: readonly RepresentabilityConstraint[];
}

export interface AuthoringCapabilityEntry {
  readonly versions: readonly PolicyVersionRange[];
  readonly deploy_feature_key: DeployFeatureKey;
  readonly surfaces: Readonly<Record<AuthoringSurface, SurfaceCapability>>;
}

export interface ConstraintViolation {
  readonly constraint_id: string;
  readonly path: string;
  readonly message: string;
}

const ALL_VERSIONS: readonly PolicyVersionRange[] = POLICY_VERSION_RANGES;
const V2_VERSIONS: readonly PolicyVersionRange[] = ["2.0.x", "2.1.x"];
const V21_VERSIONS: readonly PolicyVersionRange[] = ["2.1.x"];

const full = (constraints: readonly RepresentabilityConstraint[] = []): SurfaceCapability => ({
  author: true,
  import: true,
  preserve: true,
  deploy: true,
  constraints,
});

const preserveOnly = (
  constraints: readonly RepresentabilityConstraint[] = [],
): SurfaceCapability => ({
  author: false,
  import: true,
  preserve: true,
  deploy: true,
  constraints,
});

const unsupported = (): SurfaceCapability => ({
  author: false,
  import: false,
  preserve: false,
  deploy: false,
  constraints: [],
});

const surfaces = (
  manualForm: SurfaceCapability,
  builder: SurfaceCapability,
): Readonly<Record<AuthoringSurface, SurfaceCapability>> => ({
  "manual-form": manualForm,
  "manual-advanced": full(),
  builder,
});

const entry = (
  versions: readonly PolicyVersionRange[],
  deployFeatureKey: DeployFeatureKey,
  manualForm: SurfaceCapability = full(),
  builder: SurfaceCapability = full(),
): AuthoringCapabilityEntry => ({
  versions,
  deploy_feature_key: deployFeatureKey,
  surfaces: surfaces(manualForm, builder),
});

const ROOT_MAX_ONE: readonly RepresentabilityConstraint[] = [
  { id: "single-repository-root", kind: "max-items", max: 1 },
];
const REPOSITORY_PROVIDERS: readonly RepresentabilityConstraint[] = [
  {
    id: "repository-provider-enum",
    kind: "allowed-values",
    values: ["generic", "github", "gitlab", "bitbucket"],
  },
];
const BUILDER_CHAINS: readonly RepresentabilityConstraint[] = [
  {
    id: "builder-chain-enum",
    kind: "allowed-values",
    values: [1, 8453, 42161, 10, 137, 56, 43114],
  },
];

const manifest = {
  "policy.version": entry(ALL_VERSIONS, "policy.version"),
  "signature.sigil-envelope-v1": entry(
    ALL_VERSIONS,
    "signature.sigil-envelope-v1",
    { author: true, import: false, preserve: false, deploy: true, constraints: [] },
    { author: true, import: false, preserve: false, deploy: true, constraints: [] },
  ),

  "profile.repository": entry(V21_VERSIONS, "profile.repository"),
  "profile.repository.roots": entry(
    V21_VERSIONS,
    "profile.repository",
    full(ROOT_MAX_ONE),
    full(ROOT_MAX_ONE),
  ),
  "profile.repository.block_outside_writes": entry(V21_VERSIONS, "profile.repository"),
  "profile.repository.protect_git_history": entry(V21_VERSIONS, "profile.repository"),
  "profile.repository.protect_sensitive_files": entry(V21_VERSIONS, "profile.repository"),
  "profile.repository.git_providers": entry(
    V21_VERSIONS,
    "profile.repository",
    full(REPOSITORY_PROVIDERS),
    full(REPOSITORY_PROVIDERS),
  ),
  "profile.repository.require_shim": entry(V21_VERSIONS, "profile.repository"),

  "profile.filesystem": entry(V21_VERSIONS, "profile.filesystem", unsupported(), unsupported()),
  "profile.filesystem.actions": entry(V21_VERSIONS, "profile.filesystem", unsupported(), unsupported()),
  "profile.filesystem.write_roots": entry(V21_VERSIONS, "profile.filesystem", unsupported(), unsupported()),
  "profile.filesystem.read_roots": entry(V21_VERSIONS, "profile.filesystem", unsupported(), unsupported()),
  "profile.filesystem.allowed_effects": entry(V21_VERSIONS, "profile.filesystem", unsupported(), unsupported()),
  "profile.filesystem.blocked_paths": entry(V21_VERSIONS, "profile.filesystem", unsupported(), unsupported()),
  "profile.filesystem.protected_file_classes": entry(V21_VERSIONS, "profile.filesystem", unsupported(), unsupported()),
  "profile.filesystem.protected_class_catalog": entry(V21_VERSIONS, "profile.filesystem", unsupported(), unsupported()),
  "profile.filesystem.protected_effects": entry(V21_VERSIONS, "profile.filesystem", unsupported(), unsupported()),
  "profile.filesystem.max_files_per_action": entry(V21_VERSIONS, "profile.filesystem", unsupported(), unsupported()),
  "profile.filesystem.max_bytes_written_per_task": entry(V21_VERSIONS, "profile.filesystem", unsupported(), unsupported()),
  "profile.filesystem.max_bytes_deleted_per_task": entry(V21_VERSIONS, "profile.filesystem", unsupported(), unsupported()),
  "profile.filesystem.max_destructive_effects_per_task": entry(V21_VERSIONS, "profile.filesystem", unsupported(), unsupported()),
  "profile.filesystem.require_shim": entry(V21_VERSIONS, "profile.filesystem", unsupported(), unsupported()),

  "profile.git": entry(V21_VERSIONS, "profile.git", unsupported(), full()),
  "profile.git.actions": entry(V21_VERSIONS, "profile.git", unsupported(), full()),
  "profile.git.filesystem_actions": entry(V21_VERSIONS, "profile.git", unsupported(), full()),
  "profile.git.providers": entry(V21_VERSIONS, "profile.git", unsupported(), full(REPOSITORY_PROVIDERS)),
  "profile.git.allowed_remote_schemes": entry(V21_VERSIONS, "profile.git", unsupported(), full()),
  "profile.git.allowed_operations": entry(V21_VERSIONS, "profile.git", unsupported(), full()),
  "profile.git.require_approval": entry(V21_VERSIONS, "profile.git", unsupported(), full()),
  "profile.git.blocked_operations": entry(V21_VERSIONS, "profile.git", unsupported(), full()),
  "profile.git.protected_refs": entry(V21_VERSIONS, "profile.git", unsupported(), full()),
  "profile.git.max_ref_changes_per_task": entry(V21_VERSIONS, "profile.git", unsupported(), full()),
  "profile.git.require_shim": entry(V21_VERSIONS, "profile.git", unsupported(), full()),

  "profile.database": entry(V21_VERSIONS, "profile.database", unsupported(), full()),
  "profile.database.actions": entry(V21_VERSIONS, "profile.database", unsupported(), full()),
  "profile.database.protected_environments": entry(V21_VERSIONS, "profile.database", unsupported(), full()),
  "profile.database.allowed_operations": entry(V21_VERSIONS, "profile.database", unsupported(), full()),
  "profile.database.require_approval": entry(V21_VERSIONS, "profile.database", unsupported(), full()),
  "profile.database.allowed_resources": entry(V21_VERSIONS, "profile.database", unsupported(), full()),
  "profile.database.routine_catalog": entry(V21_VERSIONS, "profile.database", unsupported(), full()),
  "profile.database.require_read_only_for_select": entry(V21_VERSIONS, "profile.database", unsupported(), full()),
  "profile.database.deny_unreviewed_indirect_effects": entry(V21_VERSIONS, "profile.database", unsupported(), full()),
  "profile.database.max_schema_changes_per_task": entry(V21_VERSIONS, "profile.database", unsupported(), full()),
  "profile.database.statement_timeout_ms": entry(V21_VERSIONS, "profile.database", unsupported(), full()),
  "profile.database.lock_timeout_ms": entry(V21_VERSIONS, "profile.database", unsupported(), full()),
  "profile.database.require_shim": entry(V21_VERSIONS, "profile.database", unsupported(), full()),

  "evm.max_transaction_eth": entry(ALL_VERSIONS, "evm"),
  "evm.allowed_actions": entry(ALL_VERSIONS, "evm"),
  "evm.allowed_chains": entry(ALL_VERSIONS, "evm", full(), full(BUILDER_CHAINS)),
  "evm.chain_actions": entry(ALL_VERSIONS, "evm.chain_actions", preserveOnly(), full()),
  "evm.token.*.max_transaction": entry(ALL_VERSIONS, "evm.token"),
  "evm.token.*.decimals": entry(ALL_VERSIONS, "evm.token"),
  "evm.token.*.addresses": entry(ALL_VERSIONS, "evm.token"),
  "evm.token.*.consensus_threshold": entry(
    ALL_VERSIONS,
    "evm.token.consensus_threshold",
    unsupported(),
    unsupported(),
  ),
  "evm.consensus_threshold_eth": entry(ALL_VERSIONS, "evm"),
  "evm.consensus_require_hold": entry(ALL_VERSIONS, "evm"),
  "evm.require_approval": entry(V2_VERSIONS, "evm"),
  "evm.require_shim": entry(V2_VERSIONS, "evm"),
  "evm.require_calldata_enrichment": entry(
    V21_VERSIONS,
    "evm.require_calldata_enrichment",
    unsupported(),
    unsupported(),
  ),
  "evm.calldata_unknown_selector": entry(
    V21_VERSIONS,
    "evm.calldata_unknown_selector",
    unsupported(),
    unsupported(),
  ),

  "tool_calls.allowed": entry(ALL_VERSIONS, "tool_calls"),
  "tool_calls.bash.blocked_commands": entry(ALL_VERSIONS, "tool_calls"),
  "tool_calls.web_fetch.blocked_domains": entry(ALL_VERSIONS, "tool_calls"),
  "tool_calls.file_write.blocked_paths": entry(ALL_VERSIONS, "tool_calls"),
  "tool_calls.email.require_approval": entry(ALL_VERSIONS, "tool_calls"),
  "tool_calls.email.allowed_recipients": entry(ALL_VERSIONS, "tool_calls"),
  "tool_calls.email.blocked_recipients": entry(ALL_VERSIONS, "tool_calls"),
  "tool_calls.http.allowed_methods": entry(V2_VERSIONS, "tool_calls.http"),
  "tool_calls.http.blocked_methods": entry(V2_VERSIONS, "tool_calls.http"),
  "tool_calls.http.allowed_hosts": entry(V2_VERSIONS, "tool_calls.http"),
  "tool_calls.require_approval": entry(V2_VERSIONS, "tool_calls"),
  "tool_calls.require_shim": entry(V2_VERSIONS, "tool_calls"),
  "tool_calls.http.method_rules": entry(
    V21_VERSIONS,
    "tool_calls.http.method_rules",
    unsupported(),
    unsupported(),
  ),
  "tool_calls.http.method_rules.*.require_query_matches": entry(
    V21_VERSIONS,
    "tool_calls.http.method_rules",
    unsupported(),
    unsupported(),
  ),
  "tool_calls.http.method_rules.*.deny": entry(
    V21_VERSIONS,
    "tool_calls.http.method_rules",
    unsupported(),
    unsupported(),
  ),

  "mcp.allowed_servers": entry(V2_VERSIONS, "mcp"),
  "mcp.allowed_tools": entry(V2_VERSIONS, "mcp"),
  "mcp.blocked_tools": entry(V2_VERSIONS, "mcp"),
  "mcp.require_approval": entry(V2_VERSIONS, "mcp"),
  "mcp.require_shim": entry(V2_VERSIONS, "mcp"),

  "custom.allow_only": entry(ALL_VERSIONS, "custom"),
  "custom.deny_if": entry(ALL_VERSIONS, "custom"),
  "custom.deny_string": entry(ALL_VERSIONS, "custom"),
  "custom.require_approval": entry(V2_VERSIONS, "custom"),
  "custom.require_shim": entry(V2_VERSIONS, "custom"),

  "soft_limits.daily_evm_limit_eth": entry(ALL_VERSIONS, "soft_limits"),
  "soft_limits.daily_tool_calls": entry(ALL_VERSIONS, "soft_limits"),
  "soft_limits.cap.*.max_count": entry(V2_VERSIONS, "soft_limits.cap"),
  "soft_limits.cap.*.max_sum_usd": entry(V2_VERSIONS, "soft_limits.cap"),
  "soft_limits.cap.*.window": entry(V2_VERSIONS, "soft_limits.cap"),
  "soft_limits.cap.*.action": entry(V2_VERSIONS, "soft_limits.cap"),
  "soft_limits.cap.*.group_by": entry(V2_VERSIONS, "soft_limits.cap"),
  "soft_limits.cap.*.amount_field": entry(V2_VERSIONS, "soft_limits.cap"),
  "soft_limits.require_approval": entry(V2_VERSIONS, "soft_limits"),
  "soft_limits.require_shim": entry(V2_VERSIONS, "soft_limits"),

  "execution_limits.max_tool_calls_per_task": entry(ALL_VERSIONS, "execution_limits"),
  "execution_limits.max_tool_calls_per_hour": entry(ALL_VERSIONS, "execution_limits"),
  "execution_limits.max_model_spend_usd_per_task": entry(ALL_VERSIONS, "execution_limits"),
  "execution_limits.max_model_tokens_per_task": entry(ALL_VERSIONS, "execution_limits"),
  "execution_limits.require_approval": entry(V2_VERSIONS, "execution_limits.require_approval"),
  "execution_limits.require_shim": entry(V2_VERSIONS, "execution_limits.require_shim"),
} as const satisfies Readonly<Record<string, AuthoringCapabilityEntry>>;

export const AUTHORING_CAPABILITY_MANIFEST = manifest;
export type AuthoringCapabilityPath = keyof typeof AUTHORING_CAPABILITY_MANIFEST;

export const DEPLOY_FEATURE_PATHS = Object.fromEntries(
  DEPLOY_FEATURE_KEYS.map((featureKey) => [
    featureKey,
    (Object.keys(AUTHORING_CAPABILITY_MANIFEST) as AuthoringCapabilityPath[])
      .filter(
        (path) =>
          AUTHORING_CAPABILITY_MANIFEST[path].deploy_feature_key === featureKey,
      )
      .sort(),
  ]),
) as unknown as Readonly<Record<DeployFeatureKey, readonly AuthoringCapabilityPath[]>>;

/** Exact forward mapping for the Sign registry. */
export const SIGN_CAPABILITY_DEPLOY_PATHS = DEPLOY_FEATURE_PATHS;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const outputKeyByPath: Readonly<Record<string, string>> = {
  "profile.repository": "repository",
  "profile.filesystem": "filesystem",
  "profile.git": "git",
  "profile.database": "database",
  "profile.repository.block_outside_writes": "repository.blockOutsideWrites",
  "profile.repository.protect_git_history": "repository.protectGitHistory",
  "profile.repository.protect_sensitive_files": "repository.protectSensitiveFiles",
  "profile.repository.git_providers": "repository.gitProviders",
  "profile.repository.require_shim": "repository.requireShim",
  "profile.filesystem.write_roots": "filesystem.writeRoots",
  "profile.filesystem.read_roots": "filesystem.readRoots",
  "profile.filesystem.allowed_effects": "filesystem.allowedEffects",
  "profile.filesystem.blocked_paths": "filesystem.blockedPaths",
  "profile.filesystem.protected_file_classes": "filesystem.protectedFileClasses",
  "profile.filesystem.protected_class_catalog": "filesystem.protectedClassCatalog",
  "profile.filesystem.protected_effects": "filesystem.protectedEffects",
  "profile.filesystem.max_files_per_action": "filesystem.maxFilesPerAction",
  "profile.filesystem.max_bytes_written_per_task": "filesystem.maxBytesWrittenPerTask",
  "profile.filesystem.max_bytes_deleted_per_task": "filesystem.maxBytesDeletedPerTask",
  "profile.filesystem.max_destructive_effects_per_task": "filesystem.maxDestructiveEffectsPerTask",
  "profile.filesystem.require_shim": "filesystem.requireShim",
  "profile.git.filesystem_actions": "git.filesystemActions",
  "profile.git.allowed_remote_schemes": "git.allowedRemoteSchemes",
  "profile.git.allowed_operations": "git.allowedOperations",
  "profile.git.require_approval": "git.requireApproval",
  "profile.git.blocked_operations": "git.blockedOperations",
  "profile.git.protected_refs": "git.protectedRefs",
  "profile.git.max_ref_changes_per_task": "git.maxRefChangesPerTask",
  "profile.git.require_shim": "git.requireShim",
  "profile.database.protected_environments": "database.protectedEnvironments",
  "profile.database.allowed_operations": "database.allowedOperations",
  "profile.database.require_approval": "database.requireApproval",
  "profile.database.allowed_resources": "database.allowedResources",
  "profile.database.routine_catalog": "database.routineCatalog",
  "profile.database.require_read_only_for_select": "database.requireReadOnlyForSelect",
  "profile.database.deny_unreviewed_indirect_effects": "database.denyUnreviewedIndirectEffects",
  "profile.database.max_schema_changes_per_task": "database.maxSchemaChangesPerTask",
  "profile.database.statement_timeout_ms": "database.statementTimeoutMs",
  "profile.database.lock_timeout_ms": "database.lockTimeoutMs",
  "profile.database.require_shim": "database.requireShim",
  "evm.max_transaction_eth": "evm.maxTransactionEth",
  "evm.allowed_actions": "evm.allowedActions",
  "evm.allowed_chains": "evm.allowedChains",
  "evm.chain_actions": "evm.chainActions",
  "evm.consensus_threshold_eth": "evm.consensusThresholdEth",
  "evm.consensus_require_hold": "evm.requireHold",
  "evm.require_approval": "evm.requireApproval",
  "evm.require_shim": "evm.requireShim",
  "evm.require_calldata_enrichment": "evm.requireCalldataEnrichment",
  "evm.calldata_unknown_selector": "evm.calldataUnknownSelector",
  "tool_calls.allowed": "tool_calls.allowed",
  "tool_calls.bash.blocked_commands": "tool_calls.bashBlockedCommands",
  "tool_calls.web_fetch.blocked_domains": "tool_calls.webFetchBlockedDomains",
  "tool_calls.file_write.blocked_paths": "tool_calls.fileWriteBlockedPaths",
  "tool_calls.email.require_approval": "tool_calls.emailRequireApproval",
  "tool_calls.email.allowed_recipients": "tool_calls.emailAllowedRecipients",
  "tool_calls.email.blocked_recipients": "tool_calls.emailBlockedRecipients",
  "tool_calls.http.allowed_methods": "tool_calls.httpAllowedMethods",
  "tool_calls.http.blocked_methods": "tool_calls.httpBlockedMethods",
  "tool_calls.http.allowed_hosts": "tool_calls.httpAllowedHosts",
  "tool_calls.require_approval": "tool_calls.requireApproval",
  "tool_calls.require_shim": "tool_calls.requireShim",
  "tool_calls.http.method_rules": "tool_calls.httpMethodRules",
  "mcp.allowed_servers": "mcp.allowedServers",
  "mcp.allowed_tools": "mcp.allowedTools",
  "mcp.blocked_tools": "mcp.blockedTools",
  "mcp.require_approval": "mcp.requireApproval",
  "mcp.require_shim": "mcp.requireShim",
  "custom.require_approval": "custom.requireApproval",
  "custom.require_shim": "custom.requireShim",
  "soft_limits.daily_evm_limit_eth": "soft_limits.dailyEvmLimitEth",
  "soft_limits.daily_tool_calls": "soft_limits.dailyToolCalls",
  "soft_limits.require_approval": "soft_limits.requireApproval",
  "soft_limits.require_shim": "soft_limits.requireShim",
  "execution_limits.max_tool_calls_per_task": "execution_limits.maxToolCallsPerTask",
  "execution_limits.max_tool_calls_per_hour": "execution_limits.maxToolCallsPerHour",
  "execution_limits.max_model_spend_usd_per_task": "execution_limits.maxModelSpendUsdPerTask",
  "execution_limits.max_model_tokens_per_task": "execution_limits.maxModelTokensPerTask",
  "execution_limits.require_approval": "execution_limits.requireApproval",
  "execution_limits.require_shim": "execution_limits.requireShim",
};

const camelCaseDirective = (value: string): string =>
  value.replace(/_([a-z])/g, (_match, letter: string) => letter.toUpperCase());

// skipcq: JS-R1005 - The ordered path fallbacks form the public capability-path compatibility mapping.
const outputPathForCanonicalPath = (path: string): string => {
  const explicit = outputKeyByPath[path];
  if (explicit !== undefined) return explicit;
  const profile = path.match(/^profile\.(repository|filesystem|git|database)\.(.+)$/);
  if (profile?.[1] !== undefined && profile[2] !== undefined) {
    return `${profile[1]}.${camelCaseDirective(profile[2])}`;
  }
  const section = path.match(/^([a-z_]+)\.(.+)$/);
  if (section?.[1] !== undefined && section[2] !== undefined) {
    return `${section[1]}.${camelCaseDirective(section[2])}`;
  }
  return path;
};

const directValue = (policy: ParsedPolicy, outputPath: string): unknown => {
  let value: unknown = policy;
  for (const segment of outputPath.split(".")) {
    if (!isRecord(value) || !(segment in value)) return undefined;
    value = value[segment];
  }
  return value;
};

// skipcq: JS-R1005 - Wildcard paths require separate stable extraction rules for each policy family.
const dynamicValues = (policy: ParsedPolicy, path: string): unknown[] => {
  if (path.startsWith("evm.token.*.")) {
    const field = path.slice("evm.token.*.".length);
    const outputField: Readonly<Record<string, string>> = {
      max_transaction: "maxTransaction",
      consensus_threshold: "consensusThreshold",
      decimals: "decimals",
      addresses: "addresses",
    };
    const tokenRules = directValue(policy, "evm.tokenRules");
    if (!isRecord(tokenRules)) return [];
    return Object.values(tokenRules)
      .filter(isRecord)
      .map((token) => token[outputField[field] ?? field])
      .filter((value) => value !== undefined);
  }
  if (path.startsWith("tool_calls.http.method_rules.*.")) {
    const field = path.endsWith(".deny") ? "deny" : "requireQueryMatches";
    const rules = directValue(policy, "tool_calls.httpMethodRules");
    if (!isRecord(rules)) return [];
    return Object.values(rules)
      .filter(isRecord)
      .map((rule) => rule[field])
      .filter((value) => value !== undefined);
  }
  if (path.startsWith("soft_limits.cap.*.")) {
    const field = path.slice("soft_limits.cap.*.".length);
    const outputField: Readonly<Record<string, string>> = {
      max_count: "maxCount",
      max_sum_usd: "maxSumUsd",
      window: "window",
      action: "action",
      group_by: "groupBy",
      amount_field: "amountField",
    };
    const caps = directValue(policy, "soft_limits.caps");
    if (!isRecord(caps)) return [];
    return Object.values(caps)
      .filter(isRecord)
      .map((cap) => cap[outputField[field] ?? field])
      .filter((value) => value !== undefined);
  }
  return [];
};

// skipcq: JS-R1005 - This dispatch is the auditable mapping from capability paths to parsed policy values.
export const capabilityValuesForPath = (
  policy: ParsedPolicy,
  path: AuthoringCapabilityPath,
): readonly unknown[] => {
  if (path.startsWith("profile.")) {
    const profile = path.slice("profile.".length);
    if (profile === "repository" || profile === "filesystem" || profile === "git" || profile === "database") {
      const value = policy[profile];
      return value === undefined ? [] : [value];
    }
  }
  if (path.includes("*")) return dynamicValues(policy, path);
  if (path === "policy.version") return [policy.version];
  if (path === "custom.allow_only") {
    return policy.custom?.rules.filter((rule) => rule.type === "allow_field") ?? [];
  }
  if (path === "custom.deny_if") {
    return policy.custom?.rules.filter((rule) => rule.type === "field") ?? [];
  }
  if (path === "custom.deny_string") {
    return policy.custom?.rules.filter((rule) => rule.type === "deny_string") ?? [];
  }
  const value = directValue(policy, outputPathForCanonicalPath(path));
  return value === undefined ? [] : [value];
};

// skipcq: JS-R1005 - Explicit version branches retain the supported Policy version contract in one place.
export const policyVersionRange = (version: string): PolicyVersionRange | undefined => {
  const match = version.match(/^(\d+)\.(\d+)\.\d+$/);
  if (!match) return undefined;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  if (major === 0) return "0.x";
  if (major === 1) return "1.x";
  if (major === 2 && minor === 0) return "2.0.x";
  if (major === 2 && minor === 1) return "2.1.x";
  return undefined;
};

export const isCapabilityAvailable = (
  path: AuthoringCapabilityPath,
  surface: AuthoringSurface,
  dimension: CapabilityDimension,
  version: string,
): boolean => {
  const capability = AUTHORING_CAPABILITY_MANIFEST[path];
  const range = policyVersionRange(version);
  return range !== undefined
    && capability.versions.includes(range)
    && capability.surfaces[surface][dimension];
};

const constraintValues = (value: unknown): readonly unknown[] =>
  Array.isArray(value) ? value : [value];

// skipcq: JS-R1005 - Constraint-kind branches produce the precise surface diagnostics promised to authors.
export const runRepresentabilityConstraints = (
  path: AuthoringCapabilityPath,
  surface: AuthoringSurface,
  value: unknown,
): readonly ConstraintViolation[] => {
  const constraints = AUTHORING_CAPABILITY_MANIFEST[path].surfaces[surface].constraints;
  const violations: ConstraintViolation[] = [];
  for (const constraint of constraints) {
    if (constraint.kind === "max-items") {
      const count = Array.isArray(value) ? value.length : value === undefined ? 0 : 1;
      if (count > constraint.max) {
        violations.push({
          constraint_id: constraint.id,
          path,
          message: `${path} supports at most ${constraint.max} item${constraint.max === 1 ? "" : "s"} on ${surface}`,
        });
      }
    } else if (constraint.kind === "allowed-values") {
      const unsupportedValues = constraintValues(value).filter(
        (candidate) => !constraint.values.includes(candidate as string | number),
      );
      if (unsupportedValues.length > 0) {
        violations.push({
          constraint_id: constraint.id,
          path,
          message: `${path} contains values ${unsupportedValues.map(String).join(", ")} that ${surface} cannot represent`,
        });
      }
    } else if (value !== constraint.value) {
      violations.push({
        constraint_id: constraint.id,
        path,
        message: `${path} must equal ${String(constraint.value)} on ${surface}`,
      });
    }
  }
  return violations;
};

const stableJson = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
};

const PARSER_CONTRACT_TABLES = {
  schema_version: 1,
  supported_policy_versions: POLICY_VERSION_RANGES,
  policy_sections: [
    "evm",
    "tool_calls",
    "custom",
    "mcp",
    "soft_limits",
    "execution_limits",
    "repository",
    "filesystem",
    "git",
    "database",
  ],
  http_methods: ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
  filesystem_effects: [
    "read",
    "create",
    "overwrite",
    "append",
    "truncate",
    "delete",
    "rename",
    "copy",
    "hard_link",
    "symlink",
    "chmod",
    "chown",
    "xattr",
    "execute",
    "egress",
  ],
  git_providers: ["generic", "github", "gitlab", "bitbucket"],
  database_operations: [
    "select",
    "insert",
    "update",
    "merge",
    "delete",
    "truncate",
    "create_table",
    "drop_table",
    "add_column",
    "drop_column",
    "alter_column_type",
    "add_constraint",
    "drop_constraint",
    "create_index",
    "drop_index",
    "create_schema",
    "drop_schema",
    "create_database",
    "alter_database",
    "drop_database",
    "create_routine",
    "replace_routine",
    "execute_routine",
    "change_trigger",
    "change_row_security",
    "grant",
    "revoke",
    "create_extension",
  ],
  field_paths: Object.keys(AUTHORING_CAPABILITY_MANIFEST).sort(),
};

export const PARSER_CONTRACT_DIGEST_INPUT = stableJson(PARSER_CONTRACT_TABLES);
export const PARSER_CONTRACT_DIGEST_ALGORITHM = "sha256" as const;
export const PARSER_CONTRACT_DIGEST =
  "sha256:075e7cf5a02941f2c96565c324b56ae1a75b16b395c004dfd54882f13e0cb4be" as const;

export const deployFeatureKeysForPolicy = (policy: ParsedPolicy): readonly DeployFeatureKey[] => {
  const keys = new Set<DeployFeatureKey>();
  for (const path of Object.keys(AUTHORING_CAPABILITY_MANIFEST) as AuthoringCapabilityPath[]) {
    const entryValue = AUTHORING_CAPABILITY_MANIFEST[path];
    if (
      capabilityValuesForPath(policy, path).length > 0
    ) {
      keys.add(entryValue.deploy_feature_key);
    }
  }
  return DEPLOY_FEATURE_KEYS.filter((key) => keys.has(key));
};
