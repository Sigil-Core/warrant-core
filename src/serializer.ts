import type { ParsedPolicy } from "./types.js";

type RecordValue = Record<string, unknown>;

const isRecord = (value: unknown): value is RecordValue =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const csv = (value: unknown, path: string): string => {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" && typeof item !== "number")) {
    throw new TypeError(`${path} must be a string or number array`);
  }
  return value.join(", ");
};

const scalar = (value: unknown, path: string): string => {
  if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") {
    throw new TypeError(`${path} must be a string, number, or boolean`);
  }
  return String(value);
};

const customScalar = (value: unknown, path: string): string => {
  const serialized = scalar(value, path);
  return typeof value === "string" && value.trim() !== value
    ? `"${serialized}"`
    : serialized;
};

const customCsv = (value: unknown, path: string): string => {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" && typeof item !== "number")) {
    throw new TypeError(`${path} must be a string or number array`);
  }
  return value.map((item) => customScalar(item, path)).join(", ");
};

const add = (lines: string[], key: string, value: unknown, path: string, array = false): void => {
  if (value === undefined) return;
  lines.push(`${key}: ${array ? csv(value, path) : scalar(value, path)}`);
};

const genericControls = (lines: string[], value: RecordValue, path: string): void => {
  add(lines, "require_approval", value.requireApproval, `${path}.requireApproval`, true);
  add(lines, "require_shim", value.requireShim, `${path}.requireShim`);
};

const resourceKeys: Readonly<Record<string, readonly [string, string, boolean][]>> = {
  repository: [
    ["roots", "roots", true], ["block_outside_writes", "blockOutsideWrites", false],
    ["protect_git_history", "protectGitHistory", false], ["protect_sensitive_files", "protectSensitiveFiles", false],
    ["git_providers", "gitProviders", true], ["require_shim", "requireShim", false],
  ],
  filesystem: [
    ["actions", "actions", true], ["write_roots", "writeRoots", true], ["read_roots", "readRoots", true],
    ["allowed_effects", "allowedEffects", true], ["blocked_paths", "blockedPaths", true],
    ["protected_file_classes", "protectedFileClasses", true], ["protected_class_catalog", "protectedClassCatalog", false],
    ["protected_effects", "protectedEffects", true], ["max_files_per_action", "maxFilesPerAction", false],
    ["max_bytes_written_per_task", "maxBytesWrittenPerTask", false], ["max_bytes_deleted_per_task", "maxBytesDeletedPerTask", false],
    ["max_destructive_effects_per_task", "maxDestructiveEffectsPerTask", false], ["require_shim", "requireShim", false],
  ],
  git: [
    ["actions", "actions", true], ["filesystem_actions", "filesystemActions", true], ["providers", "providers", true],
    ["allowed_remote_schemes", "allowedRemoteSchemes", true], ["allowed_operations", "allowedOperations", true],
    ["require_approval", "requireApproval", true], ["blocked_operations", "blockedOperations", true],
    ["protected_refs", "protectedRefs", true], ["max_ref_changes_per_task", "maxRefChangesPerTask", false], ["require_shim", "requireShim", false],
  ],
  database: [
    ["actions", "actions", true], ["protected_environments", "protectedEnvironments", true], ["allowed_operations", "allowedOperations", true],
    ["require_approval", "requireApproval", true], ["allowed_resources", "allowedResources", true], ["routine_catalog", "routineCatalog", false],
    ["require_read_only_for_select", "requireReadOnlyForSelect", false], ["deny_unreviewed_indirect_effects", "denyUnreviewedIndirectEffects", false],
    ["max_schema_changes_per_task", "maxSchemaChangesPerTask", false], ["statement_timeout_ms", "statementTimeoutMs", false],
    ["lock_timeout_ms", "lockTimeoutMs", false], ["require_shim", "requireShim", false],
  ],
};

// skipcq: JS-R1005 - Empty and malformed resource handling must preserve canonical section emission.
const resourceSection = (name: string, value: unknown): string | undefined => {
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw new TypeError(`${name} must be an object`);
  const lines: string[] = [];
  for (const [directive, property, array] of resourceKeys[name] ?? []) {
    add(lines, directive, value[property], `${name}.${property}`, array);
  }
  return lines.length ? `## ${name}\n${lines.join("\n")}` : `## ${name}`;
};

// skipcq: JS-R1005 - Canonical EVM directive order is security-sensitive and verified as one emission routine.
const evmSection = (value: unknown): string | undefined => {
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw new TypeError("evm must be an object");
  const lines: string[] = [];
  add(lines, "max_transaction_eth", value.maxTransactionEth, "evm.maxTransactionEth");
  add(lines, "allowed_actions", value.allowedActions, "evm.allowedActions", true);
  add(lines, "allowed_chains", value.allowedChains, "evm.allowedChains", true);
  if (isRecord(value.chainActions)) {
    lines.push("chain_actions:");
    for (const chainId of Object.keys(value.chainActions).sort((a, b) => Number(a) - Number(b))) {
      lines.push(`  "${chainId}": ${csv(value.chainActions[chainId], `evm.chainActions.${chainId}`)}`);
    }
  }
  add(lines, "consensus_threshold_eth", value.consensusThresholdEth, "evm.consensusThresholdEth");
  add(lines, "consensus_require_hold", value.requireHold, "evm.requireHold");
  add(lines, "require_calldata_enrichment", value.requireCalldataEnrichment, "evm.requireCalldataEnrichment");
  add(lines, "calldata_unknown_selector", value.calldataUnknownSelector, "evm.calldataUnknownSelector");
  if (isRecord(value.tokenRules)) {
    for (const symbol of Object.keys(value.tokenRules).sort()) {
      const token = value.tokenRules[symbol];
      if (!isRecord(token)) throw new TypeError(`evm.tokenRules.${symbol} must be an object`);
      add(lines, `token.${symbol}.max_transaction`, token.maxTransaction, `evm.tokenRules.${symbol}.maxTransaction`);
      add(lines, `token.${symbol}.decimals`, token.decimals, `evm.tokenRules.${symbol}.decimals`);
      add(lines, `token.${symbol}.consensus_threshold`, token.consensusThreshold, `evm.tokenRules.${symbol}.consensusThreshold`);
      add(lines, `token.${symbol}.addresses`, token.addresses, `evm.tokenRules.${symbol}.addresses`, true);
    }
  }
  genericControls(lines, value, "evm");
  return lines.length ? `## evm\n${lines.join("\n")}` : undefined;
};

// skipcq: JS-R1005 - Canonical tool-call directive order and method rules remain in one auditable serializer.
const toolCallsSection = (value: unknown): string | undefined => {
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw new TypeError("tool_calls must be an object");
  const lines: string[] = [];
  for (const [directive, property, array] of [
    ["allowed", "allowed", true], ["bash.blocked_commands", "bashBlockedCommands", true],
    ["web_fetch.blocked_domains", "webFetchBlockedDomains", true], ["file_write.blocked_paths", "fileWriteBlockedPaths", true],
    ["email.require_approval", "emailRequireApproval", false], ["email.allowed_recipients", "emailAllowedRecipients", true],
    ["email.blocked_recipients", "emailBlockedRecipients", true], ["http.allowed_methods", "httpAllowedMethods", true],
    ["http.allowed_hosts", "httpAllowedHosts", true], ["http.blocked_methods", "httpBlockedMethods", true],
  ] as const) add(lines, directive, value[property], `tool_calls.${property}`, array);
  if (isRecord(value.httpMethodRules)) {
    for (const method of Object.keys(value.httpMethodRules).sort()) {
      const rule = value.httpMethodRules[method];
      if (!isRecord(rule)) throw new TypeError(`tool_calls.httpMethodRules.${method} must be an object`);
      add(lines, `http.method_rules.${method}.require_query_matches`, rule.requireQueryMatches, `tool_calls.httpMethodRules.${method}.requireQueryMatches`);
      add(lines, `http.method_rules.${method}.deny`, rule.deny, `tool_calls.httpMethodRules.${method}.deny`);
    }
  }
  genericControls(lines, value, "tool_calls");
  return lines.length ? `## tool_calls\n${lines.join("\n")}` : undefined;
};

const serializeSimpleSection = (name: string, value: unknown, keys: readonly [string, string, boolean][]): string | undefined => {
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw new TypeError(`${name} must be an object`);
  const lines: string[] = [];
  for (const [directive, property, array] of keys) add(lines, directive, value[property], `${name}.${property}`, array);
  genericControls(lines, value, name);
  return lines.length ? `## ${name}\n${lines.join("\n")}` : undefined;
};

// skipcq: JS-R1005 - Named-cap emission order and validation stay together for lossless canonical output.
const softLimitsSection = (value: unknown): string | undefined => {
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw new TypeError("soft_limits must be an object");
  const lines: string[] = [];
  add(lines, "daily_evm_limit_eth", value.dailyEvmLimitEth, "soft_limits.dailyEvmLimitEth");
  add(lines, "daily_tool_calls", value.dailyToolCalls, "soft_limits.dailyToolCalls");
  if (isRecord(value.caps)) {
    for (const name of Object.keys(value.caps).sort()) {
      const cap = value.caps[name];
      if (!isRecord(cap)) throw new TypeError(`soft_limits.caps.${name} must be an object`);
      add(lines, `cap.${name}.max_count`, cap.maxCount, `soft_limits.caps.${name}.maxCount`);
      add(lines, `cap.${name}.max_sum_usd`, cap.maxSumUsd, `soft_limits.caps.${name}.maxSumUsd`);
      add(lines, `cap.${name}.window`, cap.window, `soft_limits.caps.${name}.window`);
      add(lines, `cap.${name}.action`, cap.action, `soft_limits.caps.${name}.action`);
      add(lines, `cap.${name}.group_by`, cap.groupBy, `soft_limits.caps.${name}.groupBy`);
      add(lines, `cap.${name}.amount_field`, cap.amountField, `soft_limits.caps.${name}.amountField`);
    }
  }
  genericControls(lines, value, "soft_limits");
  return lines.length ? `## soft_limits\n${lines.join("\n")}` : undefined;
};

// skipcq: JS-R1005 - Custom-rule variants have distinct wire syntax and remain in one canonical emitter.
const customSection = (value: unknown): string | undefined => {
  if (value === undefined) return undefined;
  if (!isRecord(value) || !Array.isArray(value.rules)) throw new TypeError("custom.rules must be an array");
  const lines: string[] = [];
  for (const rule of value.rules) {
    if (!isRecord(rule) || typeof rule.type !== "string") throw new TypeError("custom rule must be an object with a type");
    if (rule.type === "allow_field") {
      const action = typeof rule.actionScope === "string" ? `[action=${rule.actionScope}]` : "";
      const attested = rule.attested === true ? " attested" : "";
      const operator = typeof rule.operator === "string" ? ` ${rule.operator}` : "";
      lines.push(`allow_only${action}.${scalar(rule.fieldPath, "custom.fieldPath")}${attested}${operator}: ${customCsv(rule.values, "custom.values")}`);
    } else if (rule.type === "field") {
      lines.push(`deny_if.${scalar(rule.fieldPath, "custom.fieldPath")} ${scalar(rule.operator, "custom.operator")} ${customScalar(rule.value, "custom.value")}`);
    } else if (rule.type === "deny_string") {
      lines.push(`deny_string: ${customScalar(rule.value, "custom.value")}`);
    } else throw new TypeError(`Unsupported custom rule type ${rule.type}`);
  }
  genericControls(lines, value, "custom");
  return lines.length ? `## custom\n${lines.join("\n")}` : undefined;
};

/** Canonical policy emission used for page cutover in later phases. */
export const serializePolicyMarkdown = (policy: ParsedPolicy): string => {
  if (typeof policy.version !== "string" || !/^\d+\.\d+\.\d+$/.test(policy.version)) {
    throw new TypeError("policy.version must be semver X.Y.Z");
  }
  const sections = [
    resourceSection("repository", policy.repository), resourceSection("filesystem", policy.filesystem),
    resourceSection("git", policy.git), resourceSection("database", policy.database), evmSection(policy.evm),
    toolCallsSection(policy.tool_calls), customSection(policy.custom),
    serializeSimpleSection("mcp", policy.mcp, [["allowed_servers", "allowedServers", true], ["allowed_tools", "allowedTools", true], ["blocked_tools", "blockedTools", true]]),
    softLimitsSection(policy.soft_limits),
    serializeSimpleSection("execution_limits", policy.execution_limits, [["max_tool_calls_per_task", "maxToolCallsPerTask", false], ["max_tool_calls_per_hour", "maxToolCallsPerHour", false], ["max_model_spend_usd_per_task", "maxModelSpendUsdPerTask", false], ["max_model_tokens_per_task", "maxModelTokensPerTask", false]]),
  ].filter((section): section is string => section !== undefined);
  return [`version: ${policy.version}`, ...sections].join("\n\n");
};
