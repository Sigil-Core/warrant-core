import type { ParsedPolicy } from "./types.js";
import { maskHtmlComments } from "./html-comments.js";
import { splitSignatureBlock } from "./signature.js";

const HTTP_METHODS = new Set(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]);
const V2_ONLY = /^(?:\s*allow_only(?:\[action=[^\]]+\])?\.[^\s:]+\s+(?:attested\s+)?(?:contains|starts_with|prefix|ends_with|matches|equals)\s*:|\s*http\.(?:allowed_methods|allowed_hosts|blocked_methods):|\s*cap\.[A-Za-z0-9_-]+\.)/m;
const KNOWN_SECTIONS = new Set(["evm", "tool_calls", "custom", "mcp", "soft_limits", "execution_limits", "repository", "filesystem", "git", "database"]);
const RESOURCE_SECTIONS = new Set(["repository", "filesystem", "git", "database"]);
const ACTION_PATTERN = (value: string) => Boolean(value) && (!value.includes("*") || (value.endsWith("*") && value.indexOf("*") === value.length - 1));
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const MAX_COUNTER_MICROS = 9_223_372_036_854_775_807n;
const RESERVED_PROFILE_NAMES = new Set(["__proto__", "constructor", "prototype"]);
const FILESYSTEM_EFFECTS = new Set(["read", "create", "overwrite", "append", "truncate", "delete", "rename", "copy", "hard_link", "symlink", "chmod", "chown", "xattr", "execute", "egress"]);
const GIT_OPERATIONS = new Set(["status", "diff", "log", "add", "commit", "fetch", "pull_ff_only", "push_fast_forward", "create_branch", "create_tag", "reset_hard", "clean", "rewrite_history", "delete_ref", "force_push", "mirror_push", "prune_remote", "change_remote", "change_protection", "change_credentials", "delete_repository"]);
const DATABASE_OPERATIONS = new Set(["select", "insert", "update", "merge", "delete", "truncate", "create_table", "drop_table", "add_column", "drop_column", "alter_column_type", "add_constraint", "drop_constraint", "create_index", "drop_index", "create_schema", "drop_schema", "create_database", "alter_database", "drop_database", "create_routine", "replace_routine", "execute_routine", "change_trigger", "change_row_security", "grant", "revoke", "create_extension"]);
const RESOURCE_ENUMS: Record<string, Set<string>> = {
  "repository.gitProviders": new Set(["generic", "github", "gitlab", "bitbucket"]),
  "filesystem.allowedEffects": FILESYSTEM_EFFECTS,
  "filesystem.protectedEffects": FILESYSTEM_EFFECTS,
  "git.providers": new Set(["generic", "github", "gitlab", "bitbucket"]),
  "git.allowedRemoteSchemes": new Set(["https", "ssh"]),
  "git.allowedOperations": GIT_OPERATIONS,
  "git.requireApproval": GIT_OPERATIONS,
  "git.blockedOperations": GIT_OPERATIONS,
  "database.allowedOperations": DATABASE_OPERATIONS,
  "database.requireApproval": DATABASE_OPERATIONS,
};
const RESOURCE_BOOLEAN_OUTPUT_KEYS = new Set(["requireShim", "blockOutsideWrites", "protectGitHistory", "protectSensitiveFiles", "requireReadOnlyForSelect", "denyUnreviewedIndirectEffects"]);
const RESOURCE_NUMERIC_OUTPUT_KEYS = new Set(["maxFilesPerAction", "maxBytesWrittenPerTask", "maxBytesDeletedPerTask", "maxDestructiveEffectsPerTask", "maxRefChangesPerTask", "maxSchemaChangesPerTask", "statementTimeoutMs", "lockTimeoutMs"]);
const RESOURCE_ACTION_OUTPUT_KEYS = new Set(["actions", "filesystemActions", "blockedPaths", "allowedResources", "protectedRefs"]);
const RESOURCE_ROOT_OUTPUT_KEYS = new Set(["roots", "writeRoots", "readRoots"]);
const RESOURCE_SCALAR_OUTPUT_KEYS = new Set(["routineCatalog", "protectedClassCatalog"]);
const SOFT_LIMIT_CAP_FIELDS = {
  max_count: "maxCount",
  max_sum_usd: "maxSumUsd",
  window: "window",
  action: "action",
  group_by: "groupBy",
  amount_field: "amountField",
} as const;

const RESOURCE_CONFIG: Record<string, { required: string[]; keys: Record<string, string> }> = {
  repository: {
    required: ["roots", "blockOutsideWrites", "protectGitHistory", "protectSensitiveFiles", "gitProviders", "requireShim"],
    keys: { roots: "roots", block_outside_writes: "blockOutsideWrites", protect_git_history: "protectGitHistory", protect_sensitive_files: "protectSensitiveFiles", git_providers: "gitProviders", require_shim: "requireShim" }
  },
  filesystem: {
    required: ["actions", "writeRoots", "readRoots", "allowedEffects", "requireShim"],
    keys: { actions: "actions", write_roots: "writeRoots", read_roots: "readRoots", allowed_effects: "allowedEffects", blocked_paths: "blockedPaths", protected_file_classes: "protectedFileClasses", protected_class_catalog: "protectedClassCatalog", protected_effects: "protectedEffects", max_files_per_action: "maxFilesPerAction", max_bytes_written_per_task: "maxBytesWrittenPerTask", max_bytes_deleted_per_task: "maxBytesDeletedPerTask", max_destructive_effects_per_task: "maxDestructiveEffectsPerTask", require_shim: "requireShim" }
  },
  git: {
    required: ["actions", "filesystemActions", "providers", "allowedRemoteSchemes", "allowedOperations", "blockedOperations", "protectedRefs", "requireShim"],
    keys: { actions: "actions", filesystem_actions: "filesystemActions", providers: "providers", allowed_remote_schemes: "allowedRemoteSchemes", allowed_operations: "allowedOperations", require_approval: "requireApproval", blocked_operations: "blockedOperations", protected_refs: "protectedRefs", max_ref_changes_per_task: "maxRefChangesPerTask", require_shim: "requireShim" }
  },
  database: {
    required: ["actions", "protectedEnvironments", "allowedOperations", "allowedResources", "routineCatalog", "requireReadOnlyForSelect", "denyUnreviewedIndirectEffects", "requireShim"],
    keys: { actions: "actions", protected_environments: "protectedEnvironments", allowed_operations: "allowedOperations", require_approval: "requireApproval", allowed_resources: "allowedResources", routine_catalog: "routineCatalog", require_read_only_for_select: "requireReadOnlyForSelect", deny_unreviewed_indirect_effects: "denyUnreviewedIndirectEffects", max_schema_changes_per_task: "maxSchemaChangesPerTask", statement_timeout_ms: "statementTimeoutMs", lock_timeout_ms: "lockTimeoutMs", require_shim: "requireShim" }
  }
};

const ROOT_POLICY_KEYS = new Set([
  "require_approval", "require_shim",
  "max_transaction_eth", "allowed_actions", "allowed_chains", "chain_actions", "consensus_threshold_eth", "consensus_require_hold",
  "allowed", "bash.blocked_commands", "web_fetch.blocked_domains", "file_write.blocked_paths", "email.require_approval", "email.allowed_recipients", "email.blocked_recipients",
  "http.allowed_methods", "http.allowed_hosts", "http.blocked_methods",
  "deny_string", "allowed_servers", "allowed_tools", "blocked_tools",
  "daily_tool_calls", "daily_evm_limit_eth",
  "max_tool_calls_per_task", "max_tool_calls_per_hour", "max_model_spend_usd_per_task", "max_model_tokens_per_task",
  ...Object.values(RESOURCE_CONFIG).flatMap((config) => Object.keys(config.keys)),
]);

const ROOT_POLICY_SYNTAX = [
  /^token\.[A-Za-z0-9_]+\.(?:max_transaction|consensus_threshold|decimals|addresses)\s*:/,
  /^cap\.[A-Za-z0-9_-]+\.(?:max_count|max_sum_usd|window|action|group_by|amount_field|window_days|window_hours|timezone)\s*:/,
  /^allow_only(?:\[action=[^\]]*\])?\.[^\s:]+(?:\s+attested)?(?:\s+(?:contains|starts_with|prefix|ends_with|matches|equals))?\s*:/,
  /^deny_if\.\S+\s+(?:contains|starts_with|ends_with|matches|equals|not_equals)\s+.+$/,
];

interface Section { name: string; body: string; }

function sectionsOf(markdown: string): Section[] {
  if (/^ {1,3}##\s+\S.*$/m.test(markdown)) {
    throw new Error("Indented policy headings are not supported");
  }
  const headers = [...markdown.matchAll(/^##\s+(.+?)\s*$/gm)].map((match) => ({ name: match[1]!.trim().toLowerCase(), start: match.index!, end: match.index! + match[0].length }));
  const seen = new Set<string>();
  return headers.map((header, index) => {
    if (!KNOWN_SECTIONS.has(header.name)) throw new Error(`Unknown policy block ## ${header.name}`);
    if (seen.has(header.name)) throw new Error(`Duplicate policy block ## ${header.name}`);
    seen.add(header.name);
    return { name: header.name, body: markdown.slice(header.end, headers[index + 1]?.start ?? markdown.length).trim() };
  });
}

function isOneDeletionAway(shorter: string, longer: string): boolean {
  return shorter.length + 1 === longer.length
    && Array.from({ length: longer.length }, (_, index) => longer.slice(0, index) + longer.slice(index + 1)).includes(shorter);
}

function isOneSubstitutionOrTransposition(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  const mismatches = Array.from({ length: left.length }, (_, index) => index)
    .filter((index) => left[index] !== right[index]);
  if (mismatches.length === 1) return true;
  const [first, second] = mismatches;
  return mismatches.length === 2
    && first !== undefined
    && second !== undefined
    && second === first + 1
    && left[first] === right[second]
    && left[second] === right[first];
}

function isLikelyVersionKeyTypo(candidate: string): boolean {
  const source = candidate.toLowerCase();
  const target = "version";
  if (source.length === target.length) return isOneSubstitutionOrTransposition(source, target);
  return source.length < target.length
    ? isOneDeletionAway(source, target)
    : isOneDeletionAway(target, source);
}

function parseVersion(markdown: string): string {
  const structural = maskHtmlComments(markdown);
  const firstSection = structural.search(/^##\s+/m);
  const root = firstSection < 0 ? structural : structural.slice(0, firstSection);
  const values: string[] = [];
  for (const line of root.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const match = line.match(/^\s*version:\s*(.+?)\r?$/i);
    if (match) {
      values.push(match[1]!.trim());
      continue;
    }
    if (isRootPolicySyntax(trimmed)) {
      throw new Error(`Policy field must be inside a policy block: ${trimmed}`);
    }
    const unquotedMarkdown = trimmed.replace(/^(?:[-*+>]\s*)+/, "");
    if (
      /^version(?:\s*[:=]|\s*$|\s+\d)/i.test(unquotedMarkdown)
      || /^version\s+[^A-Za-z0-9\s:=]+(?=\s*(?::|=)|\s+\d+\.\d+\.\d+(?:\s|$))/i.test(
        unquotedMarkdown,
      )
    ) {
      throw new Error(`Invalid root version declaration: ${trimmed}`);
    }
    if (/^version[^A-Za-z0-9\s:=]+(?=\s*(?::|=)|\s+\d+\.\d+\.\d+(?:\s|$))/i.test(unquotedMarkdown)) {
      throw new Error(`Unrecognized root policy field: ${trimmed}`);
    }
    const rootKey = unquotedMarkdown.match(/^([A-Za-z][\w-]*)(?:\s*[:=]|\s+\d+\.\d+\.\d+(?:\s|$))/)?.[1];
    if (rootKey && isLikelyVersionKeyTypo(rootKey)) {
      throw new Error(`Unrecognized root policy field: ${trimmed}`);
    }
  }
  if (values.length > 1) throw new Error("Duplicate version fields are not allowed");
  const version = values[0] ?? "0.0.0";
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error(`Invalid policy version "${version}"; expected semver X.Y.Z`);
  const major = Number(version.split(".")[0]);
  if ((major === 0 && version !== "0.0.0") || (major === 2 && version !== "2.0.0" && version !== "2.1.0") || major > 2) {
    throw new Error(`Policy version ${version} is not supported by this engine build`);
  }
  return version;
}

function isRootPolicySyntax(line: string): boolean {
  const key = line.match(/^([A-Za-z_][\w.]*)\s*:/)?.[1];
  return (key !== undefined && ROOT_POLICY_KEYS.has(key))
    || ROOT_POLICY_SYNTAX.some((pattern) => pattern.test(line));
}

function cleanedLines(body: string): string[] {
  return body.split("\n").map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));
}

function list(value: string): string[] {
  return value.split(",").map((entry) => unquote(entry.trim())).filter(Boolean);
}

function resourceList(value: string): string[] {
  return value.split(",").map((entry) => entry.trim()).filter(Boolean);
}

function unquote(value: string): string {
  return (value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'")) ? value.slice(1, -1) : value;
}

const boolean = (value: string, key: string, strict: boolean): boolean => {
  const normalized = value.trim().toLowerCase();
  if (strict && normalized !== "true" && normalized !== "false") throw new Error(`${key} must be true or false`);
  // Policy 1.x follows the frozen Sigil Sign parser: boolean tokens are case-insensitive.
  return normalized === "true";
};

const number = (value: string): number | undefined => {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : undefined;
};

function integer(value: string): number | undefined {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function requireKeyValue(line: string, section: string): [string, string] {
  const match = line.match(/^([\w.]+):\s*(.+)$/);
  if (!match) throw new Error(`Unrecognized ${section} policy line: ${line}`);
  return [match[1]!, match[2]!];
}

function unique(lines: string[], section: string): Array<[string, string]> {
  const seen = new Set<string>();
  return lines.map((line) => {
    const pair = requireKeyValue(line, section);
    if (seen.has(pair[0])) throw new Error(`Duplicate ${section} policy key: ${pair[0]}`);
    seen.add(pair[0]);
    return pair;
  });
}

function parseEvmChainActions(body: string): Record<string, string[]> | undefined {
  const lines = body.split("\n");
  const numericMapping = /^\s*"?\d+"?\s*:/;
  const headerIndices = lines
    .map((line, index) => (/^\s*chain_actions:\s*$/.test(line) && !/^\s*#/.test(line) ? index : -1))
    .filter((index) => index >= 0);
  if (headerIndices.length > 1) throw new Error("Duplicate EVM policy key: chain_actions");
  const headerIndex = headerIndices[0] ?? -1;
  if (headerIndex < 0) {
    if (lines.some((line) => numericMapping.test(line))) {
      throw new Error("Unknown top-level numeric mapping in ## evm");
    }
    return undefined;
  }
  if (lines.slice(0, headerIndex).some((line) => numericMapping.test(line))) {
    throw new Error("Unknown top-level numeric mapping in ## evm");
  }
  const boundaryOffset = lines.slice(headerIndex + 1).findIndex((line) =>
    line.trim() !== ""
    && !/^\s*#/.test(line)
    && (/^\S/.test(line) || /^\s+(?:require_approval|require_shim)\s*:/.test(line))
  );
  if (boundaryOffset >= 0) {
    const boundaryIndex = headerIndex + 1 + boundaryOffset;
    const boundaryLine = lines[boundaryIndex] ?? "";
    if (/^"?\d+"?\s*:/.test(boundaryLine)) {
      throw new Error("chain_actions mappings must be indented");
    }
    const dangling = lines.slice(boundaryIndex + 1).some((line) => /^\s+"?\d+"?\s*:/.test(line));
    if (dangling) throw new Error("Dangling chain_actions mapping after the block boundary");
    if (lines.slice(boundaryIndex).some((line) => numericMapping.test(line))) {
      throw new Error("Unknown top-level numeric mapping in ## evm");
    }
  }
  const result: Record<string, string[]> = {};
  const seenChainIds = new Set<string>();
  let emptyChainId: string | undefined;
  for (let index = headerIndex + 1; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (line.trim() === "" || /^\s*#/.test(line)) continue;
    if (/^\S/.test(line)) break;
    const normalized = line.replace(/#.*$/, "").trim();
    if (/^(?:require_approval|require_shim)\s*:/.test(normalized)) continue;
    const match = normalized.match(/^"?(\d+)"?\s*:\s*(.*)$/);
    if (match) {
      const chainId = match[1]!.replace(/^0+(?=\d)/, "");
      if (seenChainIds.has(chainId)) throw new Error(`Duplicate chain_actions chain ID: ${chainId}`);
      seenChainIds.add(chainId);
      const actions = list(match[2]!);
      if (!actions.length) {
        emptyChainId ??= chainId;
        continue;
      }
      result[chainId] = actions;
    }
  }
  if (emptyChainId !== undefined) throw new Error(`chain_actions entry for chain ${emptyChainId} must contain at least one action`);
  return Object.keys(result).length > 0 ? result : undefined;
}

const requiredActionList = (value: string, key: string): string[] => {
  const values = value.split(",").map((entry) => unquote(entry.trim()).trim());
  if (values.some((entry) => !entry)) throw new Error(`${key} must not contain empty actions`);
  if (values.some((entry) => !ACTION_PATTERN(entry))) throw new Error(`${key} must contain exact values or one trailing * wildcard`);
  return [...new Set(values)];
};
const validateGenericControl = (key: string, isV2: boolean, seen?: Set<string>): void => {
  if (!isV2) throw new Error("Policy syntax requires version 2.0.0");
  if (seen?.has(key)) throw new Error(`Duplicate policy key: ${key}`);
  seen?.add(key);
};
const applyGenericControl = (result: Record<string, unknown>, key: string, value: string): void => {
  if (key === "require_approval") result.requireApproval = requiredActionList(value, key);
  else result.requireShim = boolean(value, key, true);
};
const parseGenericControl = (result: Record<string, unknown>, key: string, value: string, isV2: boolean, seen?: Set<string>): boolean => {
  if (key !== "require_approval" && key !== "require_shim") return false;
  validateGenericControl(key, isV2, seen);
  applyGenericControl(result, key, value);
  return true;
};

interface EvmParserState {
  chains: boolean;
  chainActionsSeen: boolean;
}
const parseTokenDecimals = (symbol: string, value: string): number => {
  const raw = value.trim();
  if (!/^\d+$/.test(raw)) throw new Error(`token.${symbol}.decimals must be an integer from 0 through 36`);
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed > 36) throw new Error(`token.${symbol}.decimals must be an integer from 0 through 36`);
  return parsed;
};
const TOKEN_PROFILE_PARSERS: Record<string, (profile: Record<string, unknown>, symbol: string, value: string) => void> = {
  decimals: (profile, symbol, value) => { profile.decimals = parseTokenDecimals(symbol, value); },
  addresses: (profile, _symbol, value) => { profile.addresses = [...new Set([...(profile.addresses as string[] ?? []), ...list(value).map((entry) => entry.toLowerCase())])]; },
  max_transaction: (profile, _symbol, value) => { profile.maxTransaction = value.trim(); },
  consensus_threshold: (profile, _symbol, value) => { profile.consensusThreshold = value.trim(); },
};
const parseEvmToken = (tokens: Record<string, Record<string, unknown>>, tokenFields: Set<string>, line: string): boolean => {
  const token = line.match(/^token\.([A-Za-z0-9_]+)\.(max_transaction|consensus_threshold|decimals|addresses):\s*(.+)$/);
  if (!token) return false;
  const [, rawSymbol, field, rawTokenValue] = token;
  if (!rawSymbol || !field || rawTokenValue === undefined) return true;
  const symbol = rawSymbol.toUpperCase();
  const tokenField = `${symbol}.${field}`;
  if (field !== "addresses" && tokenFields.has(tokenField)) throw new Error(`Duplicate EVM token policy key: token.${tokenField}`);
  tokenFields.add(tokenField);
  TOKEN_PROFILE_PARSERS[field]?.(tokens[symbol] ??= {}, symbol, rawTokenValue);
  return true;
};
const parseMaxTransactionEth = (result: Record<string, unknown>, value: string): void => {
  const parsed = number(value);
  if (parsed === undefined || parsed <= 0) throw new Error("max_transaction_eth must be greater than zero");
  result.maxTransactionEth = parsed;
};
const parseConsensusThresholdEth = (result: Record<string, unknown>, value: string): void => {
  const parsed = number(value);
  if (parsed === undefined) throw new Error("consensus_threshold_eth must be numeric");
  if (parsed <= 0) throw new Error("consensus_threshold_eth must be greater than zero");
  result.consensusThresholdEth = parsed;
};
const EVM_VALUE_PARSERS: Record<string, (result: Record<string, unknown>, value: string, isV2: boolean) => void> = {
  max_transaction_eth: (result, value) => parseMaxTransactionEth(result, value),
  allowed_actions: (result, value) => { result.allowedActions = list(value); },
  allowed_chains: (result, value) => { result.allowedChains = list(value).map(integer).filter((entry): entry is number => entry !== undefined && entry > 0); },
  consensus_threshold_eth: (result, value) => parseConsensusThresholdEth(result, value),
  consensus_require_hold: (result, value, isV2) => { result.requireHold = boolean(value, "consensus_require_hold", isV2); },
};
const parseEvmValue = (result: Record<string, unknown>, key: string, value: string, isV2: boolean): void => {
  const parser = EVM_VALUE_PARSERS[key];
  if (!parser) throw new Error(`Unrecognized EVM policy key: ${key}`);
  parser(result, value, isV2);
};
const parseEvmChainHeader = (state: EvmParserState, line: string): boolean => {
  if (line !== "chain_actions:") return false;
  if (state.chainActionsSeen) throw new Error("Duplicate EVM policy key: chain_actions");
  state.chainActionsSeen = true;
  state.chains = true;
  return true;
};
const isEvmChainActionMapping = (state: EvmParserState, line: string): boolean =>
  state.chains && /^"?\d+"?\s*:\s*.+$/.test(line);
const ensureEvmRequirements = (result: Record<string, unknown>): void => {
  if (!Array.isArray(result.allowedActions) || result.allowedActions.length === 0) throw new Error("## evm requires at least one allowed_action");
  if (!Array.isArray(result.allowedChains) || result.allowedChains.length === 0) throw new Error("## evm requires at least one positive allowed_chain");
};
const parseEvm = (lines: string[], isV2: boolean, body: string): Record<string, unknown> => {
  const result: Record<string, unknown> = { maxTransactionEth: 5 };
  const tokens: Record<string, Record<string, unknown>> = {};
  const genericControls = new Set<string>();
  const ordinaryKeys = new Set<string>();
  const tokenFields = new Set<string>();
  const state: EvmParserState = { chains: false, chainActionsSeen: false };
  const chainActions = parseEvmChainActions(body);
  for (const line of lines) {
    if (parseEvmChainHeader(state, line)) continue;
    const generic = line.match(/^(require_approval|require_shim):\s*(.+)$/);
    if (generic) { parseGenericControl(result, generic[1]!, generic[2]!, isV2, genericControls); continue; }
    if (isEvmChainActionMapping(state, line)) continue;
    state.chains = false;
    if (parseEvmToken(tokens, tokenFields, line)) continue;
    const [key, value] = requireKeyValue(line, "EVM");
    if (parseGenericControl(result, key, value, isV2, genericControls)) continue;
    if (ordinaryKeys.has(key)) throw new Error(`Duplicate EVM policy key: ${key}`);
    ordinaryKeys.add(key);
    parseEvmValue(result, key, value, isV2);
  }
  if (chainActions !== undefined) result.chainActions = chainActions;
  if (Object.keys(tokens).length) result.tokenRules = tokens;
  ensureEvmRequirements(result);
  return result;
};

const parseToolCallHttpMethods = (result: Record<string, unknown>, key: string, value: string, isV2: boolean): void => {
  if (!isV2) throw new Error("http policy keys require version 2.0.0");
  const methods = list(value);
  if (!methods.length || methods.some((method) => !HTTP_METHODS.has(method))) throw new Error(`${key} must contain only uppercase HTTP methods (GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE)`);
  result[key === "http.allowed_methods" ? "httpAllowedMethods" : "httpBlockedMethods"] = [...new Set(methods)];
};
const parseToolCallHttpHosts = (result: Record<string, unknown>, value: string, isV2: boolean): void => {
  if (!isV2) throw new Error("http policy keys require version 2.0.0");
  const hosts = list(value).map((entry) => entry.toLowerCase().replace(/\.$/, ""));
  if (!hosts.length || hosts.some((host) => !validPolicyHost(host))) throw new Error("http.allowed_hosts must contain valid lowercase host names (use *.example.com for subdomains)");
  result.httpAllowedHosts = [...new Set(hosts)];
};
const TOOL_CALL_VALUE_PARSERS: Record<string, (result: Record<string, unknown>, key: string, value: string, isV2: boolean) => void> = {
  allowed: (result, _key, value) => { result.allowed = list(value); },
  "bash.blocked_commands": (result, _key, value) => { result.bashBlockedCommands = list(value); },
  "web_fetch.blocked_domains": (result, _key, value) => { result.webFetchBlockedDomains = list(value); },
  "file_write.blocked_paths": (result, _key, value) => { result.fileWriteBlockedPaths = list(value); },
  "email.require_approval": (result, key, value, isV2) => { result.emailRequireApproval = boolean(value, key, isV2); },
  "email.allowed_recipients": (result, _key, value) => { result.emailAllowedRecipients = list(value).map((entry) => entry.toLowerCase()); },
  "email.blocked_recipients": (result, _key, value) => { result.emailBlockedRecipients = list(value).map((entry) => entry.toLowerCase()); },
  "http.allowed_methods": parseToolCallHttpMethods,
  "http.blocked_methods": parseToolCallHttpMethods,
  "http.allowed_hosts": (result, _key, value, isV2) => parseToolCallHttpHosts(result, value, isV2),
};
const parseToolCallValue = (result: Record<string, unknown>, key: string, value: string, isV2: boolean): void => {
  const parser = TOOL_CALL_VALUE_PARSERS[key];
  if (!parser) throw new Error(`Unrecognized tool_calls policy key: ${key}`);
  parser(result, key, value, isV2);
};
const falseOnlyToolCallShim = (result: Record<string, unknown>): boolean =>
  result.requireShim === false && Object.keys(result).length === 1;
const parseToolCalls = (lines: string[], isV2: boolean): Record<string, unknown> => {
  const result: Record<string, unknown> = {};
  for (const [key, value] of unique(lines, "tool_calls")) {
    if (parseGenericControl(result, key, value, isV2)) continue;
    parseToolCallValue(result, key, value, isV2);
  }
  if (isV2 && falseOnlyToolCallShim(result)) throw new Error("## tool_calls must declare at least one enforceable rule or control");
  return result;
};

interface CustomParserState {
  rules: Array<Record<string, unknown>>;
  controls: Record<string, unknown>;
  genericControls: Set<string>;
  allows: Map<string, Record<string, unknown>>;
  operators: Map<string, string>;
}
const customAllowMatch = (line: string): RegExpMatchArray | null =>
  line.match(/^allow_only(?:\[action=([^\]]*)\])?\.([^\s:]+)(?:\s+(attested))?(?:\s+(contains|starts_with|prefix|ends_with|matches|equals))?\s*:\s*(.*)$/);
const customAllowValues = (fieldPath: string, rawValues: string): string[] => {
  // In 0.1.1, comma-containing regexes retain Sigil Sign Policy 1.x split semantics; changing this requires a coordinated compatibility-breaking parser/canonicalization release across Sign and consumers.
  const values = list(rawValues);
  if (!values.length) throw new Error(`allow_only.${fieldPath} must contain at least one value`);
  return values;
};
const customAllowRule = (actionScope: string | undefined, fieldPath: string, operator: string, attested: boolean, values: string[]): Record<string, unknown> => ({
  name: actionScope ? `allow_only[action=${actionScope}].${fieldPath}` : `allow_only.${fieldPath}`,
  type: "allow_field",
  fieldPath,
  ...(actionScope ? { actionScope } : {}),
  ...(attested ? { attested: true } : {}),
  ...(operator !== "equals" ? { operator } : {}),
  values,
});
const mergeCustomAllowRule = (state: CustomParserState, scope: string, operator: string, attested: boolean, fieldPath: string, rule: Record<string, unknown>, values: string[]): void => {
  if (state.operators.has(scope) && state.operators.get(scope) !== operator) throw new Error(`allow_only.${fieldPath} mixes operators (${state.operators.get(scope)}, ${operator}); use one operator per field and action scope`);
  state.operators.set(scope, operator);
  const key = `${scope}::${operator}`;
  const existing = state.allows.get(key);
  if (!existing) { state.allows.set(key, rule); state.rules.push(rule); return; }
  if (Boolean(existing.attested) !== attested) throw new Error(`allow_only.${fieldPath} mixes attested and non-attested rules; use one provenance mode per field and action scope`);
  existing.values = [...new Set([...(existing.values as string[]), ...values])];
};
const parseCustomAllow = (state: CustomParserState, line: string, isV2: boolean): boolean => {
  const allow = customAllowMatch(line);
  if (!allow) return false;
  const [, rawScope, rawPath, rawAttested, rawOperator, rawValues] = allow;
  if (!rawPath || rawValues === undefined) return true;
  if (!isV2 && (rawScope || rawAttested || rawOperator)) throw new Error("Policy syntax requires version 2.0.0");
  const actionScope = rawScope?.trim();
  if (actionScope === "") throw new Error("allow_only action scope must not be empty");
  const fieldPath = stripIntent(rawPath);
  if (!fieldPath) throw new Error("allow_only field path must not be empty");
  const operator = rawOperator === "prefix" ? "starts_with" : (rawOperator ?? "equals");
  const values = customAllowValues(fieldPath, rawValues.trim());
  const attested = rawAttested === "attested";
  const scope = `${actionScope ?? "<global>"}::${fieldPath}`;
  mergeCustomAllowRule(state, scope, operator, attested, fieldPath, customAllowRule(actionScope, fieldPath, operator, attested, values), values);
  return true;
};
const parseCustomDeny = (rules: Array<Record<string, unknown>>, line: string): boolean => {
  const deny = line.match(/^deny_if\.(\S+)\s+(contains|starts_with|ends_with|matches|equals|not_equals)\s+(.+)$/);
  if (!deny) return false;
  const [, rawPath, operator, rawValue] = deny;
  if (!rawPath || !operator || rawValue === undefined) return true;
  const fieldPath = stripIntent(rawPath);
  if (!fieldPath) throw new Error("deny_if field path must not be empty");
  const value = unquote(rawValue);
  rules.push({ name: `deny_if.${fieldPath}.${operator}:${value}`, type: "field", fieldPath, operator, value });
  return true;
};
const parseCustomDenyString = (rules: Array<Record<string, unknown>>, line: string): boolean => {
  const string = line.match(/^deny_string:\s*(.+)$/);
  if (!string) return false;
  const value = unquote(string[1] ?? "");
  rules.push({ name: `deny_string:${value}`, type: "deny_string", value });
  return true;
};
const parseCustomLine = (state: CustomParserState, line: string, isV2: boolean): boolean => {
  const generic = line.match(/^(require_approval|require_shim):\s*(.+)$/);
  if (generic) return parseGenericControl(state.controls, generic[1]!, generic[2]!, isV2, state.genericControls);
  return parseCustomAllow(state, line, isV2) || parseCustomDeny(state.rules, line) || parseCustomDenyString(state.rules, line);
};
const parseCustom = (lines: string[], isV2: boolean): { rules: Array<Record<string, unknown>>; requireApproval?: string[]; requireShim?: boolean } | undefined => {
  const state: CustomParserState = { rules: [], controls: {}, genericControls: new Set<string>(), allows: new Map<string, Record<string, unknown>>(), operators: new Map<string, string>() };
  for (const line of lines) if (!parseCustomLine(state, line, isV2)) throw new Error(`Unrecognized custom rule: ${line}`);
  const { rules, controls } = state;
  if (!rules.length && controls.requireApproval === undefined && controls.requireShim !== true) {
    if (controls.requireShim === false) {
      throw new Error("## custom must declare at least one enforceable rule or control");
    }
    return undefined;
  }
  return { rules, ...(controls.requireApproval ? { requireApproval: controls.requireApproval as string[] } : {}), ...(controls.requireShim !== undefined ? { requireShim: controls.requireShim as boolean } : {}) };
};

function validPolicyHost(value: string): boolean {
  const hostname = value.startsWith("*.") ? value.slice(2) : value;
  if (!hostname || hostname.length > 253) return false;
  return hostname.split(".").every((label) =>
    label.length > 0
    && label.length <= 63
    && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  );
}

const parseMcp = (lines: string[], isV2: boolean): Record<string, unknown> => {
  if (!isV2) throw new Error("Policy block ## mcp requires version 2.0.0");
  const result: Record<string, unknown> = {};
  for (const [key, value] of unique(lines, "MCP")) {
    if (key === "allowed_servers") result.allowedServers = actionList(value, key);
    else if (key === "allowed_tools") result.allowedTools = actionList(value, key);
    else if (key === "blocked_tools") result.blockedTools = actionList(value, key);
    else if (key === "require_approval") result.requireApproval = actionList(value, key);
    else if (key === "require_shim") result.requireShim = boolean(value, key, true);
    else throw new Error(`Unrecognized MCP policy key: ${key}`);
  }
  if (!(result.allowedServers || result.allowedTools || result.blockedTools)) throw new Error("## mcp must declare at least one of allowed_servers, allowed_tools, or blocked_tools");
  const allowed = result.allowedTools as string[] | undefined; const blocked = result.blockedTools as string[] | undefined;
  if (allowed && blocked) {
    const matchesPattern = (value: string, pattern: string) =>
      value === pattern || (pattern.endsWith("*") && value.startsWith(pattern.slice(0, -1)));
    const overlap = allowed.filter((entry) => blocked.some((pattern) => matchesPattern(entry, pattern)));
    if (overlap.length) throw new Error(`MCP policy lists the same tool in both allowed_tools and blocked_tools: ${overlap.join(", ")}`);
  }
  return result;
};

function actionList(value: string, key: string): string[] { const values = list(value); if (!values.length || values.some((entry) => !ACTION_PATTERN(entry))) throw new Error(`${key} must contain exact values or one trailing * wildcard`); return [...new Set(values)]; }
function resourceActionList(value: string, key: string): string[] { const values = resourceList(value); if (!values.length) throw new Error(`${key} must contain at least one entry`); if (values.some((entry) => !ACTION_PATTERN(entry))) throw new Error(`${key} must contain exact values or one trailing * wildcard`); return [...new Set(values)]; }

const hasCanonicalPathSegments = (value: string): boolean =>
  value.split("/").every((segment) => segment !== "." && segment !== "..");
const isCanonicalAbsoluteRoot = (value: string): boolean =>
  value.startsWith("/") && !value.endsWith("/") && !value.includes("//") && hasCanonicalPathSegments(value);
const isCanonicalRoot = (value: string): boolean => value === "." || value === "/" || isCanonicalAbsoluteRoot(value);
const positiveInt = (value: string): boolean => { const raw = value.trim(); return /^\d+$/.test(raw) && BigInt(raw) >= 1n && BigInt(raw) <= MAX_SAFE; };
const fixedDecimalParts = (value: string): { whole: string; fraction: string; token: string } | undefined => {
  const match = value.match(/^(0|[1-9]\d*)(?:\.(\d{1,6}))?/);
  const whole = match?.[1];
  if (whole === undefined || match === null) return undefined;
  return { whole, fraction: match[2] ?? "", token: match[0] };
};
const decimalMicros = ({ whole, fraction }: { whole: string; fraction: string }): bigint =>
  BigInt(whole) * 1_000_000n + BigInt(fraction.padEnd(6, "0"));
const isCounterMicros = (micros: bigint): boolean => micros >= 1n && micros <= MAX_COUNTER_MICROS;
const isSafeDecimalMicros = (micros: bigint): boolean => micros >= 1n && micros <= MAX_SAFE * 1_000_000n;
const hasInvalidDecimalSuffix = (value: string): boolean => /^[\d.+-]/.test(value) || /^[eE][+-]?\d/.test(value);
const finitePositiveNumber = (value: string): number | undefined => {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
};
const dailyEvmLimit = (value: string): number | undefined => {
  const raw = value.trim();
  const parts = fixedDecimalParts(raw);
  if (!parts || hasInvalidDecimalSuffix(raw.slice(parts.token.length))) return undefined;
  if (!isCounterMicros(decimalMicros(parts))) return undefined;
  return finitePositiveNumber(parts.token);
};
const positiveDecimal = (value: string): boolean => {
  const raw = unquote(value.trim());
  const parts = fixedDecimalParts(raw);
  return parts !== undefined && parts.token === raw && isSafeDecimalMicros(decimalMicros(parts));
};
const required = (value: string, key: string): string => { if (!value) throw new Error(`${key} must not be empty`); return value; };

interface SoftLimitState {
  result: Record<string, unknown>;
  caps: Record<string, Record<string, unknown>>;
  scalarKeys: Set<string>;
  capKeys: Set<string>;
  hasLimit: boolean;
}
const softCapMatch = (line: string): RegExpMatchArray | null =>
  line.match(/^cap\.([A-Za-z0-9_-]+)\.(max_count|max_sum_usd|window|action|group_by|amount_field|window_days|window_hours|timezone):\s*(.*?)\s*$/);
const validateSoftCapIdentity = (state: SoftLimitState, capName: string, field: keyof typeof SOFT_LIMIT_CAP_FIELDS): void => {
  if (["daily_tool_calls", "daily_evm_limit_eth"].includes(capName)) throw new Error(`cap name ${capName} is reserved for the legacy limit`);
  if (RESERVED_PROFILE_NAMES.has(capName)) throw new Error(`Reserved soft_limits cap name: ${capName}`);
  const canonicalKey = `${capName}.${SOFT_LIMIT_CAP_FIELDS[field]}`;
  if (state.capKeys.has(canonicalKey)) throw new Error(`Duplicate soft_limits cap key: ${capName}.${field}`);
  state.capKeys.add(canonicalKey);
};
const SOFT_CAP_VALUE_PARSERS: Record<string, (profile: Record<string, unknown>, capName: string, raw: string, value: string) => void> = {
  max_count: (profile, capName, raw) => { if (!positiveInt(raw)) throw new Error(`cap.${capName}.max_count must be a positive integer`); profile.maxCount = Number(raw); },
  max_sum_usd: (profile, capName, _raw, value) => { if (!positiveDecimal(value)) throw new Error(`cap.${capName}.max_sum_usd must be a positive USD decimal with at most 6 places`); profile.maxSumUsd = value; },
  window: (profile, capName, _raw, value) => { if (!["day", "hour", "task"].includes(value)) throw new Error(`cap.${capName}.window must be day, hour, or task`); profile.window = value; },
  action: (profile, capName, _raw, value) => { if (!ACTION_PATTERN(value)) throw new Error(`cap.${capName}.action supports only an exact value or one trailing * wildcard`); profile.action = value; },
  group_by: (profile, capName, _raw, value) => { profile.groupBy = required(value, `cap.${capName}.group_by`); },
  amount_field: (profile, capName, _raw, value) => { profile.amountField = required(value, `cap.${capName}.amount_field`); },
};
const parseSoftCap = (state: SoftLimitState, line: string, isV2: boolean): boolean => {
  const cap = softCapMatch(line);
  if (!cap) return false;
  const [, capName, rawField, rawValue] = cap;
  if (!capName || !rawField || rawValue === undefined) return true;
  if (!isV2) throw new Error("Named soft_limits caps require version 2.0.0");
  if (["window_days", "window_hours", "timezone"].includes(rawField)) throw new Error(`cap.${capName}.${rawField} is not yet supported`);
  const field = rawField as keyof typeof SOFT_LIMIT_CAP_FIELDS;
  validateSoftCapIdentity(state, capName, field);
  const raw = rawValue.trim();
  SOFT_CAP_VALUE_PARSERS[field]?.(state.caps[capName] ??= {}, capName, raw, unquote(raw));
  return true;
};
const parseDailyToolCalls = (state: SoftLimitState, value: string, isV2: boolean): void => {
  const parsed = integer(value);
  if (parsed === undefined || parsed <= 0 || (isV2 && !positiveInt(value))) throw new Error("daily_tool_calls must be a positive integer");
  state.result.dailyToolCalls = parsed;
  state.hasLimit = true;
};
const parseDailyEvmLimit = (state: SoftLimitState, value: string): void => {
  const parsed = dailyEvmLimit(value);
  if (parsed === undefined || parsed <= 0) throw new Error("daily_evm_limit_eth must be a positive decimal with at most 6 places");
  state.result.dailyEvmLimitEth = parsed;
  state.hasLimit = true;
};
const SOFT_LIMIT_VALUE_PARSERS: Record<string, (state: SoftLimitState, value: string, isV2: boolean) => void> = {
  daily_tool_calls: parseDailyToolCalls,
  daily_evm_limit_eth: (state, value) => parseDailyEvmLimit(state, value),
};
const parseSoftLimitScalar = (state: SoftLimitState, line: string, isV2: boolean): void => {
  if (line.startsWith("cap.")) throw new Error(`Unrecognized soft_limits policy key: ${line.split(":", 1)[0]}`);
  const [key, value] = requireKeyValue(line, "soft_limits");
  if (state.scalarKeys.has(key)) throw new Error(`Duplicate soft_limits policy key: ${key}`);
  state.scalarKeys.add(key);
  if (parseGenericControl(state.result, key, value, isV2)) return;
  const parser = SOFT_LIMIT_VALUE_PARSERS[key];
  if (!parser) throw new Error(`Unrecognized soft_limits policy key: ${key}`);
  parser(state, value, isV2);
};
const validateSoftCaps = (caps: Record<string, Record<string, unknown>>): void => {
  for (const [name, cap] of Object.entries(caps)) {
    if ((cap.maxCount === undefined) === (cap.maxSumUsd === undefined)) throw new Error(`cap.${name} requires exactly one of max_count or max_sum_usd`);
    if (!cap.window || !cap.action) throw new Error(`cap.${name}.window and cap.${name}.action are required`);
    if (cap.maxSumUsd !== undefined && !cap.amountField) throw new Error(`cap.${name}.amount_field is required for sum caps`);
    if (cap.maxCount !== undefined && cap.amountField) throw new Error(`cap.${name}.amount_field is not valid for count caps`);
  }
};
const parseSoftLimits = (lines: string[], isV2: boolean): Record<string, unknown> => {
  const state: SoftLimitState = { result: {}, caps: Object.create(null) as Record<string, Record<string, unknown>>, scalarKeys: new Set<string>(), capKeys: new Set<string>(), hasLimit: false };
  for (const line of lines) {
    if (parseSoftCap(state, line, isV2)) continue;
    parseSoftLimitScalar(state, line, isV2);
  }
  validateSoftCaps(state.caps);
  if (Object.keys(state.caps).length) { state.result.caps = state.caps; state.hasLimit = true; }
  if (isV2 && !state.hasLimit) throw new Error("## soft_limits must declare at least one enforced limit under version 2.0.0");
  return state.result;
};

const parseExecutionLimits = (lines: string[], isV2: boolean): Record<string, unknown> => {
  const result: Record<string, unknown> = {};
  for (const [key, value] of unique(lines, "execution_limits")) {
    if (parseGenericControl(result, key, value, isV2)) continue;
    if (key === "max_tool_calls_per_task") {
      if (!positiveInt(value)) throw new Error("max_tool_calls_per_task must be a positive integer");
      result.maxToolCallsPerTask = Number(value);
    } else if (key === "max_tool_calls_per_hour") {
      if (!positiveInt(value)) throw new Error("max_tool_calls_per_hour must be a positive integer");
      result.maxToolCallsPerHour = Number(value);
    } else if (key === "max_model_spend_usd_per_task") {
      if (!positiveDecimal(value)) throw new Error("max_model_spend_usd_per_task must be a positive decimal with at most 6 places");
      result.maxModelSpendUsdPerTask = unquote(value);
    } else if (key === "max_model_tokens_per_task") {
      if (!positiveInt(value)) throw new Error("max_model_tokens_per_task must be a positive integer");
      result.maxModelTokensPerTask = Number(value);
    } else throw new Error(`Unrecognized execution_limits policy key: ${key}`);
  }
  if (!Object.keys(result).length) {
    throw new Error("## execution_limits must declare at least one enforceable control");
  }
  if (!hasEnforceableExecutionLimitControl(result)) {
    throw new Error("## execution_limits must declare at least one enforceable control");
  }
  return result;
};

function hasEnforceableExecutionLimitControl(limits: Record<string, unknown> | undefined): boolean {
  return Object.values(limits ?? {}).some((value) => value !== undefined && value !== false);
}

const resourceNumber = (value: string, key: string): number => {
  if (!positiveInt(value)) throw new Error(`${key} must be a positive integer`);
  return Number(value);
};
const resourceRoots = (value: string, key: string): string[] => {
  const roots = resourceList(value);
  if (!roots.length || roots.some((root) => !isCanonicalRoot(root))) throw new Error(`${key} must contain . or canonical absolute paths`);
  return roots;
};
const resourceEnum = (name: string, key: string, outputKey: string, value: string): string[] => {
  const values = resourceList(value);
  const allowed = RESOURCE_ENUMS[`${name}.${outputKey}`];
  if (allowed && values.some((entry) => !allowed.has(entry))) throw new Error(`${key} contains an unsupported value`);
  return values;
};
const RESOURCE_VALUE_PARSERS: Array<[Set<string>, (value: string, key: string) => unknown]> = [
  [RESOURCE_BOOLEAN_OUTPUT_KEYS, (value, key) => boolean(value, key, true)],
  [RESOURCE_NUMERIC_OUTPUT_KEYS, resourceNumber],
  [RESOURCE_ACTION_OUTPUT_KEYS, resourceActionList],
  [RESOURCE_ROOT_OUTPUT_KEYS, resourceRoots],
  [RESOURCE_SCALAR_OUTPUT_KEYS, (value, key) => required(value.trim(), key)],
];
const parseResourceValue = (name: string, key: string, outputKey: string, value: string): unknown => {
  const parser = RESOURCE_VALUE_PARSERS.find(([keys]) => keys.has(outputKey))?.[1];
  return parser ? parser(value, key) : resourceEnum(name, key, outputKey, value);
};

const validateResourceValues = (result: Record<string, unknown>): void => {
  for (const [field, value] of Object.entries(result)) {
    if (Array.isArray(value) && value.length === 0) throw new Error(`${field} must contain at least one entry`);
  }
};
const validateResourceRequirements = (name: string, config: { required: string[] }, result: Record<string, unknown>): void => {
  for (const requiredKey of config.required) if (!(requiredKey in result)) throw new Error(`## ${name} requires ${requiredKey}`);
  if (result.requireShim !== true) throw new Error(`## ${name} requires requireShim: true`);
};
const validatesOperationApprovals = (name: string): boolean => name === "git" || name === "database";
const validateResourceOperationApprovals = (name: string, result: Record<string, unknown>): void => {
  if (!validatesOperationApprovals(name)) return;
  const allowed = result.allowedOperations as string[];
  const approval = result.requireApproval as string[] | undefined;
  if (approval?.some((operation) => !allowed.includes(operation))) throw new Error("require_approval must be a subset of allowed_operations");
};
const validateDatabaseResources = (name: string, result: Record<string, unknown>): void => {
  if (name === "database" && (result.allowedResources as string[]).includes("*")) throw new Error("allowed_resources cannot contain bare *");
};
const validateResourceResult = (name: string, config: { required: string[] }, result: Record<string, unknown>): void => {
  validateResourceValues(result);
  validateResourceRequirements(name, config, result);
  validateResourceOperationApprovals(name, result);
  validateDatabaseResources(name, result);
};

const parseResourceLine = (name: string, line: string): [string, string] => {
  const match = line.match(/^([\w.]+):\s*(.*)$/);
  const key = match?.[1];
  const value = match?.[2];
  if (key === undefined || value === undefined) throw new Error(`Unrecognized ${name} policy line: ${line}`);
  return [key, value];
};
const uniqueResourceKey = (seen: Set<string>, name: string, key: string): void => {
  if (seen.has(key)) throw new Error(`Duplicate ${name} policy key: ${key}`);
  seen.add(key);
};
const parseResource = (name: string, lines: string[]): Record<string, unknown> => {
  const config = RESOURCE_CONFIG[name];
  if (!config) throw new Error(`Unrecognized policy block ## ${name}`);
  const result: Record<string, unknown> = {};
  const seen = new Set<string>();
  for (const [key, value] of lines.map((line) => parseResourceLine(name, line))) {
    uniqueResourceKey(seen, name, key);
    const outputKey = config.keys[key];
    if (!outputKey) throw new Error(`Unrecognized ${name} policy key: ${key}`);
    result[outputKey] = parseResourceValue(name, key, outputKey, value);
  }
  validateResourceResult(name, config, result);
  return result;
};

function stripIntent(path: string): string { return path.startsWith("intent.") ? path.slice(7) : path; }
const isEmptyPolicySection = (value: unknown): boolean => {
  if (!value || typeof value !== "object") return false;
  return Object.keys(value).length === 0;
};
const retainPolicyEntry = ([key, value]: [string, unknown]): boolean =>
  key === "version" || !isEmptyPolicySection(value);
const removeEmpty = (policy: ParsedPolicy): ParsedPolicy =>
  Object.fromEntries(Object.entries(policy).filter(retainPolicyEntry)) as ParsedPolicy;

type PolicySectionParser = (lines: string[], isV2: boolean, body: string) => Partial<ParsedPolicy>;
const POLICY_SECTION_PARSERS: Record<string, PolicySectionParser> = {
  evm: (lines, isV2, body) => ({ evm: parseEvm(lines, isV2, body) }),
  tool_calls: (lines, isV2) => ({ tool_calls: parseToolCalls(lines, isV2) }),
  custom: (lines, isV2) => {
    const custom = parseCustom(lines, isV2);
    return custom === undefined ? {} : { custom };
  },
  mcp: (lines, isV2) => ({ mcp: parseMcp(lines, isV2) }),
  soft_limits: (lines, isV2) => ({ soft_limits: parseSoftLimits(lines, isV2) }),
  execution_limits: (lines, isV2) => ({ execution_limits: parseExecutionLimits(lines, isV2) }),
};
const resourceSectionResult = (name: string, lines: string[]): Partial<ParsedPolicy> => {
  const resource = parseResource(name, lines);
  if (name === "repository") return { repository: resource };
  if (name === "filesystem") return { filesystem: resource };
  if (name === "git") return { git: resource };
  return { database: resource };
};
const parsePolicySection = (section: Section, isV2: boolean): Partial<ParsedPolicy> => {
  const lines = cleanedLines(section.body);
  const parser = POLICY_SECTION_PARSERS[section.name];
  if (parser) return parser(lines, isV2, section.body);
  return resourceSectionResult(section.name, lines);
};
const assertPolicyCompatibility = (version: string, isV2: boolean, structural: string, sections: Section[]): void => {
  if (V2_ONLY.test(structural) && !isV2) throw new Error("Policy syntax requires version 2.0.0");
  if (version !== "2.1.0" && sections.some((section) => RESOURCE_SECTIONS.has(section.name))) {
    throw new Error("Policy 2.1 resource profiles require version 2.1.0");
  }
};
const parsePolicySections = (version: string, isV2: boolean, sections: Section[]): ParsedPolicy => {
  const result: ParsedPolicy = { version };
  for (const section of sections) Object.assign(result, parsePolicySection(section, isV2));
  return result;
};

export const parsePolicyMarkdown = (markdown: string): ParsedPolicy => {
  const unsigned = splitSignatureBlock(markdown).unsigned;
  const structural = maskHtmlComments(unsigned);
  if (/^ {1,3}##\s+\S.*$/m.test(structural)) throw new Error("Indented policy headings are not supported");
  const version = parseVersion(unsigned);
  const isV2 = version === "2.0.0" || version === "2.1.0";
  const sections = sectionsOf(structural);
  assertPolicyCompatibility(version, isV2, structural, sections);
  return removeEmpty(parsePolicySections(version, isV2, sections));
};
