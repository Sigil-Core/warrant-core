import type { ParsedPolicy } from "./types.js";
import { splitSignatureBlock } from "./signature.js";

const HTTP_METHODS = new Set(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]);
const V2_ONLY = /^(?:\s*allow_only(?:\[action=[^\]]+\])?\.[^\s:]+\s+(?:attested\s+)?(?:contains|starts_with|prefix|ends_with|matches|equals)\s*:|\s*http\.(?:allowed_methods|allowed_hosts|blocked_methods):|\s*cap\.[A-Za-z0-9_-]+\.)/m;
const KNOWN_SECTIONS = new Set(["evm", "tool_calls", "custom", "mcp", "soft_limits", "execution_limits", "repository", "filesystem", "git", "database"]);
const RESOURCE_SECTIONS = new Set(["repository", "filesystem", "git", "database"]);
const ACTION_PATTERN = (value: string) => Boolean(value) && (!value.includes("*") || (value.endsWith("*") && value.indexOf("*") === value.length - 1));
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
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

export function parsePolicyMarkdown(markdown: string): ParsedPolicy {
  const unsigned = splitSignatureBlock(markdown).unsigned;
  const version = parseVersion(unsigned);
  const isV2 = version === "2.0.0" || version === "2.1.0";
  const sections = sectionsOf(unsigned);
  if (V2_ONLY.test(unsigned) && !isV2) throw new Error("Policy syntax requires version 2.0.0");
  if (version !== "2.1.0" && sections.some((section) => RESOURCE_SECTIONS.has(section.name))) {
    throw new Error("Policy 2.1 resource profiles require version 2.1.0");
  }
  const result: ParsedPolicy = { version };
  for (const section of sections) {
    const lines = cleanedLines(section.body);
    if (section.name === "evm") result.evm = parseEvm(lines, isV2);
    else if (section.name === "tool_calls") result.tool_calls = parseToolCalls(lines, isV2);
    else if (section.name === "custom") result.custom = parseCustom(lines, isV2);
    else if (section.name === "mcp") result.mcp = parseMcp(lines, isV2);
    else if (section.name === "soft_limits") result.soft_limits = parseSoftLimits(lines, isV2);
    else if (section.name === "execution_limits") result.execution_limits = parseExecutionLimits(lines, isV2);
    else if (RESOURCE_SECTIONS.has(section.name)) (result as unknown as Record<string, unknown>)[section.name] = parseResource(section.name, lines);
  }
  const parsed = removeEmpty(result);
  const modelBudget = parsed.execution_limits?.maxModelSpendUsdPerTask !== undefined
    || parsed.execution_limits?.maxModelTokensPerTask !== undefined;
  const enforceable = parsed.evm !== undefined
    || parsed.tool_calls !== undefined
    || parsed.custom !== undefined
    || parsed.mcp !== undefined
    || (isV2 && parsed.soft_limits !== undefined)
    || modelBudget
    || parsed.repository !== undefined
    || parsed.filesystem !== undefined
    || parsed.git !== undefined
    || parsed.database !== undefined;
  if (!enforceable) throw new Error("warranty.md must contain an enforceable policy block");
  return parsed;
}

interface Section { name: string; body: string; }

function sectionsOf(markdown: string): Section[] {
  const headers = [...markdown.matchAll(/^##\s+(.+?)\s*$/gm)].map((match) => ({ name: match[1]!.trim().toLowerCase(), start: match.index!, end: match.index! + match[0].length }));
  const seen = new Set<string>();
  return headers.map((header, index) => {
    if (!KNOWN_SECTIONS.has(header.name)) throw new Error(`Unknown policy block ## ${header.name}`);
    if (seen.has(header.name)) throw new Error(`Duplicate policy block ## ${header.name}`);
    seen.add(header.name);
    return { name: header.name, body: markdown.slice(header.end, headers[index + 1]?.start ?? markdown.length).trim() };
  });
}

function parseVersion(markdown: string): string {
  const firstSection = markdown.search(/^##\s+/m);
  const root = firstSection < 0 ? markdown : markdown.slice(0, firstSection);
  const withoutHtmlComments = root.replace(/<!--[\s\S]*?-->/g, "");
  if (withoutHtmlComments.includes("<!--") || withoutHtmlComments.includes("-->")) {
    throw new Error("Unterminated HTML comment before the first policy block");
  }
  const values: string[] = [];
  for (const line of withoutHtmlComments.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const match = line.match(/^\s*version:\s*(.+)$/i);
    if (match) {
      values.push(match[1]!.trim());
      continue;
    }
    const unquotedMarkdown = trimmed.replace(/^(?:[-*+>]\s*)+/, "");
    if (/^version(?:\s*[:=]|\s*$|\s+\d)/i.test(unquotedMarkdown)) {
      throw new Error(`Invalid root version declaration: ${trimmed}`);
    }
    if (/^\s*[A-Za-z_][\w-]*\s*:/.test(line)) {
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

function boolean(value: string, key: string, strict: boolean): boolean {
  const normalized = value.trim().toLowerCase();
  if (strict && normalized !== "true" && normalized !== "false") throw new Error(`${key} must be true or false`);
  return normalized === "true";
}

function number(value: string): number | undefined {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

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

function parseEvm(lines: string[], isV2: boolean): Record<string, unknown> {
  const result: Record<string, unknown> = { maxTransactionEth: 5 };
  const tokens: Record<string, Record<string, unknown>> = {};
  const chainActions: Record<string, string[]> = {};
  const genericControls = new Set<string>();
  let chains = false;
  for (const line of lines) {
    if (line === "chain_actions:") { chains = true; continue; }
    if (chains && /^"?[^":]+"?:\s*.+$/.test(line) && !/^(max_|allowed_|consensus_|token\.)/.test(line)) {
      const match = line.match(/^"?([^":]+)"?:\s*(.+)$/)!;
      chainActions[match[1]!] = list(match[2]!);
      continue;
    }
    chains = false;
    const token = line.match(/^token\.([A-Za-z0-9_]+)\.(max_transaction|consensus_threshold|decimals|addresses):\s*(.+)$/);
    if (token) {
      const profile = tokens[token[1]!.toUpperCase()] ??= {};
      if (token[2] === "decimals") profile.decimals = integer(token[3]!);
      else if (token[2] === "addresses") profile.addresses = [...new Set([...(profile.addresses as string[] ?? []), ...list(token[3]!).map((entry) => entry.toLowerCase())])];
      else if (token[2] === "max_transaction") profile.maxTransaction = token[3]!.trim();
      else profile.consensusThreshold = token[3]!.trim();
      continue;
    }
    const [key, value] = requireKeyValue(line, "EVM");
    if (parseGenericControl(result, key, value, isV2, genericControls)) continue;
    if (key === "max_transaction_eth") {
      const parsed = number(value);
      if (parsed === undefined || parsed <= 0) throw new Error("max_transaction_eth must be greater than zero");
      result.maxTransactionEth = parsed;
    }
    else if (key === "allowed_actions") result.allowedActions = list(value);
    else if (key === "allowed_chains") result.allowedChains = list(value).map(integer).filter((entry): entry is number => entry !== undefined && entry > 0);
    else if (key === "consensus_threshold_eth") result.consensusThresholdEth = number(value);
    else if (key === "consensus_require_hold") result.requireHold = boolean(value, key, isV2);
    else throw new Error(`Unrecognized EVM policy key: ${key}`);
  }
  if (Object.keys(chainActions).length) result.chainActions = chainActions;
  if (Object.keys(tokens).length) result.tokenRules = tokens;
  if (!Array.isArray(result.allowedActions) || result.allowedActions.length === 0) {
    throw new Error("## evm requires at least one allowed_action");
  }
  if (!Array.isArray(result.allowedChains) || result.allowedChains.length === 0) {
    throw new Error("## evm requires at least one positive allowed_chain");
  }
  return result;
}

function parseToolCalls(lines: string[], isV2: boolean): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of unique(lines, "tool_calls")) {
    if (parseGenericControl(result, key, value, isV2)) continue;
    if (key === "allowed") result.allowed = list(value);
    else if (key === "bash.blocked_commands") result.bashBlockedCommands = list(value);
    else if (key === "web_fetch.blocked_domains") result.webFetchBlockedDomains = list(value);
    else if (key === "file_write.blocked_paths") result.fileWriteBlockedPaths = list(value);
    else if (key === "email.require_approval") result.emailRequireApproval = boolean(value, key, isV2);
    else if (key === "email.allowed_recipients") result.emailAllowedRecipients = list(value).map((entry) => entry.toLowerCase());
    else if (key === "email.blocked_recipients") result.emailBlockedRecipients = list(value).map((entry) => entry.toLowerCase());
    else if (key === "http.allowed_methods" || key === "http.blocked_methods") {
      if (!isV2) throw new Error("http policy keys require version 2.0.0");
      const methods = list(value); if (!methods.length || methods.some((method) => !HTTP_METHODS.has(method))) throw new Error(`${key} must contain only uppercase HTTP methods (GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE)`);
      result[key === "http.allowed_methods" ? "httpAllowedMethods" : "httpBlockedMethods"] = [...new Set(methods)];
    } else if (key === "http.allowed_hosts") {
      if (!isV2) throw new Error("http policy keys require version 2.0.0");
      const hosts = list(value).map((entry) => entry.toLowerCase());
      if (!hosts.length || hosts.some((host) => !/^(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host))) throw new Error("http.allowed_hosts must contain valid lowercase host names (use *.example.com for subdomains)");
      result.httpAllowedHosts = [...new Set(hosts)];
    } else throw new Error(`Unrecognized tool_calls policy key: ${key}`);
  }
  if (!Array.isArray(result.allowed) || result.allowed.length === 0) {
    throw new Error("## tool_calls requires at least one allowed tool");
  }
  return result;
}

function parseCustom(lines: string[], isV2: boolean): { rules: Array<Record<string, unknown>>; requireApproval?: string[]; requireShim?: boolean } {
  const rules: Array<Record<string, unknown>> = [];
  const controls: Record<string, unknown> = {};
  const genericControls = new Set<string>();
  const allows = new Map<string, Record<string, unknown>>();
  const operators = new Map<string, string>();
  for (const line of lines) {
    const generic = line.match(/^(require_approval|require_shim):\s*(.+)$/);
    if (generic) {
      parseGenericControl(controls, generic[1]!, generic[2]!, isV2, genericControls);
      continue;
    }
    const allow = line.match(/^allow_only(?:\[action=([^\]]*)\])?\.([^\s:]+)(?:\s+(attested))?(?:\s+(contains|starts_with|prefix|ends_with|matches|equals))?\s*:\s*(.*)$/);
    if (allow) {
      if (!isV2 && (allow[1] || allow[3] || allow[4])) throw new Error("Policy syntax requires version 2.0.0");
      const actionScope = allow[1]?.trim(); if (actionScope === "") throw new Error("allow_only action scope must not be empty");
      const fieldPath = stripIntent(allow[2]!); const operator = allow[4] === "prefix" ? "starts_with" : (allow[4] ?? "equals"); const values = list(allow[5]!);
      if (!values.length) throw new Error(`allow_only.${fieldPath} must contain at least one value`);
      const scope = `${actionScope ?? "<global>"}::${fieldPath}`;
      if (operators.has(scope) && operators.get(scope) !== operator) throw new Error(`allow_only.${fieldPath} mixes operators (${operators.get(scope)}, ${operator}); use one operator per field and action scope`);
      operators.set(scope, operator); const key = `${scope}::${operator}`; const existing = allows.get(key);
      if (existing) { if (Boolean(existing.attested) !== Boolean(allow[3])) throw new Error(`allow_only.${fieldPath} mixes attested and non-attested rules; use one provenance mode per field and action scope`); existing.values = [...new Set([...(existing.values as string[]), ...values])]; }
      else { const rule: Record<string, unknown> = { name: actionScope ? `allow_only[action=${actionScope}].${fieldPath}` : `allow_only.${fieldPath}`, type: "allow_field", fieldPath, ...(actionScope ? { actionScope } : {}), ...(allow[3] ? { attested: true } : {}), ...(operator !== "equals" ? { operator } : {}), values }; allows.set(key, rule); rules.push(rule); }
      continue;
    }
    const deny = line.match(/^deny_if\.(\S+)\s+(contains|starts_with|ends_with|matches|equals|not_equals)\s+(.+)$/);
    if (deny) { const fieldPath = stripIntent(deny[1]!); const value = unquote(deny[3]!); rules.push({ name: `deny_if.${fieldPath}.${deny[2]}:${value}`, type: "field", fieldPath, operator: deny[2]!, value }); continue; }
    const string = line.match(/^deny_string:\s*(.+)$/);
    if (string) { const value = unquote(string[1]!); rules.push({ name: `deny_string:${value}`, type: "deny_string", value }); continue; }
    if (isV2) throw new Error(`Unrecognized custom rule: ${line}`);
  }
  return { rules, ...(controls.requireApproval ? { requireApproval: controls.requireApproval as string[] } : {}), ...(controls.requireShim !== undefined ? { requireShim: controls.requireShim as boolean } : {}) };
}

function parseMcp(lines: string[], isV2: boolean): Record<string, unknown> {
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
  if (allowed && blocked) { const overlap = allowed.filter((entry) => blocked.includes(entry)); if (overlap.length) throw new Error(`MCP policy lists the same tool in both allowed_tools and blocked_tools: ${overlap.join(", ")}`); }
  return result;
}

function actionList(value: string, key: string): string[] { const values = list(value); if (!values.length || values.some((entry) => !ACTION_PATTERN(entry))) throw new Error(`${key} must contain exact values or one trailing * wildcard`); return [...new Set(values)]; }
function resourceActionList(value: string, key: string): string[] { const values = resourceList(value); if (!values.length || values.some((entry) => !ACTION_PATTERN(entry))) throw new Error(`${key} must contain exact values or one trailing * wildcard`); return [...new Set(values)]; }

function parseSoftLimits(lines: string[], isV2: boolean): Record<string, unknown> {
  const result: Record<string, unknown> = {}; const caps: Record<string, Record<string, unknown>> = {}; const genericControls = new Set<string>();
  let hasLimit = false;
  for (const line of lines) {
    const cap = line.match(/^cap\.([A-Za-z0-9_-]+)\.(max_count|max_sum_usd|window|action|group_by|amount_field):\s*(.*?)\s*$/);
    if (cap) { if (!isV2) throw new Error("Named soft_limits caps require version 2.0.0"); const profile = caps[cap[1]!] ??= {}; const field = cap[2]!; if (field in profile) throw new Error(`Duplicate soft_limits cap key: ${cap[1]}.${field}`); const value = unquote(cap[3]!); if (field === "max_count") { if (!positiveInt(value)) throw new Error(`cap.${cap[1]}.max_count must be a positive integer`); profile.maxCount = Number(value); } else if (field === "max_sum_usd") { if (!positiveDecimal(value)) throw new Error(`cap.${cap[1]}.max_sum_usd must be a positive USD decimal with at most 6 places`); profile.maxSumUsd = value; } else if (field === "window") { if (!["day", "hour", "task"].includes(value)) throw new Error(`cap.${cap[1]}.window must be day, hour, or task`); profile.window = value; } else if (field === "action") { if (!ACTION_PATTERN(value)) throw new Error(`cap.${cap[1]}.action supports only an exact value or one trailing * wildcard`); profile.action = value; } else if (field === "group_by") profile.groupBy = required(value, `cap.${cap[1]}.group_by`); else profile.amountField = required(value, `cap.${cap[1]}.amount_field`); continue; }
    if (line.startsWith("cap.")) throw new Error(`Unrecognized soft_limits policy key: ${line.split(":", 1)[0]}`);
    const [key, value] = requireKeyValue(line, "soft_limits");
    if (parseGenericControl(result, key, value, isV2, genericControls)) continue;
    if (key === "daily_tool_calls") { if (isV2 && !positiveInt(value)) throw new Error("daily_tool_calls must be a positive integer under version 2.0.0"); result.dailyToolCalls = integer(value); hasLimit = true; }
    else if (key === "daily_evm_limit_eth") { if (isV2 && !positiveDecimal(value)) throw new Error("daily_evm_limit_eth must be a positive decimal with at most 6 places under version 2.0.0"); result.dailyEvmLimitEth = number(value); hasLimit = true; }
    else throw new Error(`Unrecognized soft_limits policy key: ${key}`);
  }
  for (const [name, cap] of Object.entries(caps)) { if ((cap.maxCount === undefined) === (cap.maxSumUsd === undefined)) throw new Error(`cap.${name} requires exactly one of max_count or max_sum_usd`); if (!cap.window || !cap.action) throw new Error(`cap.${name}.window and cap.${name}.action are required`); if (cap.maxSumUsd !== undefined && !cap.amountField) throw new Error(`cap.${name}.amount_field is required for sum caps`); if (cap.maxCount !== undefined && cap.amountField) throw new Error(`cap.${name}.amount_field is not valid for count caps`); }
  if (Object.keys(caps).length) { result.caps = caps; hasLimit = true; }
  if (isV2 && !hasLimit) throw new Error("## soft_limits must declare at least one enforced limit under version 2.0.0");
  return result;
}

function parseExecutionLimits(lines: string[], isV2: boolean): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  let hasLimit = false;
  for (const [key, value] of unique(lines, "execution_limits")) {
    if (parseGenericControl(result, key, value, isV2)) continue;
    if (key === "max_tool_calls_per_task" && positiveInt(value)) {
      result.maxToolCallsPerTask = Number(value);
      hasLimit = true;
    } else if (key === "max_tool_calls_per_hour" && positiveInt(value)) {
      result.maxToolCallsPerHour = Number(value);
      hasLimit = true;
    } else if (key === "max_model_spend_usd_per_task" && positiveDecimal(value)) {
      result.maxModelSpendUsdPerTask = unquote(value);
      hasLimit = true;
    } else if (key === "max_model_tokens_per_task" && positiveInt(value)) {
      result.maxModelTokensPerTask = Number(value);
      hasLimit = true;
    } else {
      throw new Error(`Unrecognized execution_limits policy key: ${key}`);
    }
  }
  return hasLimit ? result : {};
}

function parseResource(name: string, lines: string[]): Record<string, unknown> {
  const config = RESOURCE_CONFIG[name]!; const result: Record<string, unknown> = {};
  for (const [key, value] of unique(lines, name)) {
    const outputKey = config.keys[key]; if (!outputKey) throw new Error(`Unrecognized ${name} policy key: ${key}`);
    if (["requireShim", "blockOutsideWrites", "protectGitHistory", "protectSensitiveFiles", "requireReadOnlyForSelect", "denyUnreviewedIndirectEffects"].includes(outputKey)) result[outputKey] = boolean(value, key, true);
    else if (outputKey.startsWith("max") || outputKey.endsWith("TimeoutMs")) { if (!positiveInt(value)) throw new Error(`${key} must be a positive integer`); result[outputKey] = Number(value); }
    else if (["actions", "filesystemActions", "blockedPaths", "allowedResources", "protectedRefs"].includes(outputKey)) result[outputKey] = resourceActionList(value, key);
    else if (["roots", "writeRoots", "readRoots"].includes(outputKey)) { const roots = resourceList(value); if (!roots.length || roots.some((root) => !isCanonicalRoot(root))) throw new Error(`${key} must contain . or canonical absolute paths`); result[outputKey] = roots; }
    else if (outputKey === "routineCatalog" || outputKey === "protectedClassCatalog") result[outputKey] = required(value.trim(), key);
    else {
      const values = resourceList(value);
      const allowed = RESOURCE_ENUMS[`${name}.${outputKey}`];
      if (allowed && values.some((entry) => !allowed.has(entry))) throw new Error(`${key} contains an unsupported value`);
      result[outputKey] = values;
    }
  }
  for (const requiredKey of config.required) if (!(requiredKey in result)) throw new Error(`## ${name} requires ${requiredKey}`);
  for (const requiredKey of config.required) {
    const value = result[requiredKey];
    if (Array.isArray(value) && value.length === 0) throw new Error(`${requiredKey} must contain at least one entry`);
  }
  if (result.requireShim !== true) throw new Error(`## ${name} requires requireShim: true`);
  if (name === "git" || name === "database") {
    const allowed = result.allowedOperations as string[];
    const approval = result.requireApproval as string[] | undefined;
    if (approval?.some((operation) => !allowed.includes(operation))) {
      throw new Error("require_approval must be a subset of allowed_operations");
    }
  }
  if (name === "database" && (result.allowedResources as string[]).includes("*")) {
    throw new Error("allowed_resources cannot contain bare *");
  }
  return result;
}

function stripIntent(path: string): string { return path.startsWith("intent.") ? path.slice(7) : path; }
function parseGenericControl(result: Record<string, unknown>, key: string, value: string, isV2: boolean, seen?: Set<string>): boolean {
  if (key !== "require_approval" && key !== "require_shim") return false;
  if (!isV2) throw new Error("Policy syntax requires version 2.0.0");
  if (seen?.has(key)) throw new Error(`Duplicate policy key: ${key}`);
  seen?.add(key);
  if (key === "require_approval") result.requireApproval = actionList(value, key);
  else result.requireShim = boolean(value, key, true);
  return true;
}
function isCanonicalRoot(value: string): boolean {
  return value === "." || value === "/" || (value.startsWith("/") && !value.endsWith("/") && !value.includes("//") && value.split("/").every((segment) => segment !== "." && segment !== ".."));
}
function positiveInt(value: string): boolean { const raw = value.trim(); return /^\d+$/.test(raw) && BigInt(raw) >= 1n && BigInt(raw) <= MAX_SAFE; }
function positiveDecimal(value: string): boolean { return /^(0|[1-9]\d*)(?:\.\d{1,6})?$/.test(unquote(value.trim())) && Number(unquote(value.trim())) > 0; }
function required(value: string, key: string): string { if (!value) throw new Error(`${key} must not be empty`); return value; }
function removeEmpty(policy: ParsedPolicy): ParsedPolicy { for (const key of Object.keys(policy) as Array<keyof ParsedPolicy>) if (key !== "version" && policy[key] && typeof policy[key] === "object" && !Object.keys(policy[key] as object).length) delete policy[key]; return policy; }
