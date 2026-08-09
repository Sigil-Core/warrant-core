import {
  AUTHORING_CAPABILITY_MANIFEST,
  capabilityValuesForPath,
  isCapabilityAvailable,
  policyVersionRange,
  runRepresentabilityConstraints,
  type AuthoringCapabilityPath,
  type AuthoringSurface,
  type CapabilityDimension,
} from "./capabilities.js";
import { maskHtmlComments } from "./html-comments.js";
import { parsePolicyMarkdown } from "./policy.js";
import type { ParsedPolicy } from "./types.js";

export type WarrantySurfaceHint =
  | "invalid-policy"
  | "use-manual-advanced"
  | "surface-constraint"
  | "unsigned-placeholder";

export type WarrantyValidationCode =
  | "WARRANT_INVALID_POLICY"
  | "WARRANT_INVALID_VERSION"
  | "WARRANT_UNSUPPORTED_VERSION"
  | "WARRANT_UNSUPPORTED_FIELD_VERSION"
  | "WARRANT_UNSUPPORTED_KEY"
  | "WARRANT_DUPLICATE_FIELD"
  | "WARRANT_INVALID_VALUE"
  | "WARRANT_PROFILE_FIELD_MISSING"
  | "WARRANT_SURFACE_CANNOT_AUTHOR"
  | "WARRANT_SURFACE_CANNOT_IMPORT"
  | "WARRANT_SURFACE_CANNOT_PRESERVE"
  | "WARRANT_SURFACE_CANNOT_DEPLOY"
  | "WARRANT_SURFACE_CONSTRAINT"
  | "WARRANT_ENVELOPE_INVALID_UTF8"
  | "WARRANT_ENVELOPE_DUPLICATE_HEADER"
  | "WARRANT_ENVELOPE_TRAILING_CONTENT"
  | "WARRANT_ENVELOPE_DUPLICATE_SIGNATURE"
  | "WARRANT_ENVELOPE_SIGNATURE_MISSING"
  | "WARRANT_ENVELOPE_EMPTY_POLICY"
  | "WARRANT_ENVELOPE_UNEXPECTED_HEADER";

export interface WarrantyValidationError {
  readonly code: WarrantyValidationCode;
  readonly path: string;
  readonly message: string;
  readonly surface_hint: WarrantySurfaceHint;
}

export interface WarrantyValidationOptions {
  readonly surface?: AuthoringSurface;
  readonly dimension?: CapabilityDimension;
  readonly require_preservation?: boolean;
  readonly envelope_mode?: "any" | "signed" | "unsigned-signing";
}

export interface WarrantyValidationResult {
  readonly policy?: ParsedPolicy;
  readonly errors: readonly WarrantyValidationError[];
}

interface EnvelopeInspection {
  readonly markdown?: string;
  readonly unsigned?: string;
  readonly has_signature_header: boolean;
  readonly errors: readonly WarrantyValidationError[];
}

const SIGNATURE_HEADER = /^##[ \t]+signature[ \t]*\r?$/gim;
const SIGNATURE_LINE = /^[ \t]*sigil-sig:[ \t]*([A-Za-z0-9_-]+)[ \t]*\r?$/;
const KNOWN_SECTIONS = new Set([
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
]);
const PROFILE_PATH_PREFIX: Readonly<Record<string, string>> = {
  repository: "profile.repository",
  filesystem: "profile.filesystem",
  git: "profile.git",
  database: "profile.database",
};
const FIXED_SECTION_KEYS: Readonly<Record<string, ReadonlySet<string>>> = {
  evm: new Set([
    "max_transaction_eth",
    "allowed_actions",
    "allowed_chains",
    "chain_actions",
    "consensus_threshold_eth",
    "consensus_require_hold",
    "require_approval",
    "require_shim",
    "require_calldata_enrichment",
    "calldata_unknown_selector",
  ]),
  tool_calls: new Set([
    "allowed",
    "bash.blocked_commands",
    "web_fetch.blocked_domains",
    "file_write.blocked_paths",
    "email.require_approval",
    "email.allowed_recipients",
    "email.blocked_recipients",
    "http.allowed_methods",
    "http.blocked_methods",
    "http.allowed_hosts",
    "require_approval",
    "require_shim",
  ]),
  mcp: new Set([
    "allowed_servers",
    "allowed_tools",
    "blocked_tools",
    "require_approval",
    "require_shim",
    "response.web_fetch_tools",
    "response.http_tools",
    "response.deterministic_ruleset",
    "response.block_classes",
  ]),
  soft_limits: new Set([
    "daily_evm_limit_eth",
    "daily_tool_calls",
    "require_approval",
    "require_shim",
  ]),
  execution_limits: new Set([
    "max_tool_calls_per_task",
    "max_tool_calls_per_hour",
    "max_model_spend_usd_per_task",
    "max_model_tokens_per_task",
    "require_approval",
    "require_shim",
  ]),
  repository: new Set([
    "roots",
    "block_outside_writes",
    "protect_git_history",
    "protect_sensitive_files",
    "git_providers",
    "require_shim",
  ]),
  filesystem: new Set([
    "actions",
    "write_roots",
    "read_roots",
    "allowed_effects",
    "blocked_paths",
    "protected_file_classes",
    "protected_class_catalog",
    "protected_effects",
    "max_files_per_action",
    "max_bytes_written_per_task",
    "max_bytes_deleted_per_task",
    "max_destructive_effects_per_task",
    "require_shim",
  ]),
  git: new Set([
    "actions",
    "filesystem_actions",
    "providers",
    "allowed_remote_schemes",
    "allowed_operations",
    "require_approval",
    "blocked_operations",
    "protected_refs",
    "max_ref_changes_per_task",
    "require_shim",
  ]),
  database: new Set([
    "actions",
    "protected_environments",
    "allowed_operations",
    "require_approval",
    "allowed_resources",
    "routine_catalog",
    "require_read_only_for_select",
    "deny_unreviewed_indirect_effects",
    "max_schema_changes_per_task",
    "statement_timeout_ms",
    "lock_timeout_ms",
    "require_shim",
  ]),
};

const issue = (
  code: WarrantyValidationCode,
  path: string,
  message: string,
  surfaceHint: WarrantySurfaceHint = "invalid-policy",
): WarrantyValidationError => ({
  code,
  path,
  message,
  surface_hint: surfaceHint,
});

const decodeInput = (raw: string | Uint8Array): { markdown?: string; error?: WarrantyValidationError } => {
  if (typeof raw === "string") return { markdown: raw };
  try {
    return {
      markdown: new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw),
    };
  } catch {
    return {
      error: issue(
        "WARRANT_ENVELOPE_INVALID_UTF8",
        "signature",
        "Warrant envelope contains malformed UTF-8",
      ),
    };
  }
};

// skipcq: JS-R1005 - Envelope branches preserve distinct signature errors and strict final-block checks.
const inspectEnvelope = (
  raw: string | Uint8Array,
  mode: NonNullable<WarrantyValidationOptions["envelope_mode"]>,
): EnvelopeInspection => {
  const decoded = decodeInput(raw);
  if (decoded.error !== undefined) return { has_signature_header: false, errors: [decoded.error] };
  const markdown = decoded.markdown ?? "";
  let masked: string;
  try {
    masked = maskHtmlComments(markdown);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      markdown,
      unsigned: markdown,
      has_signature_header: false,
      errors: [issue("WARRANT_INVALID_POLICY", "document", message)],
    };
  }
  const headers = [...masked.matchAll(SIGNATURE_HEADER)];
  const errors: WarrantyValidationError[] = [];
  if (headers.length === 0) {
    if (mode === "signed") {
      errors.push(
        issue(
          "WARRANT_ENVELOPE_UNEXPECTED_HEADER",
          "signature",
          "Signed Warrant envelope is missing its signature header",
        ),
      );
    }
    return { markdown, unsigned: markdown, has_signature_header: false, errors };
  }
  if (mode === "unsigned-signing") {
    errors.push(
      issue(
        "WARRANT_ENVELOPE_UNEXPECTED_HEADER",
        "signature",
        "Unsigned Warrant source must not contain a signature header",
      ),
    );
  }
  if (headers.length > 1) {
    errors.push(
      issue(
        "WARRANT_ENVELOPE_DUPLICATE_HEADER",
        "signature",
        "Warrant envelope contains duplicate signature headers",
      ),
    );
  }

  const first = headers[0];
  if (first === undefined) return { markdown, unsigned: markdown, has_signature_header: false, errors };
  const headerIndex = first.index ?? 0;
  const unsigned = markdown.slice(0, headerIndex).replace(/[ \t\r\n]+$/, "");
  if (unsigned.length === 0) {
    errors.push(
      issue(
        "WARRANT_ENVELOPE_EMPTY_POLICY",
        "signature",
        "Warrant envelope contains an empty policy payload",
      ),
    );
  }

  const tail = markdown.slice(headerIndex + first[0].length);
  let signatureCount = 0;
  let trailingContent = false;
  for (const line of tail.split("\n")) {
    const signature = line.match(SIGNATURE_LINE);
    if (signature !== null) {
      signatureCount += 1;
      continue;
    }
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (/^#{2,}[ \t]+\S/.test(trimmed)) {
      trailingContent = true;
      continue;
    }
    if (trimmed.startsWith("#")) continue;
    trailingContent = true;
  }
  if (signatureCount === 0 && !trailingContent && mode === "signed") {
    errors.push(
      issue(
        "WARRANT_ENVELOPE_SIGNATURE_MISSING",
        "signature.sigil-sig",
        "Signature block contains no sigil-sig value and is not a verification candidate",
        "unsigned-placeholder",
      ),
    );
  }
  if (signatureCount > 1) {
    errors.push(
      issue(
        "WARRANT_ENVELOPE_DUPLICATE_SIGNATURE",
        "signature.sigil-sig",
        "Warrant envelope contains duplicate sigil-sig lines",
      ),
    );
  }
  if (trailingContent) {
    errors.push(
      issue(
        "WARRANT_ENVELOPE_TRAILING_CONTENT",
        "signature",
        "Signature block must be final and contain only sigil-sig, # comments, and whitespace",
      ),
    );
  }
  return { markdown, unsigned, has_signature_header: true, errors };
};

interface SectionSlice {
  readonly name: string;
  readonly body: string;
}

const sectionSlices = (
  structural: string,
  errors: WarrantyValidationError[],
): SectionSlice[] => {
  if (/^ {1,3}##[ \t]+\S.*$/m.test(structural)) {
    errors.push(
      issue(
        "WARRANT_UNSUPPORTED_KEY",
        "document.headings",
        "Indented policy headings are not supported",
      ),
    );
  }
  const headers = [...structural.matchAll(/^##[ \t]+(.+?)[ \t]*\r?$/gm)].map(
    (match) => ({
      name: (match[1] ?? "").trim().toLowerCase(),
      start: match.index ?? 0,
      end: (match.index ?? 0) + match[0].length,
    }),
  );
  const seen = new Set<string>();
  const sections: SectionSlice[] = [];
  headers.forEach((header, index) => {
    if (!KNOWN_SECTIONS.has(header.name)) {
      errors.push(
        issue(
          "WARRANT_UNSUPPORTED_KEY",
          header.name || "document.heading",
          `Unknown policy block ## ${header.name}`,
        ),
      );
    }
    if (seen.has(header.name)) {
      errors.push(
        issue(
          "WARRANT_DUPLICATE_FIELD",
          header.name,
          `Duplicate policy block ## ${header.name}`,
        ),
      );
    }
    seen.add(header.name);
    sections.push({
      name: header.name,
      body: structural.slice(
        header.end,
        headers[index + 1]?.start ?? structural.length,
      ),
    });
  });
  return sections;
};

// skipcq: JS-R1005 - Version outcomes retain stable error codes for each invalid or unsupported condition.
const validateRootVersion = (
  structural: string,
  errors: WarrantyValidationError[],
): string | undefined => {
  const firstSection = structural.search(/^##[ \t]+/m);
  const root = firstSection < 0 ? structural : structural.slice(0, firstSection);
  const versions = root
    .split("\n")
    .map((line) => line.match(/^[ \t]*version:[ \t]*(.*?)[ \t]*\r?$/i)?.[1])
    .filter((value): value is string => value !== undefined);
  if (versions.length > 1) {
    errors.push(
      issue(
        "WARRANT_DUPLICATE_FIELD",
        "version",
        "Duplicate version fields are not allowed",
      ),
    );
  }
  const version = versions[0]?.trim() ?? "0.0.0";
  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    errors.push(
      issue(
        "WARRANT_INVALID_VERSION",
        "version",
        `Invalid policy version "${version}"; expected semver X.Y.Z`,
      ),
    );
    return undefined;
  }
  if (policyVersionRange(version) === undefined) {
    errors.push(
      issue(
        "WARRANT_UNSUPPORTED_VERSION",
        "version",
        `Policy version ${version} is newer than this engine`,
      ),
    );
  }
  return version;
};

const rawDirective = (
  line: string,
): { key: string; value: string } | undefined => {
  const match = line.match(/^[ \t]*([\w.]+):[ \t]*(.*?)[ \t]*\r?$/);
  if (match?.[1] === undefined || match[2] === undefined) return undefined;
  return { key: match[1], value: match[2] };
};

const isDynamicSectionKey = (section: string, key: string): boolean => {
  if (section === "evm") {
    return /^token\.[A-Za-z0-9_]+\.(?:max_transaction|consensus_threshold|decimals|addresses)$/.test(key);
  }
  if (section === "tool_calls") {
    return /^http\.method_rules\.(?:GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)\.(?:require_query_matches|deny)$/.test(key);
  }
  if (section === "soft_limits") {
    return /^cap\.[A-Za-z0-9_-]+\.(?:max_count|max_sum_usd|window|action|group_by|amount_field)$/.test(key);
  }
  return false;
};

const canonicalDirectivePath = (section: string, key: string): string => {
  const profilePrefix = PROFILE_PATH_PREFIX[section];
  if (profilePrefix !== undefined) return `${profilePrefix}.${key}`;
  if (section === "evm" && key.startsWith("token.")) return `evm.${key}`;
  return `${section}.${key}`;
};

// skipcq: JS-R1005 - Section scanning deliberately combines key, duplicate, and version diagnostics by directive.
const scanSection = (
  section: SectionSlice,
  version: string | undefined,
  errors: WarrantyValidationError[],
): void => {
  if (!KNOWN_SECTIONS.has(section.name)) return;
  const lines = section.body
    .split("\n")
    .filter((line) => line.trim() && !line.trimStart().startsWith("#"));
  const directives = lines
    .map(rawDirective)
    .filter((value): value is { key: string; value: string } => value !== undefined);
  const seen = new Set<string>();
  for (const directive of directives) {
    if (
      section.name === "custom"
      || (section.name === "evm" && /^\d+$/.test(directive.key))
    ) {
      continue;
    }
    const known = FIXED_SECTION_KEYS[section.name]?.has(directive.key)
      || isDynamicSectionKey(section.name, directive.key);
    const path = canonicalDirectivePath(section.name, directive.key);
    if (!known) {
      errors.push(
        issue(
          "WARRANT_UNSUPPORTED_KEY",
          path,
          `Unrecognized ${section.name} policy key: ${directive.key}`,
        ),
      );
      continue;
    }
    const duplicateIdentity = section.name === "evm"
      && /^token\.[A-Za-z0-9_]+\.addresses$/.test(directive.key)
      ? undefined
      : directive.key.toUpperCase().replace(/^TOKEN\.([^.]+)/, "TOKEN.$1");
    if (duplicateIdentity !== undefined && seen.has(duplicateIdentity)) {
      errors.push(
        issue(
          "WARRANT_DUPLICATE_FIELD",
          path,
          `Duplicate ${section.name} policy key: ${directive.key}`,
        ),
      );
    }
    if (duplicateIdentity !== undefined) seen.add(duplicateIdentity);
  }

  const versionRange = version === undefined ? undefined : policyVersionRange(version);
  const v21Only = section.name in PROFILE_PATH_PREFIX
    || directives.some((directive) =>
      directive.key === "require_calldata_enrichment"
      || directive.key === "calldata_unknown_selector"
      || directive.key.startsWith("http.method_rules.")
    );
  if (v21Only && versionRange !== undefined && versionRange !== "2.1.x" && versionRange !== "2.2.x") {
    if (section.name in PROFILE_PATH_PREFIX) {
      errors.push(
        issue(
          "WARRANT_UNSUPPORTED_FIELD_VERSION",
          PROFILE_PATH_PREFIX[section.name] ?? section.name,
          `## ${section.name} requires Policy 2.1.x`,
        ),
      );
    }
    for (const directive of directives) {
      if (
        directive.key === "require_calldata_enrichment"
        || directive.key === "calldata_unknown_selector"
        || directive.key.startsWith("http.method_rules.")
      ) {
        errors.push(
          issue(
            "WARRANT_UNSUPPORTED_FIELD_VERSION",
            canonicalDirectivePath(section.name, directive.key),
            `${directive.key} requires Policy 2.1.x`,
          ),
        );
      }
    }
  }
  const responseDirectives = directives.filter((directive) => directive.key.startsWith("response."));
  if (responseDirectives.length > 0 && versionRange !== undefined && versionRange !== "2.2.x") {
    for (const directive of responseDirectives) {
      errors.push(
        issue(
          "WARRANT_UNSUPPORTED_FIELD_VERSION",
          canonicalDirectivePath(section.name, directive.key),
          `${directive.key} requires Policy 2.2.x`,
        ),
      );
    }
  }
};

// skipcq: JS-R1005 - Ordered parser-message matching maps legacy errors to stable authoring paths.
const parserErrorPath = (message: string): string => {
  const block = message.match(/(?:block|section) ## ([\w.-]+)/i)?.[1];
  if (block !== undefined) return block.toLowerCase();
  const policyKey = message.match(/policy key: ([\w.-]+)/i)?.[1];
  if (policyKey !== undefined) return policyKey;
  const tokenKey = message.match(/(token\.[A-Za-z0-9_]+\.[\w.]+)/)?.[1];
  if (tokenKey !== undefined) return `evm.${tokenKey}`;
  const capKey = message.match(/(cap\.[A-Za-z0-9_-]+\.[\w.]+)/)?.[1];
  if (capKey !== undefined) return `soft_limits.${capKey}`;
  if (/version/i.test(message)) return "version";
  return "document";
};

// skipcq: JS-R1005 - Parser error categories map directly to documented validation codes in priority order.
const mapParserError = (error: unknown): WarrantyValidationError => {
  const message = error instanceof Error ? error.message : String(error);
  const path = parserErrorPath(message);
  if (/unsupported|unrecognized|unknown policy block/i.test(message)) {
    return issue("WARRANT_UNSUPPORTED_KEY", path, message);
  }
  if (/duplicate/i.test(message)) {
    return issue("WARRANT_DUPLICATE_FIELD", path, message);
  }
  if (/version .*not supported|newer than this engine/i.test(message)) {
    return issue("WARRANT_UNSUPPORTED_VERSION", "version", message);
  }
  if (/invalid policy version|expected semver/i.test(message)) {
    return issue("WARRANT_INVALID_VERSION", "version", message);
  }
  if (/ requires /i.test(message) && /^##/.test(message)) {
    return issue("WARRANT_PROFILE_FIELD_MISSING", path, message);
  }
  if (/must|cannot|invalid|requires|reject/i.test(message)) {
    return issue("WARRANT_INVALID_VALUE", path, message);
  }
  return issue("WARRANT_INVALID_POLICY", path, message);
};

// skipcq: JS-R1005 - Surface checks retain distinct availability, preservation, and constraint diagnostics.
const surfaceErrors = (
  policy: ParsedPolicy,
  options: WarrantyValidationOptions,
  hasSignatureHeader: boolean,
): WarrantyValidationError[] => {
  if (options.surface === undefined) return [];
  const surface = options.surface;
  const dimension = options.dimension ?? "import";
  const requirePreservation = options.require_preservation ?? dimension === "import";
  const errors: WarrantyValidationError[] = [];
  if (
    hasSignatureHeader
    && !isCapabilityAvailable("signature.sigil-envelope-v1", surface, dimension, policy.version)
  ) {
    const code = `WARRANT_SURFACE_CANNOT_${dimension.toUpperCase()}` as
      | "WARRANT_SURFACE_CANNOT_AUTHOR"
      | "WARRANT_SURFACE_CANNOT_IMPORT"
      | "WARRANT_SURFACE_CANNOT_PRESERVE"
      | "WARRANT_SURFACE_CANNOT_DEPLOY";
    errors.push(
      issue(
        code,
        "signature.sigil-envelope-v1",
        `${surface} cannot ${dimension} signature.sigil-envelope-v1`,
        surface === "manual-advanced" ? "invalid-policy" : "use-manual-advanced",
      ),
    );
  }
  for (const path of Object.keys(AUTHORING_CAPABILITY_MANIFEST) as AuthoringCapabilityPath[]) {
    if (path === "signature.sigil-envelope-v1") continue;
    const values = capabilityValuesForPath(policy, path);
    if (values.length === 0) continue;
    const entry = AUTHORING_CAPABILITY_MANIFEST[path];
    const range = policyVersionRange(policy.version);
    if (range === undefined || !entry.versions.includes(range)) {
      errors.push(
        issue(
          "WARRANT_UNSUPPORTED_FIELD_VERSION",
          path,
          `${path} is not available under Policy ${policy.version}`,
        ),
      );
      continue;
    }
    if (!isCapabilityAvailable(path, surface, dimension, policy.version)) {
      const code = `WARRANT_SURFACE_CANNOT_${dimension.toUpperCase()}` as
        | "WARRANT_SURFACE_CANNOT_AUTHOR"
        | "WARRANT_SURFACE_CANNOT_IMPORT"
        | "WARRANT_SURFACE_CANNOT_PRESERVE"
        | "WARRANT_SURFACE_CANNOT_DEPLOY";
      errors.push(
        issue(
          code,
          path,
          `${surface} cannot ${dimension} ${path}`,
          surface === "manual-advanced" ? "invalid-policy" : "use-manual-advanced",
        ),
      );
      continue;
    }
    if (
      requirePreservation
      && !isCapabilityAvailable(path, surface, "preserve", policy.version)
    ) {
      errors.push(
        issue(
          "WARRANT_SURFACE_CANNOT_PRESERVE",
          path,
          `${surface} cannot preserve ${path} losslessly`,
          surface === "manual-advanced" ? "invalid-policy" : "use-manual-advanced",
        ),
      );
      continue;
    }
    for (const value of values) {
      for (const violation of runRepresentabilityConstraints(path, surface, value)) {
        errors.push(
          issue(
            "WARRANT_SURFACE_CONSTRAINT",
            violation.path,
            violation.message,
            surface === "manual-advanced" ? "invalid-policy" : "surface-constraint",
          ),
        );
      }
    }
  }
  return errors;
};

const deduplicate = (
  errors: readonly WarrantyValidationError[],
): readonly WarrantyValidationError[] => {
  const seen = new Set<string>();
  return errors.filter((error) => {
    const identity = `${error.code}\u0000${error.path}`;
    if (seen.has(identity)) return false;
    seen.add(identity);
    return true;
  });
};

/**
 * Parses once after exhaustive structural scanning. Callers must apply UI
 * state only when errors is empty, preserving the zero-partial-mutation rule.
 */
// skipcq: JS-R1005 - The validation pipeline deliberately short-circuits malformed envelopes before parsing.
export const validateAndParsePolicyMarkdown = (
  raw: string | Uint8Array,
  options: WarrantyValidationOptions = {},
): WarrantyValidationResult => {
  const envelope = inspectEnvelope(raw, options.envelope_mode ?? "any");
  if (envelope.markdown === undefined || envelope.unsigned === undefined) {
    return { errors: envelope.errors };
  }
  const errors = [...envelope.errors];
  let structural: string;
  try {
    structural = maskHtmlComments(envelope.unsigned);
  } catch (error) {
    return { errors: deduplicate([...errors, mapParserError(error)]) };
  }
  const version = validateRootVersion(structural, errors);
  const sections = sectionSlices(structural, errors);
  for (const section of sections) scanSection(section, version, errors);

  let policy: ParsedPolicy | undefined;
  try {
    policy = parsePolicyMarkdown(envelope.unsigned);
  } catch (error) {
    errors.push(mapParserError(error));
  }
  if (policy !== undefined) errors.push(...surfaceErrors(policy, options, envelope.has_signature_header));
  const uniqueErrors = deduplicate(errors);
  return uniqueErrors.length === 0 && policy !== undefined
    ? { policy, errors: uniqueErrors }
    : { errors: uniqueErrors };
};

/** Returns the complete stable D9 issue list for a warranty.md document. */
export const validatePolicyMarkdown = (
  raw: string | Uint8Array,
  options: WarrantyValidationOptions = {},
): readonly WarrantyValidationError[] =>
  validateAndParsePolicyMarkdown(raw, options).errors;

/** Byte-oriented entry point that can report malformed UTF-8 before parsing. */
export const validatePolicyBytes = (
  raw: Uint8Array,
  options: WarrantyValidationOptions = {},
): readonly WarrantyValidationError[] => validatePolicyMarkdown(raw, options);
