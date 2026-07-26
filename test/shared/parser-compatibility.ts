import { expect, it } from "vitest";

import { parsePolicyMarkdown } from "../../src/index.js";
import consumerCompatibilityFixture from "../vectors/consumer-compatibility.json";

interface ConsumerCompatibilityCaseBase {
  id: string;
  markdown: string;
  versions?: string[];
}

interface ConsumerCompatibilityAcceptCase extends ConsumerCompatibilityCaseBase {
  outcome: "accept";
  canonicalPolicy?: unknown;
  errorContains?: never;
}

interface ConsumerCompatibilityRejectCase extends ConsumerCompatibilityCaseBase {
  outcome: "reject";
  canonicalPolicy?: never;
  errorContains: string;
}

type ConsumerCompatibilityCase = ConsumerCompatibilityAcceptCase | ConsumerCompatibilityRejectCase;

export const KNOWN_PARITY_DIVERGENCES = new Set([
  "tool-controls-without-allowed-list",
  "token-decimals-numeric-prefix",
  "soft-limit-below-bound-source-overprecision",
  "legacy-daily-evm-limit-precision",
]);

const validatedVersions = (record: Record<string, unknown>): string[] => {
  if (!Array.isArray(record.versions) || record.versions.length === 0 || record.versions.some((version) => typeof version !== "string" || version.trim() === "")) {
    throw new Error(`Consumer compatibility case ${record.id} versions must be a non-empty string array`);
  }
  return record.versions as string[];
};
const versionHeaderValue = (record: Record<string, unknown>): string => {
  const versionHeader = record.markdown.match(/^version:\s*(\S+)\s*$/m);
  const version = versionHeader?.[1];
  if (!versionHeader || version === undefined) {
    throw new Error(`Consumer compatibility case ${record.id} with versions must contain a version header`);
  }
  return version;
};
const validateVersions = (record: Record<string, unknown>): string[] | undefined => {
  if (record.versions === undefined) return undefined;
  const versions = validatedVersions(record);
  const version = versionHeaderValue(record);
  if (!versions.includes(version)) {
    throw new Error(`Consumer compatibility case ${record.id} version header must match one of its versions`);
  }
  return versions;
};

const consumerCompatibilityRecord = (candidate: unknown, index: number): Record<string, unknown> => {
  if (typeof candidate !== "object" || candidate === null) {
    throw new Error(`Consumer compatibility case ${index} must be an object`);
  }
  return candidate as Record<string, unknown>;
};
const validateConsumerCompatibilityIdentity = (record: Record<string, unknown>, index: number): { id: string; markdown: string } => {
  if (typeof record.id !== "string" || record.id.trim() === "") {
    throw new Error(`Consumer compatibility case ${index} must have a non-empty id`);
  }
  if (typeof record.markdown !== "string" || record.markdown.trim() === "") {
    throw new Error(`Consumer compatibility case ${record.id} must have non-empty markdown`);
  }
  return { id: record.id, markdown: record.markdown };
};
const acceptedConsumerCompatibilityCase = (record: Record<string, unknown>, base: ConsumerCompatibilityCaseBase): ConsumerCompatibilityAcceptCase => {
  if (record.errorContains !== undefined) {
    throw new Error(`Accepted consumer compatibility case ${record.id} must not define errorContains`);
  }
  return { ...base, outcome: "accept", ...("canonicalPolicy" in record ? { canonicalPolicy: record.canonicalPolicy } : {}) };
};
const rejectedConsumerCompatibilityCase = (record: Record<string, unknown>, base: ConsumerCompatibilityCaseBase): ConsumerCompatibilityRejectCase => {
  if (typeof record.errorContains !== "string" || record.errorContains.trim() === "") {
    throw new Error(`Rejected consumer compatibility case ${record.id} must define a non-empty errorContains`);
  }
  if ("canonicalPolicy" in record) {
    throw new Error(`Rejected consumer compatibility case ${record.id} must not define canonicalPolicy`);
  }
  return { ...base, outcome: "reject", errorContains: record.errorContains };
};
const validateConsumerCompatibilityCase = (candidate: unknown, index: number): ConsumerCompatibilityCase => {
  const record = consumerCompatibilityRecord(candidate, index);
  const identity = validateConsumerCompatibilityIdentity(record, index);
  const versions = validateVersions(record);
  const base = { ...identity, ...(versions ? { versions } : {}) };
  if (record.outcome === "accept") return acceptedConsumerCompatibilityCase(record, base);
  if (record.outcome === "reject") return rejectedConsumerCompatibilityCase(record, base);
  throw new Error(`Consumer compatibility case ${record.id} must have outcome accept or reject`);
};

const validateConsumerCompatibilityFixture = (fixture: unknown): ConsumerCompatibilityCase[] => {
  if (typeof fixture !== "object" || fixture === null || !("cases" in fixture) || !Array.isArray(fixture.cases)) {
    throw new Error("Consumer compatibility fixture must contain a cases array");
  }
  return fixture.cases.map(validateConsumerCompatibilityCase);
};

const consumerCompatibilityCases = validateConsumerCompatibilityFixture(consumerCompatibilityFixture);
const consumerCompatibilityCaseIds = new Set(consumerCompatibilityCases.map(({ id }) => id));

export const assertKnownParityDivergencesCovered = (): void => {
  for (const id of KNOWN_PARITY_DIVERGENCES) {
    if (!consumerCompatibilityCaseIds.has(id)) {
      throw new Error(`Known Sigil Sign parity divergence ${id} must have a validated consumer-compatibility case`);
    }
  }
};

const markdownForVersion = (compatibilityCase: ConsumerCompatibilityCase, version: string): string => {
  let replaced = false;
  const markdown = compatibilityCase.markdown.replace(/^version:\s*\S+\s*$/m, () => {
    replaced = true;
    return `version: ${version}`;
  });
  if (!replaced) {
    throw new Error(`Consumer compatibility case ${compatibilityCase.id} could not replace its version header`);
  }
  return markdown;
};

const markdownCasesFor = (compatibilityCase: ConsumerCompatibilityCase): string[] =>
  compatibilityCase.versions?.map((version) => markdownForVersion(compatibilityCase, version)) ?? [compatibilityCase.markdown];

const assertAcceptedConsumerCompatibilityCase = (compatibilityCase: ConsumerCompatibilityAcceptCase, markdownCases: string[]): void => {
  for (const markdown of markdownCases) {
    const parsed = parsePolicyMarkdown(markdown);
    if ("canonicalPolicy" in compatibilityCase) expect(parsed).toEqual(compatibilityCase.canonicalPolicy);
  }
};

const assertRejectedConsumerCompatibilityCase = (compatibilityCase: ConsumerCompatibilityRejectCase, markdownCases: string[]): void => {
  for (const markdown of markdownCases) {
    expect(() => parsePolicyMarkdown(markdown)).toThrow(compatibilityCase.errorContains);
  }
};

const assertConsumerCompatibilityCase = (compatibilityCase: ConsumerCompatibilityCase): void => {
  const markdownCases = markdownCasesFor(compatibilityCase);
  if (compatibilityCase.outcome === "accept") return assertAcceptedConsumerCompatibilityCase(compatibilityCase, markdownCases);
  return assertRejectedConsumerCompatibilityCase(compatibilityCase, markdownCases);
};

const defineConsumerCompatibilityVectorTest = (runtime: string, compatibilityCase: ConsumerCompatibilityCase): void => {
  it(`matches the ${compatibilityCase.id} consumer-compatibility vector in ${runtime}`, () => {
    assertConsumerCompatibilityCase(compatibilityCase);
  });
};
export const defineConsumerCompatibilityVectorTests = (runtime: string): void => {
  consumerCompatibilityCases.forEach((compatibilityCase) => defineConsumerCompatibilityVectorTest(runtime, compatibilityCase));
};
