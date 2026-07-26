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

const validateVersions = (record: Record<string, unknown>): string[] | undefined => {
  if (record.versions === undefined) return undefined;
  if (!Array.isArray(record.versions) || record.versions.length === 0 || record.versions.some((version) => typeof version !== "string" || version.trim() === "")) {
    throw new Error(`Consumer compatibility case ${record.id} versions must be a non-empty string array`);
  }
  const versions = record.versions as string[];
  const versionHeader = record.markdown.match(/^version:\s*(\S+)\s*$/m);
  const version = versionHeader?.[1];
  if (!versionHeader || version === undefined) {
    throw new Error(`Consumer compatibility case ${record.id} with versions must contain a version header`);
  }
  if (!versions.includes(version)) {
    throw new Error(`Consumer compatibility case ${record.id} version header must match one of its versions`);
  }
  return versions;
};

const validateConsumerCompatibilityCase = (candidate: unknown, index: number): ConsumerCompatibilityCase => {
  if (typeof candidate !== "object" || candidate === null) {
    throw new Error(`Consumer compatibility case ${index} must be an object`);
  }
  const record = candidate as Record<string, unknown>;
  if (typeof record.id !== "string" || record.id.trim() === "") {
    throw new Error(`Consumer compatibility case ${index} must have a non-empty id`);
  }
  if (typeof record.markdown !== "string" || record.markdown.trim() === "") {
    throw new Error(`Consumer compatibility case ${record.id} must have non-empty markdown`);
  }
  const versions = validateVersions(record);
  const base = { id: record.id, markdown: record.markdown, ...(versions ? { versions } : {}) };
  if (record.outcome === "accept") {
    if (record.errorContains !== undefined) {
      throw new Error(`Accepted consumer compatibility case ${record.id} must not define errorContains`);
    }
    return { ...base, outcome: "accept", ...("canonicalPolicy" in record ? { canonicalPolicy: record.canonicalPolicy } : {}) };
  }
  if (record.outcome === "reject") {
    if (typeof record.errorContains !== "string" || record.errorContains.trim() === "") {
      throw new Error(`Rejected consumer compatibility case ${record.id} must define a non-empty errorContains`);
    }
    if ("canonicalPolicy" in record) {
      throw new Error(`Rejected consumer compatibility case ${record.id} must not define canonicalPolicy`);
    }
    return { ...base, outcome: "reject", errorContains: record.errorContains };
  }
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

export const defineConsumerCompatibilityVectorTests = (runtime: string): void => {
  for (const compatibilityCase of consumerCompatibilityCases) {
    it(`matches the ${compatibilityCase.id} consumer-compatibility vector in ${runtime}`, () => {
      assertConsumerCompatibilityCase(compatibilityCase);
    });
  }
};
