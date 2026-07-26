import type { CryptoAdapter } from "./types.js";

const encoder = new TextEncoder();

/** Warrant policy hashes use en-US collation with a deterministic UTF-16 tie-break. */
export function canonicalizePolicyObject(value: unknown): string {
  return serializePolicy(value);
}

const comparePolicyKeys = (left: string, right: string): number => {
  const collated = left.localeCompare(right, "en-US", {
    sensitivity: "variant",
    numeric: false,
    caseFirst: "false",
  });
  if (collated !== 0) return collated;
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
};

function serializePolicy(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return Number.isFinite(value) ? JSON.stringify(value) : "null";
  if (Array.isArray(value)) {
    const entries = Array.from({ length: value.length }, (_, index) =>
      Object.hasOwn(value, index) ? serializePolicy(value[index]) : "null"
    );
    return `[${entries.join(",")}]`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([left], [right]) => comparePolicyKeys(left, right));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${serializePolicy(entry)}`).join(",")}}`;
  }
  return "null";
}

export async function sha256Hex(adapter: CryptoAdapter, text: string): Promise<string> {
  const digest = await adapter.sha256(encoder.encode(text));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function policyCanonicalBytes(policy: unknown): Uint8Array {
  return encoder.encode(canonicalizePolicyObject(policy));
}

export async function hashPolicy(adapter: CryptoAdapter, policy: unknown): Promise<string> {
  const digest = await adapter.sha256(policyCanonicalBytes(policy));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
