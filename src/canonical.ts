import type { CryptoAdapter } from "./types.js";

const encoder = new TextEncoder();

/** Existing Warrant policy hashes use stable en-US localeCompare ordering. */
export function canonicalizePolicyObject(value: unknown): string {
  return serializePolicy(value);
}

function serializePolicy(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return Number.isFinite(value) ? JSON.stringify(value) : "null";
  if (Array.isArray(value)) return `[${value.map(serializePolicy).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([left], [right]) => left.localeCompare(right, "en-US", {
        sensitivity: "variant",
        numeric: false,
        caseFirst: "false",
      }));
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
