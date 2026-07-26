import type { CryptoAdapter, JsonValue } from "./types.js";

const encoder = new TextEncoder();

/** pg-commit-v1 orders object keys by ECMAScript UTF-16 code units. */
export function canonicalizePgCommitV1(value: unknown): string {
  return serialize(value, new Set<object>());
}

function compareUtf16CodeUnits(left: string, right: string): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = left.charCodeAt(index) - right.charCodeAt(index);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

function serialize(value: unknown, stack: Set<object>): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("pg-commit-v1 rejects non-finite numbers");
    return JSON.stringify(value);
  }
  if (typeof value === "undefined") throw new TypeError("pg-commit-v1 rejects undefined");
  if (typeof value === "bigint") throw new TypeError("pg-commit-v1 rejects bigint");
  if (typeof value === "function") throw new TypeError("pg-commit-v1 rejects functions");
  if (typeof value === "symbol") throw new TypeError("pg-commit-v1 rejects symbols");
  if (typeof value !== "object") throw new TypeError("pg-commit-v1 rejects unsupported values");
  if (stack.has(value)) throw new TypeError("pg-commit-v1 rejects cyclic values");
  stack.add(value);
  try {
    if (Array.isArray(value)) return serializeArray(value, stack);
    if (!isPlainObject(value)) throw new TypeError("pg-commit-v1 rejects non-plain objects");
    if (Object.getOwnPropertySymbols(value).length) throw new TypeError("pg-commit-v1 rejects symbol-keyed object properties");
    const entries = Object.getOwnPropertyNames(value)
      .sort(compareUtf16CodeUnits)
      .map((key) => {
        const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
        if (!descriptor.enumerable) throw new TypeError("pg-commit-v1 rejects non-enumerable object properties");
        if (isAccessor(descriptor)) throw new TypeError("pg-commit-v1 rejects accessor properties");
        return `${JSON.stringify(key)}:${serialize(descriptor.value, stack)}`;
      });
    return `{${entries.join(",")}}`;
  } finally {
    stack.delete(value);
  }
}

function serializeArray(value: unknown[], stack: Set<object>): string {
  if (Object.getPrototypeOf(value) !== Array.prototype) throw new TypeError("pg-commit-v1 rejects non-plain arrays");
  if (Object.getOwnPropertySymbols(value).length) throw new TypeError("pg-commit-v1 rejects symbol-keyed object properties");
  const names = Object.getOwnPropertyNames(value);
  for (const name of names) {
    if (name === "length") continue;
    if (!isArrayIndex(name, value.length)) throw new TypeError("pg-commit-v1 rejects non-index array properties");
    const descriptor = Object.getOwnPropertyDescriptor(value, name)!;
    if (!descriptor.enumerable) throw new TypeError("pg-commit-v1 rejects non-enumerable array properties");
    if (isAccessor(descriptor)) throw new TypeError("pg-commit-v1 rejects accessor properties");
  }
  const entries: string[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor) throw new TypeError("pg-commit-v1 rejects sparse array holes");
    if (isAccessor(descriptor)) throw new TypeError("pg-commit-v1 rejects accessor properties");
    entries.push(serialize(descriptor.value, stack));
  }
  return `[${entries.join(",")}]`;
}

function isPlainObject(value: object): boolean {
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isArrayIndex(name: string, length: number): boolean {
  if (!/^(?:0|[1-9]\d*)$/.test(name)) return false;
  const index = Number(name);
  return Number.isSafeInteger(index) && index >= 0 && index < length;
}

function isAccessor(descriptor: PropertyDescriptor): descriptor is PropertyDescriptor & { get?: () => unknown; set?: (value: unknown) => void } {
  return "get" in descriptor || "set" in descriptor;
}

export function pgCommitV1Bytes(intent: JsonValue): Uint8Array {
  return encoder.encode(canonicalizePgCommitV1(intent));
}

export async function hashPgCommitV1(adapter: CryptoAdapter, intent: JsonValue): Promise<string> {
  const digest = await adapter.sha256(pgCommitV1Bytes(intent));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
