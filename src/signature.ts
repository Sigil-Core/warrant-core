import type {
  SignedEnvelope,
  SplitSignatureBlock,
  WarrantEnvelopeErrorCode,
} from "./types.js";
import { maskHtmlComments } from "./html-comments.js";

const encoder = new TextEncoder();
const signatureHeader = /^##[ \t]+signature[ \t]*\r?$/gim;
const signatureValue = /^[ \t]*sigil-sig:[ \t]*([A-Za-z0-9_-]+)[ \t]*\r?$/;
const signatureLine = /^[ \t]*sigil-sig:/;
const trailingByte = new Set([0x20, 0x09, 0x0d, 0x0a]);
const legacySignatureHeader = /^##[ \t]+signature[ \t]*$/im;
const legacySignatureValue = /^sigil-sig:[ \t]*([A-Za-z0-9_-]+)[ \t]*$/;

export class WarrantEnvelopeError extends Error {
  readonly code: WarrantEnvelopeErrorCode;

  constructor(code: WarrantEnvelopeErrorCode, message: string) {
    super(message);
    this.name = "WarrantEnvelopeError";
    this.code = code;
  }
}

const decodeUtf8 = (raw: Uint8Array): string => {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw);
  } catch {
    throw new WarrantEnvelopeError(
      "WARRANT_ENVELOPE_INVALID_UTF8",
      "Warrant envelope contains malformed UTF-8",
    );
  }
};

const stripTrailingBytes = (raw: Uint8Array): Uint8Array => {
  let end = raw.length;
  while (end > 0) {
    const byte = raw[end - 1];
    if (byte === undefined || !trailingByte.has(byte)) break;
    end -= 1;
  }
  return raw.slice(0, end);
};

const assertPayload = (payload: Uint8Array): Uint8Array => {
  if (payload.length === 0) {
    throw new WarrantEnvelopeError(
      "WARRANT_ENVELOPE_EMPTY_POLICY",
      "Warrant envelope contains an empty policy payload",
    );
  }
  return payload;
};

const signatureHeaders = (markdown: string): RegExpMatchArray[] => {
  const masked = maskHtmlComments(markdown);
  return [...masked.matchAll(signatureHeader)];
};

const byteOffset = (markdown: string, stringOffset: number): number => {
  return encoder.encode(markdown.slice(0, stringOffset)).length;
};

// skipcq: JS-R1005 - Each branch enforces a distinct final-signature envelope invariant.
const parseSignatureBlock = (block: string): string | undefined => {
  const signatures: string[] = [];
  for (const line of block.split("\n")) {
    const value = signatureValue.exec(line)?.[1];
    if (value) {
      signatures.push(value);
      continue;
    }
    const trimmed = line.trim();
    if (!trimmed) continue;
    // A Markdown heading starts with `#`, but it is a new section rather than
    // a permitted signature-block comment. The signature block must be final.
    if (/^#{2,}[ \t]+\S/.test(trimmed)) {
      throw new WarrantEnvelopeError(
        "WARRANT_ENVELOPE_TRAILING_CONTENT",
        "Signature block must be final",
      );
    }
    if (trimmed.startsWith("#")) continue;
    if (signatureLine.test(trimmed)) {
      throw new WarrantEnvelopeError(
        "WARRANT_ENVELOPE_TRAILING_CONTENT",
        "Signature block must contain only sigil-sig and comment lines",
      );
    }
    if (/^##[ \t]+\S/.test(trimmed)) {
      throw new WarrantEnvelopeError(
        "WARRANT_ENVELOPE_TRAILING_CONTENT",
        "Signature block must be final",
      );
    }
    throw new WarrantEnvelopeError(
      "WARRANT_ENVELOPE_TRAILING_CONTENT",
      "Signature block must contain only sigil-sig and comment lines",
    );
  }
  if (signatures.length > 1) {
    throw new WarrantEnvelopeError(
      "WARRANT_ENVELOPE_DUPLICATE_SIGNATURE",
      "Warrant envelope contains duplicate sigil-sig lines",
    );
  }
  return signatures[0];
};

// skipcq: JS-R1005 - Header, payload, and signature checks remain ordered in one strict envelope parser.
export const signedEnvelopeParse = (raw: Uint8Array): SignedEnvelope => {
  const markdown = decodeUtf8(raw);
  const headers = signatureHeaders(markdown);
  if (headers.length === 0) {
    throw new WarrantEnvelopeError(
      "WARRANT_ENVELOPE_UNEXPECTED_HEADER",
      "Signed Warrant envelope is missing its signature header",
    );
  }
  if (headers.length > 1) {
    throw new WarrantEnvelopeError(
      "WARRANT_ENVELOPE_DUPLICATE_HEADER",
      "Warrant envelope contains duplicate signature headers",
    );
  }
  const header = headers[0];
  if (header === undefined || header.index === undefined) {
    throw new WarrantEnvelopeError(
      "WARRANT_ENVELOPE_UNEXPECTED_HEADER",
      "Signed Warrant envelope has an invalid signature header",
    );
  }
  const headerIndex = header.index;
  const payload = assertPayload(stripTrailingBytes(raw.slice(0, byteOffset(markdown, headerIndex))));
  const signature = parseSignatureBlock(markdown.slice(headerIndex + header[0].length));
  return { payload, ...(signature ? { signature } : {}) };
};

export const unsignedSigningPayload = (raw: Uint8Array): Uint8Array => {
  const markdown = decodeUtf8(raw);
  if (signatureHeaders(markdown).length > 0) {
    throw new WarrantEnvelopeError(
      "WARRANT_ENVELOPE_UNEXPECTED_HEADER",
      "Unsigned Warrant source must not contain a signature header",
    );
  }
  return assertPayload(stripTrailingBytes(raw));
};

export const emit = (payload: Uint8Array, signature: string): Uint8Array => {
  decodeUtf8(payload);
  if (!/^[A-Za-z0-9_-]+$/.test(signature)) {
    throw new Error("Signature must be base64url");
  }
  const signable = unsignedSigningPayload(payload);
  const suffix = encoder.encode(`\n\n## signature\nsigil-sig: ${signature}\n`);
  const result = new Uint8Array(signable.length + suffix.length);
  result.set(signable);
  result.set(suffix, signable.length);
  return result;
};

export const splitSignatureBlock = (markdown: string): SplitSignatureBlock => {
  // This compatibility wrapper deliberately retains the published string API.
  // New signing and verification paths must use the byte-level functions above.
  const masked = maskHtmlComments(markdown);
  const match = legacySignatureHeader.exec(masked);
  if (!match || match.index === undefined) return { unsigned: markdown.trimEnd() };
  const unsigned = markdown.slice(0, match.index).trimEnd();
  const block = masked.slice(match.index + match[0].length);
  if (/^##\s+/m.test(block)) throw new Error("Signature block must be final");
  const signature = legacySignatureValue.exec(block.trim())?.[1];
  if (!signature) throw new Error("Signature block must contain only sigil-sig");
  return { unsigned, signature };
};

export const appendSignatureBlock = (unsigned: string, signature: string): string => {
  if (!/^[A-Za-z0-9_-]+$/.test(signature)) throw new Error("Signature must be base64url");
  if (legacySignatureHeader.test(maskHtmlComments(unsigned))) {
    throw new Error("Unsigned policy already contains a signature block");
  }
  return `${unsigned.trimEnd()}\n\n## signature\nsigil-sig: ${signature}\n`;
};
