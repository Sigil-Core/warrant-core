import type {
  SignedEnvelope,
  SplitSignatureBlock,
  StrictWarrantFramingOptions,
  WarrantMarkdownFrame,
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
const strictSignatureHeader = "## signature\n";
const strictSignature = /^[A-Za-z0-9_-]{86}$/;
const strictWarrantMaximumBytes = 256 * 1024;
const strictSignaturePrefix = "sigil-sig: ";
const base64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

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

const throwStrictEnvelopeError = (code: WarrantEnvelopeErrorCode, message: string): never => {
  throw new WarrantEnvelopeError(code, message);
};

// skipcq: JS-R1005 - The ordered strict size failures expose stable public error codes.
const assertStrictByteLimit = (raw: Uint8Array, options: StrictWarrantFramingOptions): void => {
  const maximumBytes = options.maxBytes ?? strictWarrantMaximumBytes;
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0 || maximumBytes > strictWarrantMaximumBytes || raw.length > maximumBytes) {
    throwStrictEnvelopeError("WARRANT_ENVELOPE_STRICT_SIZE", "Strict Warrant framing exceeds its configured byte limit");
  }
  if (raw.length === 0) {
    throwStrictEnvelopeError("WARRANT_ENVELOPE_EMPTY_POLICY", "Warrant framing contains an empty policy payload");
  }
};

// skipcq: JS-R1005 - Each raw-byte rejection maps to a distinct strict framing error code.
const assertStrictRawBytes = (raw: Uint8Array): void => {
  if (raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf) {
    throwStrictEnvelopeError("WARRANT_ENVELOPE_STRICT_BOM", "Strict Warrant framing forbids a UTF-8 BOM");
  }
  if (raw.includes(0x0d)) {
    throwStrictEnvelopeError("WARRANT_ENVELOPE_STRICT_CR", "Strict Warrant framing forbids CR bytes");
  }
  if (raw.includes(0x00)) {
    throwStrictEnvelopeError("WARRANT_ENVELOPE_STRICT_NUL", "Strict Warrant framing forbids NUL bytes");
  }
};

const strictHeaderOffsets = (raw: Uint8Array, markdown: string): { headerIndex: number; headerByteIndex: number } => {
  const headerIndex = markdown.indexOf(strictSignatureHeader);
  if (headerIndex <= 0 || headerIndex !== markdown.lastIndexOf(strictSignatureHeader)) {
    return throwStrictEnvelopeError("WARRANT_ENVELOPE_STRICT_HEADER", "Strict Warrant framing requires one final literal signature header");
  }
  const headerByteIndex = byteOffset(markdown, headerIndex);
  if (raw[headerByteIndex - 1] !== 0x0a) {
    return throwStrictEnvelopeError("WARRANT_ENVELOPE_STRICT_HEADER", "Strict Warrant framing requires the signature header at the start of a line");
  }
  return { headerIndex, headerByteIndex };
};

const isCanonical64ByteBase64url = (signature: string): boolean => {
  const finalCharacter = signature.at(-1);
  return strictSignature.test(signature)
    && finalCharacter !== undefined
    // An 86-character unpadded Base64url value encodes 64 bytes only when
    // the low four unused bits in its final sextet are zero.
    && (base64urlAlphabet.indexOf(finalCharacter) & 0x0f) === 0;
};

// skipcq: JS-R1005 - Signature structure and canonical encoding failures must remain distinct.
const strictSignatureFromBlock = (markdown: string, headerIndex: number): string => {
  const signatureBlock = markdown.slice(headerIndex + strictSignatureHeader.length);
  const finalNewline = signatureBlock.indexOf("\n");
  const signatureLine = finalNewline === -1 ? signatureBlock : signatureBlock.slice(0, finalNewline);
  const trailing = finalNewline === -1 ? "" : signatureBlock.slice(finalNewline);
  if (!signatureLine.startsWith(strictSignaturePrefix) || !/^[ \t\n]*$/.test(trailing)) {
    return throwStrictEnvelopeError("WARRANT_ENVELOPE_STRICT_SIGNATURE", "Strict Warrant framing requires one bounded base64url signature");
  }
  const signature = signatureLine.slice(strictSignaturePrefix.length);
  if (!isCanonical64ByteBase64url(signature)) {
    return throwStrictEnvelopeError("WARRANT_ENVELOPE_STRICT_SIGNATURE", "Strict Warrant framing requires a canonical 64-byte Ed25519 signature");
  }
  return signature;
};

// skipcq: JS-R1005 - The strict empty-policy outcome depends on this ordered byte scan.
const strictPreimages = (raw: Uint8Array, headerByteIndex: number): Pick<WarrantMarkdownFrame, "unsigned" | "legacyUnsigned"> => {
  let payloadEnd = headerByteIndex;
  while (payloadEnd > 0) {
    const byte = raw[payloadEnd - 1];
    if (byte !== 0x20 && byte !== 0x09 && byte !== 0x0a) break;
    payloadEnd -= 1;
  }
  if (payloadEnd === 0) {
    return throwStrictEnvelopeError("WARRANT_ENVELOPE_EMPTY_POLICY", "Warrant framing contains an empty policy payload");
  }
  const legacyUnsigned = raw.slice(0, payloadEnd);
  const unsigned = new Uint8Array(payloadEnd + 1);
  unsigned.set(legacyUnsigned);
  unsigned[payloadEnd] = 0x0a;
  return { unsigned, legacyUnsigned };
};

/**
 * Frame an exact CC-1 Warrant source. This is intentionally stricter than the
 * legacy helpers and preserves every accepted raw/preimage byte unchanged.
 */
// skipcq: JS-R1005 - Each ordered branch maps one strict wire-format failure
// to its stable public error code; splitting them would obscure that contract.
export const frameWarrantMarkdownBytes = (
  raw: Uint8Array,
  options: StrictWarrantFramingOptions = {},
): WarrantMarkdownFrame => {
  assertStrictByteLimit(raw, options);
  assertStrictRawBytes(raw);
  const markdown = decodeUtf8(raw);
  const { headerIndex, headerByteIndex } = strictHeaderOffsets(raw, markdown);
  const signature = strictSignatureFromBlock(markdown, headerIndex);
  const { unsigned, legacyUnsigned } = strictPreimages(raw, headerByteIndex);
  return {
    raw: raw.slice(),
    markdown,
    unsigned,
    legacyUnsigned,
    signature,
  };
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
