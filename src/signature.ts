import type { SplitSignatureBlock } from "./types.js";

const signatureHeader = /^##\s+signature\s*$/im;
const signatureValue = /^sigil-sig:[ \t]*([A-Za-z0-9_-]+)[ \t]*$/;

export function splitSignatureBlock(markdown: string): SplitSignatureBlock {
  const match = signatureHeader.exec(markdown);
  if (!match || match.index === undefined) return { unsigned: markdown.trimEnd() };
  const unsigned = markdown.slice(0, match.index).trimEnd();
  const block = markdown.slice(match.index + match[0].length);
  if (/^##\s+/m.test(block)) throw new Error("Signature block must be final");
  const signature = signatureValue.exec(block.trim())?.[1];
  if (!signature) throw new Error("Signature block must contain only sigil-sig");
  return { unsigned, signature };
}

export function appendSignatureBlock(unsigned: string, signature: string): string {
  if (!/^[A-Za-z0-9_-]+$/.test(signature)) throw new Error("Signature must be base64url");
  if (signatureHeader.test(unsigned)) throw new Error("Unsigned policy already contains a signature block");
  return `${unsigned.trimEnd()}\n\n## signature\nsigil-sig: ${signature}\n`;
}
