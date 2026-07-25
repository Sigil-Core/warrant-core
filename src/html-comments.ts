/** Replace closed HTML comments with spaces while preserving line breaks and offsets. */
export function maskHtmlComments(markdown: string): string {
  const masked = markdown.replace(/<!--[\s\S]*?-->/g, (comment) => comment.replace(/[^\n]/g, " "));
  if (masked.includes("<!--") || masked.includes("-->")) {
    throw new Error("Unterminated HTML comment in policy");
  }
  return masked;
}
