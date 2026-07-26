/** Replace closed HTML comments with spaces while preserving line breaks and offsets. */
export function maskHtmlComments(markdown: string): string {
  let cursor = 0;
  let masked = "";
  while (cursor < markdown.length) {
    const opener = markdown.indexOf("<!--", cursor);
    if (opener < 0) return masked + markdown.slice(cursor);
    const closer = markdown.indexOf("-->", opener + 4);
    if (closer < 0) {
      throw new Error("Unterminated HTML comment in policy");
    }
    masked += markdown.slice(cursor, opener);
    masked += markdown.slice(opener, closer + 3).replace(/[^\n]/g, " ");
    cursor = closer + 3;
  }
  return masked;
}
