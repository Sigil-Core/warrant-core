import { createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { execFileSync } from "node:child_process";

import {
  canonicalizePolicyObject,
} from "../dist/index.js";

const signCheckout = process.argv[2];
if (!signCheckout) {
  throw new Error("Usage: npm run test:sign-parity -- /absolute/path/to/sigil-sign");
}

const parityFixture = JSON.parse(readFileSync(new URL("../test/vectors/sigil-sign-parser-parity.json", import.meta.url), "utf8"));
const policyFixture = JSON.parse(readFileSync(new URL("../test/vectors/policy-fixtures.json", import.meta.url), "utf8"));
const actualCommit = execFileSync("git", ["-C", signCheckout, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
if (actualCommit !== parityFixture.sigilSignCommit) {
  throw new Error(`Sigil Sign commit mismatch: expected ${parityFixture.sigilSignCommit}, received ${actualCommit}`);
}

const require = createRequire(import.meta.url);
const { parseWarrantyContent } = require(resolve(signCheckout, "dist/lex/parser.js"));
const seed = Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex");
const rawPublicKey = Buffer.from("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "hex");
const operatorPublicKey = rawPublicKey.toString("base64url");
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
  format: "der",
  type: "pkcs8",
});

function signPolicy(markdown) {
  const unsigned = markdown.replace(/\n## signature[\s\S]*$/i, "").trimEnd();
  const signature = sign(null, Buffer.from(unsigned, "utf8"), privateKey).toString("base64url");
  return `${unsigned}\n\n## signature\nsigil-sig: ${signature}`;
}

function parseWithSign(markdown) {
  return parseWarrantyContent(signPolicy(markdown), { operatorPublicKey }).policy;
}

for (const fixture of policyFixture.fixtures) {
  const parsed = parseWithSign(fixture.templateBody);
  if (canonicalizePolicyObject(parsed) !== fixture.canonicalPolicyJson) {
    throw new Error(`Sigil Sign canonical policy mismatch for ${fixture.slug}`);
  }
}

for (const parityCase of parityFixture.cases) {
  if (parityCase.outcome === "accept") {
    const parsed = parseWithSign(parityCase.markdown);
    if (canonicalizePolicyObject(parsed) !== canonicalizePolicyObject(parityCase.canonicalPolicy)) {
      throw new Error(`Sigil Sign accepted a different canonical policy for ${parityCase.id}`);
    }
  } else {
    let rejected = false;
    try {
      parseWithSign(parityCase.markdown);
    } catch {
      rejected = true;
    }
    if (!rejected) throw new Error(`Sigil Sign unexpectedly accepted ${parityCase.id}`);
  }
}

console.log(`Sigil Sign parser parity passed at ${actualCommit}: ${policyFixture.fixtures.length} canonical policies and ${parityFixture.cases.length} edge cases`);
