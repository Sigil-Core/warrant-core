# @sigilcore/warrant-core

Platform-neutral primitives for Sigil Warrant policies. The package provides the policy parser, the established Warrant policy-hash canonicalizer, the `pg-commit-v1` commitment canonicalizer, SHA-256 adapter boundaries, and signature-block helpers.

The root entry point has no Node.js, browser, Cloudflare, network, or framework dependency. Import a runtime-specific cryptographic adapter explicitly.

## Installation

This package is published as a public npm package after its initial owner-controlled release.

```sh
npm install @sigilcore/warrant-core@0.2.4
```

Security-sensitive consumers must pin the full reviewed version. Do not use a caret, tilde, range, or the `latest` tag.

### Published release

`@sigilcore/warrant-core@0.2.1` is immutable. Its npm dist integrity is
`sha512-1q2H80vewATLciWUoJLV+4v6ApqPrLfsw9kUBcK37eMMfZzdIetf8jQzcGw1wkE+6nbdO/j2Hb+4HeK/yh8SBw==`,
its SHA-1 shasum is `320456aaba51d7ecdda0575e1c1c3de0ba9c6458`, and its
published Git head is `cebf31e1af460a1328571d5d8ba2639cc77d9c2d`. npm records
SLSA provenance for this release.

`@sigilcore/warrant-core@0.2.2` advances the frozen Sigil Sign parser-contract
commit for the trusted-shim activation rollout. Its npm dist integrity is
`sha512-Qz1Fea8bqARTjq+rnFzxoRBPdRQ4/2jxtPmqIt7vWBMh37jhEpygVpqzTVmFk2xd+1gWM8BgI2Wk/v6xvzdDOQ==`,
its SHA-1 shasum is `f7376132334a36e4539243ab0a68b8c736db63e3`, and its
published Git head is `479673ea735d0059989c68c6b25cb1b206e64b45`. Tag `v0.2.2`
and trusted-publisher workflow run `30278830707` bind the release evidence. npm
records SLSA provenance for this release.

`@sigilcore/warrant-core@0.2.3` re-pins the byte-identical parser corpus to
Sigil Sign `915ff62003e59b24189e6c09f6dda2d8685bfcb9`. Its npm dist integrity is
`sha512-49Qw4zzb/9nqwyzYqEHs+yZ+77h9mc9QJPKgfFpqBW9nvBI4h28DtZsxpwqN7ATE4g4hMtXLhdBocOYQ3tdCmw==`,
its SHA-1 shasum is `f4654a3d6c879e558a63f4566227d2ba6267bb47`, and its
published Git head is `d04fd7482e40d6652ddff45dc964c8dd8b6a34fe`. Tag `v0.2.3`
and trusted-publisher workflow run `30541352312` bind the release evidence. npm
records SLSA provenance for this release.

`@sigilcore/warrant-core@0.2.4` extends the frozen parser corpus with
duplicate-key reject cases and re-pins it to Sigil Sign
`08c1d7376de358a4bf4254c382b9bcc1fec33f83`. npm registry readback reports
dist integrity
`sha512-WSTgzRTkofHRX5AVAeje6zEwEkaLnto4HsNgoG1VbPwwOTBYMJ3b7ZWCUBKmHJvF6WTgA/yWnbrDfZUNKnKCLg==`,
SHA-1 shasum `19348e216417eb34a4fe1a56f8432f9a66dcad69`, and Git head
`ac6f469f57b1fe6945642daf9914d7b256abf221`. This document does not independently
claim provenance for that release.

Version `0.3.0` is the Policy 2.2 and compiled response-policy format 1 release
candidate. It is not published yet. Do not claim npm integrity or provenance
until the trusted-publisher workflow and registry readback complete.

## Public API

The Policy 2.2 and compiled response-policy format 1 exports documented below
are unreleased `0.3.0` candidate APIs. The published `0.2.4` installation shown
above does not provide them.

```ts
import {
  appendSignatureBlock,
  canonicalizeCompiledResponsePolicyFormat1,
  canonicalizePgCommitV1,
  canonicalizePolicyObject,
  compileResponsePolicyFormat1,
  compiledResponsePolicyFormat1Bytes,
  frameWarrantMarkdownBytes,
  hashCompiledResponsePolicyFormat1,
  hashPgCommitV1,
  hashPolicy,
  lintPolicyAdvisories,
  parsePolicyMarkdown,
  serializePolicyMarkdown,
  signedEnvelopeParse,
  splitSignatureBlock,
  unsignedSigningPayload,
  validateAndParsePolicyMarkdown,
  validateCompiledResponsePolicyFormat1,
  validatePolicyMarkdown,
  verifyCompiledResponsePolicyFormat1,
} from "@sigilcore/warrant-core";
```

| Export | Contract |
| --- | --- |
| `parsePolicyMarkdown(markdown)` | Parses unversioned Policy 0.x and versioned Policy 1.x, 2.0.x, 2.1.x, and 2.2.x input. Policy 2.2 adds conditional MCP response coverage, deterministic block classes, and response-specific deny literals. Coverage values remain opaque exact strings and must be exact allowed-tool members. Unknown, misplaced, wildcard, duplicate, blocked, or version-incompatible response controls reject, and response defaults are never inserted into legacy ASTs. |
| `lintPolicyAdvisories(policy)` | Returns non-blocking recommended-field and trusted-shim warnings for Policy 2.1 resource profiles. |
| `canonicalizePolicyObject(value)` | Produces the established Warrant policy-hash JSON serialization. Use only for Warrant policy compatibility. |
| `policyCanonicalBytes(policy)` | UTF-8 bytes of `canonicalizePolicyObject(policy)`. |
| `hashPolicy(adapter, policy)` | SHA-256 lowercase hexadecimal digest of `policyCanonicalBytes(policy)`. |
| `sha256Hex(adapter, text)` | SHA-256 lowercase hexadecimal digest of UTF-8 `text`. |
| `canonicalizePgCommitV1(intent)` | Produces the Proving Ground `pg-commit-v1` JSON serialization. |
| `pgCommitV1Bytes(intent)` | UTF-8 bytes of `canonicalizePgCommitV1(intent)`. |
| `hashPgCommitV1(adapter, intent)` | SHA-256 lowercase hexadecimal digest of `pgCommitV1Bytes(intent)`. |
| `splitSignatureBlock(markdown)` | Splits a final `## signature` block and returns `{ unsigned, signature? }`. It rejects a signature block without `sigil-sig` and rejects a later section after it. It trims trailing whitespace from `unsigned`. |
| `appendSignatureBlock(unsigned, signature)` | Appends the standard final signature block. `signature` must be base64url text. It trims trailing whitespace from `unsigned` and always finishes with one newline. |
| `signedEnvelopeParse(raw)` | Validates a signed `sigil-envelope-v1` byte envelope and returns its exact payload bytes plus an optional signature for an empty placeholder block. |
| `unsignedSigningPayload(raw)` | Validates unsigned UTF-8 source and returns its signing payload after stripping ASCII space, tab, CR, and LF bytes only. |
| `emit(payload, signature)` | Emits the canonical signed envelope for a validated unsigned payload. |
| `frameWarrantMarkdownBytes(raw, options?)` | Frames a strict CC-1 signed Warrant. It rejects BOM, CR, NUL, non-literal or repeated final signature headers, invalid Base64url, and payloads over 256 KiB. `unsigned` is the CC-1 one-LF preimage. `legacyUnsigned` exists only to verify an envelope previously emitted by `emit()`, whose historical signing preimage excludes that LF. |
| `validatePolicyMarkdown(markdown, options?)` | Returns all independent authoring diagnostics as stable `{ code, path, message, surface_hint }` values. |
| `validateAndParsePolicyMarkdown(markdown, options?)` | Returns the complete diagnostic list and, only on success, the parsed policy. Callers apply authoring state only when `errors` is empty. |
| `serializePolicyMarkdown(policy)` | Emits the canonical Phase 1 Markdown body for a parsed policy. Page cutover remains a later phase. |
| `compileResponsePolicyFormat1(policy, input)` | Compiles a parsed Policy 2.2.x AST and trusted Sign context into the closed format 1 payload. |
| `validateCompiledResponsePolicyFormat1(value)` | Rejects missing, unknown, malformed, unsorted, duplicate, mismatched, or format-incompatible payload fields. |
| `canonicalizeCompiledResponsePolicyFormat1(value)` | Emits strict `pg-commit-v1` canonical JSON for a validated format 1 payload. |
| `compiledResponsePolicyFormat1Bytes(value)` | Returns the exact UTF-8 payload bytes used by compact JWS. |
| `hashCompiledResponsePolicyFormat1(adapter, value)` | Returns the lowercase SHA-256 digest of the exact canonical payload bytes. |
| `verifyCompiledResponsePolicyFormat1(adapter, compactJws, context)` | Verifies canonical compact JWS, Ed25519, trusted claims, lifetime, revocation, digests, and coverage. It returns the flattened payload plus `compiledPolicyDigest`. |
| `AUTHORING_CAPABILITY_MANIFEST` | Executable per-field author/import/preserve/deploy contract for `manual-form`, `manual-advanced`, and `builder`. |

The root entry point also exports the `ParsedPolicy`, `CryptoAdapter`, `JsonValue`, and `SplitSignatureBlock` types.

## Policy 2.1 authoring contract

Use `validateAndParsePolicyMarkdown` for an authoring or import boundary. It
returns the complete stable diagnostic list and yields a parsed policy only when
there are no errors. Treat a result containing errors as a zero-mutation result.
Use `validatePolicyMarkdown` when a caller needs diagnostics only, then use
`serializePolicyMarkdown` to emit the supported canonical Markdown body.

For a signed import, pass the original `Uint8Array` to `signedEnvelopeParse`.
It validates the `sigil-envelope-v1` structure and returns the exact payload
bytes without normalizing them. Verify those bytes with an explicitly selected
runtime adapter and trusted operator public key, then use `emit` to append a
new signature to already validated unsigned payload bytes. The package never
selects a key, establishes trust, or performs a network deployment.

## Policy 2.2 response-policy contract

Policy 2.2 adds these keys under `## mcp`:

```text
response.web_fetch_tools: fetch.server.fetch
response.http_tools: api.server.request
response.deterministic_ruleset: sof-response-rules-v1
response.block_classes: malicious_url, prompt_injection, secret
```

Each covered-tool token is an opaque exact member of `allowed_tools`.
Implementations must not split or normalize it. Coverage lists and class lists
are unique and lexicographically sorted in the parsed AST. Policy 2.2 also adds
repeatable JSON-quoted `response.deny_string` rules under `## custom`.
Response fields are emitted only when declared, preserving established Policy
0.x through 2.1.x hashes.

Format 1 is runtime-neutral. This package compiles and verifies canonical
payloads but performs no network call, key discovery, policy enforcement, or
response inspection. Sigil Sign supplies trusted execution context and signs
the compact JWS. Enforcers supply the independently trusted public key and
expected claims.

## Canonicalization profiles

The package intentionally exposes two distinct profiles. Their different sort rules are security-relevant. Never substitute one for the other.

### Warrant policy hash profile

Use `canonicalizePolicyObject` and `hashPolicy` for an existing Sigil Warrant `policyHash`.

- Object keys use `localeCompare` ordering pinned to `en-US` with variant sensitivity, lexical
  number handling, and locale-default case order. Distinct keys that collate equally use ECMAScript
  UTF-16 code-unit order as a deterministic tie-break, so insertion order cannot change policy bytes.
- Array order stays unchanged.
- Sparse array holes and explicit `undefined` array entries serialize as `null`, preserving array length and valid JSON.
- Object properties with `undefined` values are omitted.
- `null`, strings, booleans, and finite numbers serialize as JSON.
- Unsupported values serialize as `null` rather than becoming a `pg-commit-v1` validation error.

This profile preserves compatibility with the established Warrant policy hash. It is not an interchange format for a free-form request commitment.

### Proving Ground commitment profile: `pg-commit-v1`

Use `canonicalizePgCommitV1` and `hashPgCommitV1` for the Proving Ground request commitment.

- Object keys sort by ECMAScript UTF-16 code units, not locale collation.
- Array order stays unchanged.
- Cycles, `undefined`, `bigint`, functions, symbols, and non-finite numbers throw `TypeError`.
- Objects must have either `Object.prototype` or a null prototype. Arrays must have `Array.prototype`.
- Symbol-keyed properties, non-enumerable properties, accessor properties, sparse-array holes, and non-index array properties throw `TypeError`.
- Input must be a `JsonValue` before `pgCommitV1Bytes` or `hashPgCommitV1` receives it.

This strict profile makes a malformed commitment impossible to serialize silently.

## Runtime adapters

Import exactly one adapter for the runtime that performs hashing or Ed25519 work.

### Browser and Cloudflare Workers

```ts
import { hashPolicy } from "@sigilcore/warrant-core";
import { createWebCryptoAdapter } from "@sigilcore/warrant-core/crypto/browser";

const adapter = createWebCryptoAdapter(globalThis.crypto);
const policyHash = await hashPolicy(adapter, parsedPolicy);
```

`@sigilcore/warrant-core/crypto/workers` exports the same `createWebCryptoAdapter` API for Workers-focused imports. Both rely on the runtime's Web Crypto `SHA-256` and Ed25519 support. They do not provide a fallback implementation.

### Node.js

```ts
import { hashPgCommitV1 } from "@sigilcore/warrant-core";
import { createNodeCryptoAdapter } from "@sigilcore/warrant-core/crypto/node";

const adapter = createNodeCryptoAdapter();
const commitment = await hashPgCommitV1(adapter, fixedIntent);
```

The Node adapter accepts Ed25519 PKCS#8 private-key bytes for signing. Its verification method accepts either a DER SPKI public key or a 32-byte raw Ed25519 public key.

## Signature boundary

New CC-1 signing and verification integrations use
`frameWarrantMarkdownBytes`. Its `unsigned` property is the only CC-1 signing
preimage and has exactly one final LF. `legacyUnsigned` exists only for
verification of a previously emitted legacy envelope, whose `emit()` signing
preimage omits that LF. Do not sign a new CC-1 Warrant with `legacyUnsigned`.

Legacy `signedEnvelopeParse`, `unsignedSigningPayload`, and `emit` validate
UTF-8, preserve BOM and Unicode whitespace bytes, and strip only trailing ASCII
space, tab, CR, and LF. The older string helpers remain compatibility wrappers
and are not an exact-byte signing API.

`splitSignatureBlock` and `appendSignatureBlock` operate on Warrant text structure. They do not hash, sign, verify, base64url-decode, validate policy semantics, or select a trusted public key.

Closed HTML comments are ignored when locating policy and signature structure. A standalone `-->` remains literal policy text, while any `<!--` without a later closer rejects the artifact.

The helpers normalize trailing whitespace. A caller that must verify a signature over original raw file bytes must retain those bytes separately and must not reconstruct them through these helpers.

## Security boundary

This package parses and transforms policy artifacts. It does not mediate tool calls, execute an approved action, manage keys, fetch trust material, validate an issuer, or establish an execution boundary.

Callers must:

- validate the intended policy and select the correct canonicalization profile;
- obtain public keys and trust metadata from an independently trusted source;
- verify the intended signature over the intended bytes;
- enforce the resulting decision at the action boundary.

See [SECURITY.md](SECURITY.md) for reporting guidance.

## Consumer version rule

Every security-sensitive consumer pins the same exact `@sigilcore/warrant-core` version. Release tooling, `sigilcore`, and `sigil-attestations` must move together after the vector suite proves parity. A consumer update changes an artifact contract and requires its own review.

## Sigil Sign parser parity

The package keeps a frozen accepted-and-rejected parser corpus against the approved coordinated Sigil Sign R1 baseline commit `62638f0c2430965c4705fcf3927914f0aa8de5b0`. The final package release must re-pin this field to the reviewed Sign implementation head before publication. The prior pin `08c1d7376de358a4bf4254c382b9bcc1fec33f83` introduced duplicate-key rejection within `warranty.md` sections; this package already rejected those inputs. The corpus covers six canonical policies plus 105 edge cases, including eleven duplicate-key reject vectors across `tool_calls`, `custom`, `mcp`, `soft_limits`, `execution_limits`, and the Policy 2.1 `repository`, `filesystem`, `git`, and `database` profiles. It asserts outcome parity, not error text. One vector, `duplicate-tool-calls-block-then-inline-allowed`, rejects on both sides for different reasons: Sign parses the block-format list and then rejects the inline redeclaration as a duplicate, while this package rejects the block-format line itself because it accepts only inline comma-separated lists. That block-format divergence is pre-existing and intentional. `execution_limits` preserves approval-only, shim-only, and combined controls in canonical output. A standalone `require_shim: false` is rejected because it has no enforcement effect. Sigilcore consumer compatibility is authoritative where its committed parser contract intentionally differs from this Sign corpus. After building both repositories, run the local differential gate with the absolute Sigil Sign checkout path:

```sh
npm run test:sign-parity -- /absolute/path/to/sigil-sign
```

The gate signs only with the published RFC 8032 test key. It compares all six pinned canonical policies plus the parser edge-case corpus against Sigil Sign's compiled parser. It never reads an operator or production key.

That frozen corpus records legacy parser compatibility behaviors from the pinned Sign parser: ETH amount and consensus threshold fields accept a leading numeric prefix, and chain entries use their leading integer while filtering nonpositive or nonnumeric results. Numeric-prefix ETH parsing is retained for established policy hashes, while a configured nonnumeric or nonpositive limit rejects instead of removing a default or silently omitting enforcement. Token decimals are a deliberate hardening exception: they require a complete integer token from 0 through 36 in Policy 1.x and 2.x. Daily EVM limits retain a nonnumeric suffix compatibility prefix such as `1ETH`, but the numeric prefix itself must use fixed-point notation with at most six decimal places in every supported version. Exponent notation and source overprecision reject before Number conversion. Treat `parsePolicyMarkdown` as a compatibility parser with explicit hardening, not as a standalone lexical validator. Changing a frozen behavior requires coordinated parser changes, new vectors, and synchronized consumer releases.

## Release and npm trusted publishing

`.github/workflows/publish.yml` publishes only an unpublished stable semantic version whose tag exactly equals `v` plus the package version. Prerelease and build-metadata versions fail before the OIDC publish job. The workflow runs on a GitHub-hosted runner with Node 24, npm 11.5.1 or later, `id-token: write`, and `contents: read`. It tests, builds, packs, and inspects the tarball before `npm publish --access public --provenance`. It fails before publication if that immutable npm version already exists.

Sigil Sign is a private sibling repository, and the trusted-publish workflow's
repository-scoped token cannot read it. Therefore the mandatory cross-repository
parity control runs in the approved release execution before the release tag is
created: build the exact reviewed Sign worktree, run `test:sign-parity` against
its absolute path, bind the Sign commit and result in the release receipt, and
create no tag when that gate fails. The hosted publish job is downstream of
that recorded gate and is not evidence of cross-repository parity by itself.

The initial npm package bootstrap is complete. The following steps are a non-repeatable historical record:

1. `package.json` was confirmed to contain the exact public `Sigil-Core/warrant-core` `repository.url`.
2. An audited bootstrap commit set the package version to `0.1.0-rc.0`, updated the lockfile, and created the non-`v*` Git tag `bootstrap-0.1.0-rc.0`, which did not match the release workflow trigger.
3. The full local release checks ran, the prerelease tarball was created, and its SHA-256 was recorded in the release evidence.
4. The approved npm owner authenticated in an interactive terminal and published only the prerelease with provenance disabled under the `bootstrap` tag. The publish did not use the `latest` tag.
5. The npm package settings were configured with the GitHub Actions trusted publisher for organization `Sigil-Core`, repository `warrant-core`, workflow filename `publish.yml`, and the `npm publish` permission.
6. The reviewed stable `0.1.0` commit set `package.json` and `package-lock.json` to `0.1.0` and used the exact `v0.1.0` tag. The workflow published that immutable first stable version through npm OIDC.

Do not repeat the bootstrap or use owner-authenticated publication for a later release. For every later stable release, including `0.2.0`, update the package and lockfile to the exact new version and push the matching `v` tag so the configured trusted publisher runs `.github/workflows/publish.yml`. The workflow intentionally contains no npm write token. See npm's [trusted publishing documentation](https://docs.npmjs.com/trusted-publishers/) for the current registry requirements.
