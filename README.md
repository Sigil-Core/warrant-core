# @sigilcore/warrant-core

Platform-neutral primitives for Sigil Warrant policies. The package provides the policy parser, the established Warrant policy-hash canonicalizer, the `pg-commit-v1` commitment canonicalizer, SHA-256 adapter boundaries, and signature-block helpers.

The root entry point has no Node.js, browser, Cloudflare, network, or framework dependency. Import a runtime-specific cryptographic adapter explicitly.

## Installation

This package is published as a public npm package after its initial owner-controlled release.

```sh
npm install @sigilcore/warrant-core@0.2.1
```

Security-sensitive consumers must pin the full reviewed version. Do not use a caret, tilde, range, or the `latest` tag.

## Public API

```ts
import {
  appendSignatureBlock,
  canonicalizePgCommitV1,
  canonicalizePolicyObject,
  hashPgCommitV1,
  hashPolicy,
  parsePolicyMarkdown,
  serializePolicyMarkdown,
  signedEnvelopeParse,
  splitSignatureBlock,
  unsignedSigningPayload,
  validateAndParsePolicyMarkdown,
  validatePolicyMarkdown,
} from "@sigilcore/warrant-core";
```

| Export | Contract |
| --- | --- |
| `parsePolicyMarkdown(markdown)` | Parses a supported `warranty.md` body into `ParsedPolicy`. It accepts unversioned Policy 0.x, Policy 1.x, 2.0.x, and 2.1.x policy input, and rejects unknown or duplicate policy blocks, unsupported versions, known policy fields placed at document root, malformed explicit limits, duplicate scalar, generic-control, or dynamic-cap declarations in `soft_limits`, unknown custom-rule syntax in every version, invalid Policy 2.x syntax, false-only no-op controls, and empty Policy 2.1 resource lists. Policy 2.1 resource profiles may omit fields or `require_shim`; use `lintPolicyAdvisories` for their non-blocking authoring warnings. Version 0.2.0 adds the public Policy 2.1 authoring core and strict signed-envelope handling while retaining the 0.1.1 numeric safety hardening: malformed or nonpositive transaction, consensus, and daily limits reject rather than silently removing enforcement, and token decimals must be a complete integer from 0 through 36. A `matches` declaration uses the same comma-separated list semantics as Sigilcore's Manual Warrant and Warrant Builder parser. |
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
| `validatePolicyMarkdown(markdown, options?)` | Returns all independent authoring diagnostics as stable `{ code, path, message, surface_hint }` values. |
| `validateAndParsePolicyMarkdown(markdown, options?)` | Returns the complete diagnostic list and, only on success, the parsed policy. Callers apply authoring state only when `errors` is empty. |
| `serializePolicyMarkdown(policy)` | Emits the canonical Phase 1 Markdown body for a parsed policy. Page cutover remains a later phase. |
| `AUTHORING_CAPABILITY_MANIFEST` | Executable per-field author/import/preserve/deploy contract for `manual-form`, `manual-advanced`, and `builder`. |

The root entry point also exports the `ParsedPolicy`, `CryptoAdapter`, `JsonValue`, and `SplitSignatureBlock` types.

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

New signing and verification integrations use `signedEnvelopeParse`,
`unsignedSigningPayload`, and `emit`. They validate UTF-8, preserve BOM and
Unicode whitespace bytes, and strip only trailing ASCII space, tab, CR, and LF.
The older string helpers remain compatibility wrappers and are not an exact-byte
signing API.

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

The package keeps a frozen accepted-and-rejected parser corpus against Sigil Sign production merge `a6673f9c8b50f6b8fca5f4fd15cbc6c42671f656`. `execution_limits` preserves approval-only, shim-only, and combined controls in canonical output. A standalone `require_shim: false` is rejected because it has no enforcement effect. Sigilcore consumer compatibility is authoritative where its committed parser contract intentionally differs from this older Sign corpus. After building both repositories, run the local differential gate with the absolute Sigil Sign checkout path:

```sh
npm run test:sign-parity -- /absolute/path/to/sigil-sign
```

The gate signs only with the published RFC 8032 test key. It compares all six pinned canonical policies plus the parser edge-case corpus against Sigil Sign's compiled parser. It never reads an operator or production key.

That frozen corpus records legacy parser compatibility behaviors from the pinned Sign parser: ETH amount and consensus threshold fields accept a leading numeric prefix, and chain entries use their leading integer while filtering nonpositive or nonnumeric results. Numeric-prefix ETH parsing is retained for established policy hashes, while a configured nonnumeric or nonpositive limit rejects instead of removing a default or silently omitting enforcement. Token decimals are a deliberate hardening exception: they require a complete integer token from 0 through 36 in Policy 1.x and 2.x. Daily EVM limits retain a nonnumeric suffix compatibility prefix such as `1ETH`, but the numeric prefix itself must use fixed-point notation with at most six decimal places in every supported version. Exponent notation and source overprecision reject before Number conversion. Treat `parsePolicyMarkdown` as a compatibility parser with explicit hardening, not as a standalone lexical validator. Changing a frozen behavior requires coordinated parser changes, new vectors, and synchronized consumer releases.

## Release and npm trusted publishing

`.github/workflows/publish.yml` publishes only an unpublished stable semantic version whose tag exactly equals `v` plus the package version. Prerelease and build-metadata versions fail before the OIDC publish job. The workflow runs on a GitHub-hosted runner with Node 24, npm 11.5.1 or later, `id-token: write`, and `contents: read`. It tests, builds, packs, and inspects the tarball before `npm publish --access public --provenance`. It fails before publication if that immutable npm version already exists.

The initial npm package bootstrap is complete. The following steps are a non-repeatable historical record:

1. `package.json` was confirmed to contain the exact public `Sigil-Core/warrant-core` `repository.url`.
2. An audited bootstrap commit set the package version to `0.1.0-rc.0`, updated the lockfile, and created the non-`v*` Git tag `bootstrap-0.1.0-rc.0`, which did not match the release workflow trigger.
3. The full local release checks ran, the prerelease tarball was created, and its SHA-256 was recorded in the release evidence.
4. The approved npm owner authenticated in an interactive terminal and published only the prerelease with provenance disabled under the `bootstrap` tag. The publish did not use the `latest` tag.
5. The npm package settings were configured with the GitHub Actions trusted publisher for organization `Sigil-Core`, repository `warrant-core`, workflow filename `publish.yml`, and the `npm publish` permission.
6. The reviewed stable `0.1.0` commit set `package.json` and `package-lock.json` to `0.1.0` and used the exact `v0.1.0` tag. The workflow published that immutable first stable version through npm OIDC.

Do not repeat the bootstrap or use owner-authenticated publication for a later release. For every later stable release, including `0.2.0`, update the package and lockfile to the exact new version and push the matching `v` tag so the configured trusted publisher runs `.github/workflows/publish.yml`. The workflow intentionally contains no npm write token. See npm's [trusted publishing documentation](https://docs.npmjs.com/trusted-publishers/) for the current registry requirements.
