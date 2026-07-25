# @sigilcore/warrant-core agent guide

## Purpose

`@sigilcore/warrant-core` is the platform-neutral source of truth for Sigil Warrant policy parsing, canonical serialization, policy hashing, Proving Ground commitments, and signature-block handling. It must run in browsers, Node.js, and Cloudflare Workers without changing policy bytes or canonical output.

## Required reading

1. Read `_MANIFEST.md` before task work.
2. Read `README.md`, `package.json`, and the relevant source module before changing public behavior.
3. Read `SECURITY.md` before changing parsing, canonicalization, hashing, or cryptographic adapters.

## Contract rules

- Preserve the documented canonicalization profile. A profile change is a breaking security change, even when TypeScript types still compile.
- Keep the core free of React, Node-only imports, browser globals, Cloudflare bindings, and network calls.
- Route cryptography through the runtime adapter exports. Do not select a runtime adapter implicitly from the core entry point.
- Preserve the documented unsigned-byte contract when splitting or appending a signature block. `splitSignatureBlock` normalizes trailing whitespace, so do not use it where raw-byte preservation is required.
- Treat malformed policy input as untrusted. Reject unsupported syntax instead of silently dropping fields.
- Update vectors and runtime-parity tests with every behavior change.

## Release rules

- Consumers pin the exact package version. Do not use a caret, tilde, range, or `latest` tag for a security-sensitive consumer.
- `package.json` owns the package name, version, exports, and npm publication settings. Do not alter it without explicit release-owner approval.
- CI must pass on Node 22 and 24. A release tag must be `v` plus the exact `package.json` version.
- npm publication uses GitHub Actions OIDC trusted publishing. Never add an npm write token to repository secrets or workflow configuration.
- The first npm package creation and trusted-publisher configuration require the package owner to authenticate on npmjs.com. The workflow must not attempt that setup.

## Verification

Run these commands before handoff when package source changes:

```sh
npm ci
npm run typecheck
npm run test:node
npx playwright install chromium
npm run test:browser
npm run test:workers
npm run build
npm pack --json
```

Inspect the tarball contents and ensure only the public build and required package files ship.
