# Security policy

## Scope

This package handles policy parsing, canonical serialization, hashes, commitment serialization, signature-block boundaries, and runtime cryptographic adapters. Treat changes to any of those behaviors as security-relevant.

The package does not enforce a policy at an execution boundary. Callers must validate their own inputs, select the intended canonicalization profile, verify signatures against an independently trusted key, and enforce any resulting decision before execution.

## Supported versions

Only the latest released `0.x` version receives security fixes before the first stable release. Consumers must pin the exact version they have reviewed.

## Reporting a vulnerability

Do not open a public issue for a suspected parsing, canonicalization, hash, signature, or adapter vulnerability.

Use the repository's private GitHub security advisory reporting path. If private reporting has not been enabled, contact the repository owner through GitHub before disclosing technical details publicly. Include a minimal reproducer, affected version, runtime, expected behavior, actual behavior, and any known exploit path.

## Security release expectations

- Preserve the vulnerable artifact and publish a new immutable version. Do not retag or replace an existing release.
- Add a regression vector for the reported behavior.
- Verify browser, Node.js, and Workers parity for affected canonicalization or cryptographic paths.
- Document any required consumer upgrade and exact-version change.
