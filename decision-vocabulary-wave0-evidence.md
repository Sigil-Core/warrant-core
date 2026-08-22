# Decision vocabulary Wave 0 evidence

Baseline: `origin/main` at `d66e5589e7b0501728f13872ecded82eb874e209`.

Method: case-sensitive `APPROVED` substring search over Git text files, with `.git` excluded. The result is 15 occurrences in 2 files. Each row below accounts for every occurrence on the baseline. Classifications use the design's closed set: gate-decision, hold-status, or foreign-domain.

| Baseline path | Lines | Classification | Reason |
| --- | --- | --- | --- |
| `test/runtime/launch-scenarios.test.ts` | 13, 14, 74, 75, 76, 87 | gate-decision | Launch-scenario authorization outcomes and accept-both compatibility assertions. |
| `test/vectors/launch-scenarios.json` | 22, 23, 45, 125, 126, 145, 224, 225, 246 | gate-decision | Frozen launch-scenario authorization outcomes and expected attestation decisions. |

Totals: gate-decision 15; hold-status 0; foreign-domain 0. Production `src` contains no success decision literal. The literal gate also scans the contract tests and vectors, where every exact compatibility occurrence is allowlisted with a count. It is advisory in Wave 1. `npm run decision:gate:blocking` is the Wave 3 switch. The negative-control test plants one additional occurrence and proves blocking mode exits nonzero while advisory mode reports it.

## Wave 3 applicability and gate state

At Wave 3 base `021d8a127e1218f6acac68cb4d744a3b2f8b90da`, this
repository has zero applicable execution-authorizing entry points. The package
parses and transforms policy artifacts. It does not execute an authorized
action or enforce a decision at an action boundary. Capability and
import/architecture gates are therefore not applicable under the approved
Revision 5 classification.

Literal hygiene remains applicable. CI and the release workflow now invoke
`npm run decision:gate:blocking`. The committed negative control proves that a
planted unclassified literal exits nonzero, and a workflow regression test
keeps both invocations on the blocking command.
