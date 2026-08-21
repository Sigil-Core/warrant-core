# Decision vocabulary Wave 0 evidence

Baseline: `origin/main` at `d66e5589e7b0501728f13872ecded82eb874e209`.

Method: case-sensitive `APPROVED` substring search over Git text files, with `.git` excluded. The result is 15 occurrences in 2 files. Each row below accounts for every occurrence on the baseline. Classifications use the design's closed set: gate-decision, hold-status, or foreign-domain.

| Baseline path | Lines | Classification | Reason |
| --- | --- | --- | --- |
| `test/runtime/launch-scenarios.test.ts` | 13, 14, 74, 75, 76, 87 | gate-decision | Launch-scenario authorization outcomes and accept-both compatibility assertions. |
| `test/vectors/launch-scenarios.json` | 22, 23, 45, 125, 126, 145, 224, 225, 246 | gate-decision | Frozen launch-scenario authorization outcomes and expected attestation decisions. |

Totals: gate-decision 15; hold-status 0; foreign-domain 0. Production `src` contains no success decision literal. The literal gate also scans the contract tests and vectors, where every exact compatibility occurrence is allowlisted with a count. It is advisory in Wave 1. `npm run decision:gate:blocking` is the Wave 3 switch. The negative-control test plants one additional occurrence and proves blocking mode exits nonzero while advisory mode reports it.
