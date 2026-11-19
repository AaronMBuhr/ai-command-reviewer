# Exception Grants: Implementation Plan Review — Revision 2

Reviewed: 2026-11-19  
Artifact: `exception-grants-implementation-plan.md`, revision 2  
Design baseline: amended `exception-grants-design.md`, labeled revision 4  
Verdict: **Approved with notes**

Revision 2 addresses all five previous major findings. The installer changes now accompany the new import, JSON objects preserve key case, repair diff work is bounded, automated setup tests avoid the real store, and Python/.NET ACL evaluation uses raw descriptors with shared fixtures.

The plan is ready to guide implementation once the small test-contract corrections below are incorporated. No remaining Blocker or Major finding is identified. This is approval of the plan, not evidence that the feature is implemented or ready for release.

## Evidence and scope

Read the revised plan, its disposition table, the prior review, and the amended design's corresponding provisions. Confirmed that the design now records the scope refinements instead of leaving them as undeclared plan departures. No grant implementation was found.

A harmless Windows PowerShell 5.1 probe confirmed that the proposed ordinal `OrderedDictionary` preserves `name` and `Name` as two distinct entries. The earlier case-merging finding is therefore resolved by the proposed representation.

Windows-only, exact-command grants, the explicit installer trust exception, and the stated guardrail threat model remain the review scope. No removed feature or broader security architecture is requested.

## Disposition of previous findings

| ID | Status | Revision 2 assessment |
|---|---|---|
| PLAN-001 | Resolved in plan | Both installers change in Phase 4, with dependency coverage and copied-artifact execution checks. |
| PLAN-002 | Resolved in plan | Ordinal dictionaries and schema-key sets preserve case; field access avoids case-insensitive properties. |
| PLAN-003 | Resolved in plan; test correction below | LCS has an explicit work bound and a complete-output fallback. |
| PLAN-004 | Resolved in plan | Real-store mutation is removed from automated tests; setup decisions use a read-only interface. |
| PLAN-005 | Resolved in plan | Both implementations inspect raw ACE types; ancestors reject NULL/unsupported DACLs; binary fixtures exercise parity. |
| PLAN-006 | Resolved in plan | False-like non-mappings are rejected, error prefixes are correct, and drive-absolute validation is explicit. |
| PLAN-007 | Resolved in plan | Design amendments are listed and reflected in the design; unsupported cwd no longer silently becomes `any`. |
| PLAN-008 | Resolved in plan | Custom stores are explicitly manual provisioning, and setup refuses them. |
| PLAN-009 | Resolved in plan; AST integration note below | `Set-StrictMode` is removed; AST checks replace the regex as the main command-invocation check. |

The previous additional clarifications are also substantially addressed: randomized record fields receive separate assertions, post-write uncertainty has a defined failure result, code-point lengths have boundary cases, SID numeric limits are explicit, and test paths are repository-anchored.

## Minor corrections

### PLAN-010 — Minor: the diff fixture expects the wrong branch

**Location:** D20, section 7.4, and Phase 5 tests. **Confidence: high.**

The algorithm uses LCS when old-line count × new-line count is at most 1,000,000. The test says a 5,000-line old file and 10-line edited file use the full-diff path. Their product is 50,000, so the specified algorithm selects LCS, not the remove-all/add-all fallback.

**Suggested change:** assert `lcs` for that case, or change the dimensions if the intent is to test fallback. Retain the 200,000-by-10 case for `fallback`. Add an exact-threshold and just-over-threshold pair, and use a sufficiently wide numeric type for the product before deciding which branch to allocate.

**Why this is minor:** the resource-bound design is fixed; one expected test outcome contradicts it.

**Verify:** branch choice, complete emitted changes, and cancellation/cleanup for both algorithms. Do not weaken the bound to satisfy an inconsistent test.

### PLAN-011 — Minor: distinguish portable Windows-path fixtures from real conversion fixtures

**Location:** sections 2.1, 2.2, and Phase 2/5 tests. **Confidence: high.**

The placeholder rule substitutes actual temp paths before Python validation, but Phase 2 must run on Ubuntu and validates only drive-letter Windows paths. Ubuntu's actual `tmp_path` produces a POSIX path, so an otherwise valid `{TMP}` fixture would fail the Windows-path rule.

Pure Python request validation does not inspect filesystem existence; writer conversion does. These two uses need different fixture expansion rules.

**Suggested change:** use deterministic lexical Windows paths for platform-independent validation fixtures. In Windows writer/conversion tests, expand placeholders to real Windows temp directories and normalize the expected fields accordingly. Keep filesystem conversion expectations separate from pure schema expectations. Do not relax Windows-path validation on Ubuntu merely to make fixtures pass.

**Why this is minor:** the runtime rule is correct; fixture preparation needs to honor the different validation layers.

**Verify:** all pure cases pass with the same verdicts on Ubuntu and Windows, while conversion cases use existing Windows temp folders/repositories.

### PLAN-012 — Minor: extend the setup AST check to the permitted imported helpers

**Location:** A18, Phase 5 AST helper, section 8, and Phase 6 tests. **Confidence: high.**

The shown AST checker allows calls only to functions defined in the file being checked. Setup now dot-sources the writer and calls its integrity/security helpers. Merely exempting the one dot-source command does not add those imported helper names to the checker's allowed set, so legitimate setup calls can still be rejected.

**Suggested change:** for setup only, combine definitions from the setup file and the explicitly designated writer source, while independently checking the writer's AST. Permit precisely the documented `-LibraryOnly` import shape. Do not execute the import to discover functions, and do not turn the exception into a general permission for dynamic invocation or arbitrary imports.

Also keep setup's entry-point names distinct from imported writer entry points, or explicitly define loading order so dot-sourcing cannot overwrite the intended setup dispatcher.

**Why this is minor:** sharing trusted installer helpers is consistent with the declared exception; the static test needs to understand that exact relationship.

**Verify:** a setup sample calling a permitted imported helper passes; an unapproved cmdlet, another dot-source, and dynamic invocation fail. Check that loading the library does not dispatch a writer action or replace setup's entry point.

### PLAN-013 — Minor: specify the read-only setup-plan interface completely

**Location:** section 8 parameters, setup steps, and Phase 6 tests. **Confidence: high.**

The test section introduces `-PlanOnly` and supplied inspected state, but the parameter list and main dispatch only define `-Reset`, `-SourceWriter`, and `-ProgramData`. The intended safe test seam is clear, but its actual inputs and execution boundary are not.

**Suggested change:** define the input format/parameters for `Get-SetupPlan`, including existing backup names and the timestamp. Dispatch plan-only mode before mutex acquisition, real-store inspection, dialogs, and mutations. Make the plan-only result descriptive data; it must not act as authorization for a later production write based on supplied state.

**Why this is minor:** this is completion of the chosen read-only testing interface, not a request for a production safety bypass.

**Verify:** every decision combination using supplied state, with real filesystem/security/process operations made to fail if called. Plan-only must still succeed without touching them.

## Implementation checkpoints

These are implementation-review checks, not additional requests to redesign the plan:

- **Raw descriptor parsing:** enforce containment inside the declared ACL/ACE structures, not just the outer byte-buffer length. An ACE's SID must fit inside its `AceSize`, and ACEs must fit inside `AclSize`. Add malformed nested-size fixtures, not only truncated outer buffers.
- **PowerShell function results:** suppress incidental method output and preserve JSON arrays as arrays for zero, one, and many elements. Test the actual writer parser/serializer round trip; PowerShell's pipeline enumeration can otherwise change the returned shape.
- **Canonical fixtures:** description output must not depend on the machine's local timezone, locale, account-display lookup, or random ID unless those portions are normalized or asserted separately. The revised converted-record comparison already provides a good pattern.
- **Library-only behavior:** ensure loading definitions returns before action dispatch. The writer's `-Now` test seam must remain ignored by write actions.
- **Validation parity:** enforce the existing shared fixtures before integrating an alternative parser under R3. Any newly discovered disagreement should be fixed at the input contract/implementation boundary, not by weakening one side's acceptance rules.
- **Release evidence:** successful protected writes, ACLs after replacement, elevation, mutex concurrency, and reset remain disposable-environment release checks. Unit and validation-only tests cannot substitute for them.

## Recommended disposition

Proceed with the phase structure and incorporate the four minor corrections above as part of the plan/test definitions. Preserve the new installer boundary, raw-descriptor fixtures, safe setup testing, and bounded diff.

The next review should focus on actual implementation and phase-specific execution evidence. Another architectural design cycle is not indicated by this review.

## Verification and limits

This pass used document/source inspection and a small in-memory probe under Windows PowerShell 5.1:

```text
Ordinal OrderedDictionary:
Count: 2
name: first
Name: second

5000 × 10 = 50000
```

No implementation exists yet, so the baseline application test suite was not rerun. No elevation, setup/update/reset, ACL changes, real-store writes, or large diff allocations were performed.

Only this review document was revised. Reviewed plan SHA-256:

```text
F30047E4D56F8C91412F87E2D1725B7B976E6B652549000B450E1B6ACCAA91DB
```

The accompanying amended design still labels itself revision 4; its SHA-256 at review time was:

```text
C5C3298183B5310673A6EC25F531BC8500E756DE33C6B8485520DC8F27E5CB53
```
