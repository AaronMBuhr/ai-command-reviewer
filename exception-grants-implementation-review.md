# Exception Grants: Implementation Review — Second Pass

Reviewed: 2026-11-19

**Verdict: Revision required.** One Major and one Minor finding remain in the implementation now covering phases 1–8. The two findings from the first pass are resolved. Automated checks pass, but the new approval-scope defect must be corrected, and the planned manual release checks remain outstanding.

## Scope and snapshot

Reviewed commit `ba2b515a32d8e57cd11efce966f0c21f8d740241`. The working tree was clean at the start. This review updates only this document.

The review covers the Python grant reader and hook integration, the new PowerShell writer and setup script, the `aiallow` CLI, installation and documentation changes, and their tests. The primary new focus was phases 5–8: request conversion and confirmation, write and repair paths, mutex use, setup/reset, launch arguments, and cross-language validation.

Authoritative documents:

| Artifact | SHA-256 |
|---|---|
| `exception-grants-design.md`, revision 4 | `C5C3298183B5310673A6EC25F531BC8500E756DE33C6B8485520DC8F27E5CB53` |
| `exception-grants-implementation-plan.md`, revision 3 with implementation notes | `C05407A10E9CB33801E3BE770FA8141C9C54B21428DC2D995F6233EC6C45D7A0` |

This remains a standalone review. There is no workflow state file, and no implementation or plan files were changed.

## Previous findings

| ID | Disposition | Evidence |
|---|---|---|
| CODE-001: reviewer-skip test could swallow its own failure | Resolved | `tests/test_grant_review.py:80` now records calls to `_external_review_with_deadline` and asserts the list is empty after review returns. The suite passes with this assertion. |
| CODE-002: ACL fixture generator used a Python 3.10-only argument | Resolved by inspection | `tests/fixtures/acl/make_fixtures.py:172` now writes encoded bytes, preserving LF without `write_text(newline=...)`. Python 3.9 execution was not repeated locally. |

## CODE-003: Save the scope the user actually approved

Severity: **Major**. Confidence: High.

Location: `grant-writer/grant-writer.ps1:949` (`ConvertTo-Grant`), `:1138` (`Get-ExpiryDescription`), and `:1322–1325` (`Invoke-Add`).

**Expected:** Design section 1 requires that what the user approves is what gets allowed. Section 6 requires the resolved repository root to be shown in the confirmation.

**Observed:** The initial conversion resolves the repository root and builds the record used for the confirmation. Changing the expiry also performs a fresh conversion. After Approve, `Invoke-Add` calls `ConvertTo-Grant` yet again and writes that new record. Each conversion independently calls `Get-RepoRoot`; the dialog returns only an expiry string, not the record it displayed.

The grant mutex serializes grant operations, but it does not prevent an ordinary repository operation from adding or removing a `.git` marker while the dialog is open. For example, if a nested repository marker is removed and a parent repository remains, the final conversion selects the parent. The stored grant then covers more starting folders than the user approved.

**Evidence:** A read-only Windows PowerShell 5.1 probe loaded the writer with `-LibraryOnly`, built a valid repository-scoped request, and replaced only `Get-RepoRoot` in memory to simulate the filesystem result changing between the same two conversions used by `Invoke-Add`. It produced:

```text
Displayed path: E:\Source\Mine\Claude-code-ai-validate-pretool
Final path: E:\Source\Mine
Final validation error:
```

The second record passed stored-record validation. The probe performed no grant write, repository modification, elevation, or dialog interaction. The source establishes that the second conversion is the record sent to the write function.

**Consequence:** A valid grant can authorize a broader repository scope than the last confirmation displayed. This is a confirmation-integrity defect even under the accepted guardrail threat model; it does not require a hostile agent.

**Recommended change:** Resolve the scope once, retain the candidate record associated with the displayed description, and return that candidate on approval. Expiry changes should update the expiry on the retained scope and regenerate the description from that candidate. Persist the approved record. If a filesystem recheck is necessary, reject or request renewed confirmation when it changes the scope; never silently substitute a new root.

**Verification required:** Add a regression test with changing repository-root results across the confirmation boundary. Assert that the persisted path equals the last displayed path, or that the operation stops and asks for renewed confirmation. Cover both the initial expiry and a changed expiry. This can use stubbed UI and write functions without elevating or changing a real store.

## CODE-004: Propagate failure of setup's final check

Severity: **Minor**. Confidence: High.

Location: `.claude/hooks/aiallow.py:223–239` (`cmd_setup`).

**Expected:** Setup's final unelevated verification is part of establishing that the store is usable. If it fails after the elevated child reports success, the overall command should return a failure status.

**Observed:** `cmd_setup` calls `cmd_check(settings)`, discards its result, and returns the elevated child's code. With a successful child and a failing reader check, the command prints “Done.” followed by “Not protected” and exits 0.

**Evidence:** A Python probe mocked `run_elevated` to return 0 and `check_store` to report a post-setup integrity failure. Calling the real `cmd_setup` printed:

```text
Done.

Not protected: C:\ProgramData\cc-ai-review\grants.jsonl
  - post-setup integrity failure
cmd_setup exit: 0
```

No process was launched and no store was modified.

**Consequence:** A caller or automation sees success even though the required final check reports failure. The hook itself still fails safe; this is an outcome-reporting defect.

**Recommended change:** Preserve a nonzero child exit code. When the child succeeds, return the final check's code. Avoid the unqualified completion message until both stages succeed. Add tests for child success/check failure, both succeeding, and child failure.

## Verification performed

Commands run from the repository on Windows:

```powershell
& 'C:\Users\aaron\anaconda3\envs\mypython312\python.exe' -B -m pytest -q -o addopts='' -p no:cacheprovider
& 'C:\Users\aaron\anaconda3\envs\mypython312\python.exe' -B -m ruff check . --no-cache
git diff --check
```

Results:

- **844 tests passed in 94.57 seconds**, with no skips reported.
- Ruff: all checks passed.
- Diff whitespace check: passed on the clean implementation snapshot.
- Read-only probes confirmed CODE-003 and CODE-004 as described above.

The suite exercises Python/PowerShell request and file fixtures, ACL parity fixtures, conversion and description goldens, diff boundaries, rejection of a user-owned store, mutex contention, library-only loading, the no-cmdlet AST check, setup planning, mocked CLI launches, all six adapter grant round trips, and existing hook behavior.

The previous shared-module installer fix remains present. Setup planning is dispatched before its library import, and the actual writer's library-only mode returns before action dispatch. The setup and writer both use the same named mutex. These are positive results, but they do not substitute for successful privileged operation tests.

## Remaining verification and release limits

The implementation plan's section 15 explicitly records the manual release checks and the Claude Code `! aiallow` check as not done. This review did not perform them.

Before treating the feature as release-ready, record the planned disposable-machine evidence for actual UAC approval/decline, successful protected writes and post-replacement permissions, add/revoke/edit interaction, setup/update/reset, and failure recovery. Exercise the real approval dialogs, including expiry changes and cancellation. Current tests largely reach the write actions' refusal paths; successful commits and their outcome codes have not been demonstrated by this review.

The local run used Windows Python 3.12 and Windows PowerShell 5.1. The Python 3.9/3.11/3.13 and Ubuntu CI matrix was not rerun or independently verified. No Linux-container execution was necessary for the Windows-only writer, but portable Python compatibility still depends on that matrix.

No real UAC launch, privileged store mutation, ACL change, installation, or manual UI action was performed. The documented guardrail threat model and accepted hook check/read race remain unchanged.

## Next action

Blocking finding: **CODE-003**. Nonblocking finding: **CODE-004**. Closed findings: CODE-001 and CODE-002.

The next implementer should disposition both new findings and make focused corrections with regression tests. No implementation fixes were made in this review.

Paste-ready prompt:

> Read exception-grants-implementation-review.md. Disposition CODE-003 and CODE-004, fix the accepted findings, and add focused regression tests. Preserve the exact scope shown in the approval dialog and propagate setup's final verification failure. Run the relevant tests and lint checks, then report the results. Keep the manual privileged release checks explicitly outstanding until performed in a disposable environment.
