# Exception Grants: Design Review — Revision 4

Reviewed: 2026-11-19  
Artifact: `exception-grants-design.md`, revision 4  
Verdict: **Approved with notes**

Revision 4 resolves the previous major finding and the repair/reset gaps. The design is sufficiently defined to proceed to implementation within its stated Windows-only, exact-command, guardrail scope. The remaining notes are limited documentation and lifecycle clarifications, not reasons for another architecture change.

This is design approval, not implementation or release approval. The successful-write, permissions, concurrency, and recovery checks in section 11 remain release requirements.

## Scope and evidence

Read revision 4 in full, compared the revision 3 review, checked the working tree for implementation changes, and consulted Microsoft's synchronization-object documentation. No exception implementation was found.

This review accepts the declared installer/update trust exception, the well-meaning-agent threat model, and the documented check/read gap. It does not ask to restore prefixes, POSIX support, citation, or use limits.

## Disposition of previous findings

| ID | Status | Assessment |
|---|---|---|
| EG-001 | Resolved in design | Writer integrity is checked before normal elevation; setup/update are explicit trusted-installer exceptions. |
| EG-002 | Resolved in design | File-specific ACL/owner checks include the writer; setup and updates establish its permissions explicitly. |
| EG-003 | Closed for v1 | POSIX support was removed. |
| EG-004 | Resolved | No untrusted consumption counter or authorization-dependent activity log. |
| EG-005 | Resolved | Invalid snapshots fail closed; revoke order is explicit. |
| EG-006 | Resolved | Exact raw-command matching. |
| EG-007 | Closed for v1 | Prefix grants were removed. |
| EG-008 | Resolved | Full requests, generated descriptions, and mandatory confirmation replace approval IDs. |
| EG-009 | Resolved | SID matching and per-user revocation. |
| EG-010 | Resolved in design; minor API note below | One named mutex coordinates writes, setup, update, and reset independently of the store directory. |
| EG-011 | Resolved | Shared finalization and stored extra lines preserve logging and rendering. |
| EG-012 | Resolved in intent; wording notes below | Initial-file creation and recovery are defined; preflight/update wording needs alignment. |
| EG-013 | Resolved | Tool identity means the core's actual label, with host-specific help. |
| EG-014 | Resolved in design | Stored field tables and separate read-only request/file validation modes support shared fixtures. |
| EG-015 | Resolved | Repair accepts invalid current contents, validates the edited result, displays a line diff, and redirects oversized files to reset. |

“Resolved” refers to the specification. Implementation tests must still establish that the code follows it.

## Minor corrections

### EG-016 — Minor: named mutexes have permissions and creation/opening can fail

**Location:** revision summary and section 6.1. **Confidence: high.**

Replacing the lock file with a named mutex is a suitable way to coordinate across directory reset. However, “it has no permissions to check” is inaccurate. Windows mutexes are securable kernel objects; their default security descriptor comes from the creator's token, and opening them checks access rights. The .NET constructor can fail for access denial or a same-name object of a different type. See [Synchronization Object Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/sync/synchronization-object-security-and-access-rights) and the [Mutex constructor reference](https://learn.microsoft.com/en-us/dotnet/api/system.threading.mutex.-ctor?view=net-7.0).

**Suggested correction:** say that the mutex has no *filesystem* integrity dependency. Specify creation/opening rights for the supported elevated callers, distinguish access/name errors from ordinary contention, and refuse the operation on any mutex failure. Never continue without the mutex or fall back to a different name. Retain the accepted denial-of-service limitation; preventing deliberate name pre-creation is outside this threat model.

Use acquire/release/dispose in a guaranteed cleanup path, releasing only when ownership was acquired. Keep the documented abandoned-mutex behavior and subsequent file validation.

**Why this is minor:** the coordination architecture is sound. These failures should stop an operation, not widen authorization; the specification needs accurate API behavior and diagnostics.

**Verify:** normal contention, access-denied existing mutex, same-name different object type, abandoned holder, and cleanup after cancellation/errors. Every unsuccessful acquisition leaves the store unchanged.

### EG-012 — Minor: explicitly exempt setup/reset from installed-writer preflight

**Location:** sections 1.2, 4.1, 5, and 6. **Confidence: high.**

Section 4.1 says the unelevated integrity check runs “before every UAC request,” including the installed writer. On first installation that file does not exist; reset may be needed precisely because its protection is invalid. Applying the wording literally prevents the documented installation/recovery path.

The explicit installer exception in sections 1.2 and 5 already makes the intended behavior clear enough to resolve this without redesign.

**Suggested correction:** scope installed-writer preflight to normal `add`, `revoke`, and `edit` launches. Setup/update/reset launch the explicit installer under section 1.2 and perform their own inspection/confirmation rules. State that failure of normal preflight never silently selects the installer or reset.

**Why this is minor:** this is a conflict between a general sentence and an already-defined exception, not a missing trust model.

**Verify:** first setup without a writer, ordinary-operation refusal for an unsafe writer, and explicit reset of that installation. Each takes its intended path without automatic fallback.

### EG-012 — Minor: align the update test with refusal of unsafe existing files

**Location:** section 5 step 1 and section 11 manual test 8. **Confidence: high.**

Setup treats an existing installation as an update only if its administrative integrity check passes. If the writer has an untrusted owner or Users write access, setup must refuse. Manual test 8 then says, after introducing exactly that defect, “After an update, the writer's permissions are correct again.”

Those steps cannot both describe the same direct update attempt.

**Suggested correction:** keep inspect-before-mutate. Test normal update on a valid installation separately from recovery of an invalid writer. For the latter, confirm normal launch and ordinary setup refuse, then explicitly reset with backup preservation (or first restore the ACL manually if that is the documented maintenance procedure).

**Why this is minor:** the production rule is conservative and already defined; the test sequence needs to reflect it.

**Verify:** valid update preserves grants; invalid writer causes refusal without mutation; explicit recovery preserves the old history in the documented backup.

## Small editorial and implementation notes

- Section 7.3's escaped-duplicate-key example currently displays `"name"` twice. Use an actual escaped spelling in the second key so it illustrates the stated rule.
- Move “file over 1 MB” out of the filesystem-integrity test group into content validation, matching the new separation that enables repair.
- Remove the future POSIX lock-path aside from v1, or label it illustrative and unverified. A Windows-only design does not need to assert portability of a specific future lock location.
- Use explicit ordinal, case-sensitive command comparison in the Windows writer/validator, consistent with the raw-text contract. Do not let language-default comparison behavior weaken that contract.
- Keep the case-insensitive Windows path policy distinct from exact command/tool comparison, and preserve the component-based containment tests already specified.

These are implementation guidance or editorial corrections, not additional unresolved major findings.

## Recommended disposition

Proceed with the planned implementation phases, incorporating the three minor corrections above. Preserve the current scope and shared fixture approach. The next substantive review should inspect actual implementation and execution evidence, especially elevated writer launch, mutex handling, permissions after replacement, and repair/reset behavior.

No remaining Blocker or Major finding is identified in this design review.

## Verification and limits

This pass used document review, repository inspection, and official Windows/.NET documentation. No code changed, and the existing test suite was not rerun. The prior 357 passing tests remain historical baseline evidence; they do not test this unimplemented feature.

No elevation, mutex experiment, setup/update/reset, permission modification, or live host operation was performed. The Windows runtime behavior remains to be verified during implementation and through section 11's release checks.

Only the review document was revised. Reviewed design SHA-256:

```text
7FCCBDE92E62856CAF9860F6104C8ED00BAA284FE43B5C890526D59FD8DD053F
```
