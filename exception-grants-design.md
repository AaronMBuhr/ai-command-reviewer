# Exception Grants: Design (revision 4)

Status: draft for external review. No code has been written.

Revision 4 answers the revision 3 review. Its main changes:

- The writer lock is now a **Windows named mutex** instead of a lock file. It doesn't depend
  on any file's permissions, and it survives `--reset` (section 6.1).
- The integrity rule now also covers the **writer script itself**, and it is checked before
  UAC (sections 4, 6).
- `edit` is now a separate **repair path** that shows a line diff (section 6.3).
- There are now two **read-only validation modes**, and field tables for stored records
  (sections 6.2, 7.2).

Revision 3 answered the revision 2 review. Three features were **cut** rather than patched:

- **Prefix grants.** Replaced by a list of exact commands.
- **Description citation (`cite`).** Removed.
- **Linux/macOS support.** v1 supports Windows only.

Section 13 maps every finding from both reviews to how this revision handles it.

## 1. What we are trying to do

The hook reviews each shell command an AI agent proposes and returns `allow`, `ask` or `deny`.
Sometimes the user wants a command the hook blocks or questions to go ahead anyway, for a
limited time. Today the only options are answering the host's `ask` prompt one command at a
time (where the host has one), or changing the policy for good. There is nothing for a hard
`deny`, and nothing for "allow this for the next hour".

The goal is a **temporary exception the user can grant without learning any syntax**:

1. The user asks the AI: "What permission do you need? Give it a short name."
2. The AI explains in plain language and gives a request block to copy. The hook's deny message
   includes the block already filled in, so the AI usually adds only a name and a reason.
3. The user copies the block and runs `aiallow add`. A UAC prompt appears. Then an admin-only
   tool describes, **in its own words**, exactly what the block would allow, and the user
   confirms.
4. The user tells the AI to retry. The hook sees the grant and allows the command.

Requirements:

- **Only the user can create a grant.** It needs a UAC prompt plus a confirmation shown by the
  admin-only tool.
- **What the user approves is what gets allowed.** The confirmation is generated from the
  request's fields, not from the AI's explanation.
- **Grants are precise.** They cover one or more exact commands, for one tool name, from a
  chosen folder or repo, for the user who granted them.
- **Grants end.** At a set time, or, if the user explicitly chooses, when revoked.
- **There is a history.** The grants file is append-only by convention and records every grant
  and revoke.
- **It works on every host the hook supports.** No adapter code changes are needed.
- **It fails safe.** Any problem with grants means "no grant" and normal review, never "allow".
- **Windows only in v1.** On other platforms the feature reports "not supported" and review
  continues as normal.

### 1.1 Threat model

This is a **guardrail against a well-meaning but mistaken AI**, the same model the hook already
documents in `SECURITY.md`. It is **not** a defence against an AI deliberately trying to get
around it. Such an AI could already edit the hook, its config or the host settings, all of
which are user-writable, and resisting it is out of scope. The gap between checking the grants
file and reading it (section 4.3) is accepted under this model.

Within this model, the design guards against:

- the AI granting itself an exception by mistake,
- the AI's explanation not matching its request,
- grants matching more than intended, and
- broken files, concurrent writes or permission mistakes silently widening what is allowed.

### 1.2 Elevation rule

**Day-to-day grant operations never run user-writable code with admin rights.** The one
deliberate exception is **setup and update** (section 5). That is an installer the user chooses
to run elevated, like any software install, and it is the moment trust is established.
Granting, revoking and editing never install or update anything.

## 2. Overview

```
AI: "I need to force-push feature/x. Request:"
    {"v":1,"name":"push-feature-x","commands":["git push --force-with-lease origin feature/x"],
     "tool":"Bash","where":"repo","cwd":"E:\\Source\\Mine\\proj","hosts":null,
     "expires":"30m","why":"The rebase rewrote history, so a normal push is rejected."}

User copies the block and runs:  aiallow add
   └─► UAC prompt
       └─► grant-writer.ps1  (admin-only folder, System32 PowerShell, .NET calls only)
             takes the writer mutex, reads the clipboard, validates, and shows its OWN description
             └─► user clicks Approve
                 └─► the grant is written to C:\ProgramData\cc-ai-review\grants.jsonl

User: "push-feature-x is granted, retry."
Hook: grants file passes the integrity rule ─► an active grant matches ─► allow
      (recorded in the decision log as source "grant", with the grant ID)
```

| Part | Runs as | Location | Trusted with |
|---|---|---|---|
| **Hook** (`review_core` plus new `exception_grants.py`) | the user | user profile (existing) | Reading grants |
| **`aiallow`** (Python CLI) | the user | next to the hooks | Nothing. It lists grants, runs checks, and launches the writer or setup. It never passes request contents. |
| **`grant-writer.ps1`** | admin, after UAC | admin-only folder | Validating, describing, confirming and writing grants |
| **`setup-grants.ps1`** | admin, after UAC | installer copy in the hook folder | One-time setup and updates (section 1.2) |
| **Grants file** | written by admin, readable by users | admin-only folder | The source of truth |

There is no separate activity log. The grants file holds every grant and revoke. Each grant
allow is written to the existing decision log (`policy.log_path`) whenever that log is on.

## 3. Configuration

```yaml
exceptions:
  # Master switch, off by default. While false, the hook never reads grants and
  # adds nothing to reasons.
  enabled: false

  # Protected grants file. null = C:\ProgramData\cc-ai-review\grants.jsonl
  grants_path: null
```

- `enabled` is parsed with the existing strict `coerce_bool`.
- `grants_path` must be null or a non-empty string. Any other type is a `ConfigError`, which
  fails closed. That includes a boolean produced by the environment parser from `off` or
  `false`.
- **A configurable path is safe.** The config file is user-writable, but the hook, the writer
  and `aiallow check` all apply the integrity rule in section 4 to whatever path is configured.
  Pointing the path at a folder the user controls just means grants are ignored.
- **A custom path is set up by hand.** `aiallow setup` provisions only the default location. If
  `grants_path` is set to anything else, setup refuses and explains why. An administrator must
  create the folder, the empty grants file and the writer copy there, with the permissions in
  section 5. `aiallow check` then reports whether that location passes the integrity rule.
  Custom paths are documented as an advanced option.
- On non-Windows platforms, `enabled: true` adds the note "Exception grants are not supported
  on this platform." to deny and ask reasons, and has no other effect.

## 4. Integrity rule (one definition for setup, writer and hook)

"Protected" means exactly the following, and the same code logic is applied everywhere. It
covers **filesystem protection only**. Whether the file's contents are valid, including the
size cap, is a separate check (section 7.3), so a protected but broken file can still be
repaired (section 6.3). The
hook gets each object's self-relative binary security descriptor through `ctypes`
(`GetNamedSecurityInfoW` and `GetSecurityDescriptorLength`) and parses it in pure Python. The
writer and setup get the same binary form through `GetSecurityDescriptorBinaryForm()` and
parse it with .NET's `RawSecurityDescriptor`. Shared hex-encoded descriptor fixtures
(section 11) keep the two implementations in agreement.

**Trusted principals:**

| Principal | SID |
|---|---|
| Administrators | `S-1-5-32-544` |
| SYSTEM | `S-1-5-18` |
| TrustedInstaller | `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464` |

**Write-type rights** (any of these bits in an access mask):

| Right | Mask |
|---|---|
| `FILE_WRITE_DATA` / `FILE_ADD_FILE` | `0x2` |
| `FILE_APPEND_DATA` / `FILE_ADD_SUBDIRECTORY` | `0x4` |
| `FILE_WRITE_EA` | `0x10` |
| `FILE_DELETE_CHILD` | `0x40` |
| `FILE_WRITE_ATTRIBUTES` | `0x100` |
| `DELETE` | `0x10000` |
| `WRITE_DAC` | `0x40000` |
| `WRITE_OWNER` | `0x80000` |
| `GENERIC_ALL` | `0x10000000` |
| `GENERIC_WRITE` | `0x40000000` |

**The grants folder, the grants file and the writer script (`grant-writer.ps1`) must each:**

Each of these is checked on its own permissions. Windows checks access against each file's
own security settings, so a protected folder doesn't guarantee that the files inside it are
protected.

1. be owned by a trusted principal;
2. not be a reparse point (no symlink or junction);
3. have a DACL that exists (no NULL DACL) and contains only standard allow and deny entries;
4. give no write-type right to anyone except trusted principals, in any entry that applies to
   the object itself. Inherit-only entries are ignored, since they don't apply to the object.
   Deny entries can only take rights away, so they never fail the check.

The folder must also be **protected from inheritance**, so a later permission change on the
parent can't flow into it.

**Every parent folder, up to the drive root, must:**

1. be owned by a trusted principal;
2. not be a reparse point;
3. have a permission list that exists (no NULL DACL, which would allow everyone everything);
4. contain only standard allow and deny entries. Unusual entry types fail rather than being
   guessed at;
5. give no untrusted principal `DELETE`, `FILE_DELETE_CHILD`, `WRITE_DAC`, `WRITE_OWNER` or
   `GENERIC_ALL` in an entry that applies to it. These are the rights that would let someone
   rename or replace a folder on the path, or change its permissions.

Both implementations (the Python hook and the .NET writer) evaluate the same **raw binary
security descriptor**, using the same entry types, flags and masks.

The default location passes this. `C:\ProgramData` lets Users create subfolders, but not
delete or rename them.

**Other checks:**

- **Elevated reader:** the hook treats an elevated process as untrusted, using
  `GetTokenInformation(TokenElevation)`. Grants never apply to an AI tool that is running as
  administrator.

Any failed check, or any error while checking, means "not protected". The hook then ignores
all grants, and the deny or ask reason says "Exception grants ignored: \<which check\>. Run
`aiallow check`."

### 4.1 Validation modes

- **Unelevated** (hook, `aiallow check`, and `aiallow` before launching `add`, `revoke` or
  `edit`): runs everything above, including the elevated-reader check. The hook checks the
  folder and the grants file. For those three actions, `aiallow` also checks the writer script
  **before asking for UAC**, so a writer with the wrong owner or permissions is refused before
  it ever runs as admin.

  **Setup, update and reset are exempt** from this pre-UAC check. On first install the writer
  doesn't exist yet, and reset is the way to recover from a broken one. They launch the
  installer under section 1.2, which does its own inspection (section 5). A failed pre-UAC check
  never automatically switches to setup or reset; it only says what to run.
- **Administrative** (setup, writer): runs everything except the elevated-reader check. The
  writer runs it on the folder, the grants file and itself before reading anything.

### 4.2 Commands no grant can unlock

A new check in `review_payload`, run before `local_review` and **only while exceptions are
enabled**, **denies** any command that mentions any of these:

- the grants folder,
- `grant-writer`,
- `setup-grants`, or
- `aiallow`.

Its flag, `exception-store-access`, is on a list of flags no grant can lift. File-edit tools
are already blocked from the grants folder by its permissions.

**Why it runs only while enabled:** with exceptions off there is nothing to protect. Running it
anyway would block every command that merely mentions `aiallow`, including work on this
repository itself. **Why it sits in `review_payload` rather than `local_review`:** it needs the
grants path from the exceptions settings, which `local_review` doesn't receive.

### 4.3 Accepted gap

The hook opens the grants file after checking it. The file could in theory be swapped between
the check and the read. This is accepted under the guardrail model and documented.

## 5. Setup and updates (`aiallow setup`)

`aiallow setup` launches `setup-grants.ps1` from the installed hook folder through UAC. It uses
`System32` PowerShell, `-NoProfile`, and .NET calls only. **This is the deliberate installer
exception in section 1.2.** The user is choosing to install software, and the script is
whatever version the user installed.

**Steps:**

0. **Take the named mutex** (section 6.1). If a grant window is open, stop and say so.
1. **Inspect before changing anything.**
   - If the folder doesn't exist, it is a fresh install (step 2).
   - If it exists and passes the administrative integrity check, it is an **update** (step 3).
   - If it exists and fails, setup **stops without changing anything**. It shows which check
     failed and offers `aiallow setup --reset`.
2. **Fresh install.**
   - Create the folder with `Directory.CreateDirectory(path, DirectorySecurity)`, so it gets
     its full permissions in the same call. The permissions, written in Windows' SDDL notation:

     ```
     O:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)
     ```

     In words: the owner is Administrators. The permission list is protected from inheritance
     and holds exactly three entries: full control for Administrators (`BA`) and SYSTEM
     (`SY`), and read-and-execute (`0x1200a9`) for Users (`BU`). `OICI` means files and
     subfolders inside inherit each entry. No other entries exist, so nothing left over can
     survive.
   - Create an empty `grants.jsonl`.
   - Copy in `grant-writer.ps1`.
   - **Set both files' permissions explicitly**, protected from inheritance, owner
     Administrators, with the same three entries. Don't rely on inheriting them.
3. **Update.** Replace `grant-writer.ps1`, then set its permissions explicitly again.
   **`grants.jsonl` is left untouched**, so history is kept.
4. **Verify.** Run the administrative integrity check on the folder, both files, and the
   parent folders. Then `aiallow` runs the unelevated check as a separate step.

**If a fresh install fails partway**, setup reports which step failed and leaves what it
created. Running setup again then finds a folder that either passes the check and is treated
as an update (if, say, only the final verify step failed), or fails it and is refused. In the
second case, `--reset` cleans up.

**`--reset`:**

- holds the same named mutex, so it can't run while a grant window is open;
- shows what it will do and asks for confirmation;
- renames the existing folder to `cc-ai-review.old-<UTC timestamp>`, adding `-2`, `-3` and so
  on if that name is taken, which keeps its history;
- then does a fresh install.

It never opens or trusts any file inside the old folder. If the rename fails, reset stops
without creating anything.

## 6. The writer (`grant-writer.ps1`)

**Started by `aiallow` through `Start-Process -Verb RunAs`:**

```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass
  -File C:\ProgramData\cc-ai-review\grant-writer.ps1 -Action <add|revoke|edit>
  -ForUser <SID> [-Name <name>] [-GrantsPath <path>]
```

Before asking for UAC, `aiallow` runs the unelevated integrity check on the writer script, its
folder and its parent folders (section 4.1). If that check fails, `aiallow` refuses to launch
the writer.

**It runs no user-writable code:**

- The interpreter is the one in `System32`.
- `-NoProfile` skips PowerShell profile scripts.
- The script itself is in the admin-only folder.
- It uses **.NET calls only**, for clipboard, JSON, files, permissions and its dialog. It never
  calls PowerShell commands that could auto-load modules from user-writable folders.
- It never reads the user-writable config.
- **It never runs Git.** The repo root is found by checking parent folders for a `.git` folder
  or file, using only `Directory.Exists` and `File.Exists` (a `.git` *file* marks a worktree
  root). The root it finds is shown in the confirmation.

**It treats every input as untrusted:**

- `-ForUser` and `-GrantsPath` are shown in the confirmation. The destination must pass the
  administrative integrity check.
- The request is read **from the clipboard by the writer itself**
  (`System.Windows.Forms.Clipboard.GetText()`). `aiallow` never passes it.

### 6.1 Transaction contract (EG-010)

**The lock is a Windows named mutex**, `Global\cc-ai-review-grants`. A named mutex is a lock
object Windows keeps in memory and finds by name. It is not a file, so:

- it doesn't depend on any **filesystem** permissions;
- it can't go missing; and
- it is unaffected when `--reset` renames the folder.

A mutex is still a Windows object with its own permissions. Creating or opening it can fail
for two reasons:

- access is denied (another program created it with restrictive permissions), or
- the name is already used by a different kind of object.

**Any mutex failure stops the operation, with a message saying which failure it was.** That is
distinct from ordinary contention ("Another grant window is open"). The writer never continues
without the mutex and never falls back to another name. All callers run elevated, so the
default permissions of a mutex created by one of them let the others open it.

Acquire, release and dispose happen in a `try`/`finally`. The mutex is released only if it was
actually acquired.

Windows releases it automatically if the holder exits or crashes. The writer treats .NET's
`AbandonedMutexException` (thrown when the previous holder crashed) as a successful acquire,
then validates the file as usual.

Setup, update, reset, `add`, `revoke` and `edit` all take this one mutex. Hook reads take no
lock. Any program, an AI tool included, could create a mutex with that name first. That can
only block grant windows ("Another grant window is open"), never allow anything, so it is
accepted under the guardrail model.

`add` and `revoke` follow these steps:

1. **Lock.** Acquire the mutex without waiting. If another process holds it, show "Another
   grant window is open" and exit. It is held until step 6, *including while the confirmation
   dialog is open*. That makes read, confirm and write one transaction, so a second writer
   can't work from a stale copy.
2. **Check.** Run the administrative integrity check (section 4.1).
3. **Read and validate.** Read `grants.jsonl` and validate its contents fully, including the
   1 MB cap (section 7.3). If it is invalid, refuse and point to `aiallow edit` (section 6.3).
4. **Confirm.** Show the dialog (section 6.4).
5. **Write.** Build the new contents: the old file plus one line the writer generates itself.
   - If the result would exceed 1 MB, stop and tell the user.
   - Write it to a temp file in the same folder, flush it to disk, and set its permissions
     explicitly, as for the grants file.
   - Swap it in with `File.Replace(temp, grants, null)`.
   - **If the swap reports an error**, don't assume the outcome. Re-read `grants.jsonl` and
     report what is actually there: unchanged, or containing the new line. Delete the temp
     file if it remains. Never retry automatically.
6. **Unlock.**

**Effect on the hook:** each hook run reads the file fresh. A revoke affects every hook run that
starts after the swap. An allow the hook has already returned can't be withdrawn.

### 6.2 Actions

| Action | Effect |
|---|---|
| `add` | Validates the clipboard request (section 7.1). Refuses if the user already has an active grant with that name. Shows the confirmation. Lets the user change the expiry. Writes the grant. |
| `revoke -Name <n>` | Lists **this user's** active grants with that name. `*` lists all of this user's active grants. Writes a revoke after confirmation. |
| `edit` | The repair path (section 6.3). |
| `validate-request -RequestFile <f>` | Validates a request and prints the description and the grant record it would produce. Read-only. |
| `validate-file -GrantsFile <f>` | Validates a whole grants file (section 7.3) and prints each line's result, plus the active grants per user. Read-only. |

**The two validate actions:** they never write, never take the mutex and never need
elevation. They use the same validation functions as `add`, `revoke` and `edit`. The shared
automated tests run through them. There is no auto-confirm switch.

### 6.3 Repair editing (`edit`)

`edit` is how a broken grants file is fixed, so it doesn't require the current contents to be
valid:

1. Take the mutex, then run the administrative integrity check on the files and folders. This
   is the filesystem check only; it doesn't validate the contents.
2. If the file is over 1 MB, stop. Point to `aiallow setup --reset`, which keeps the old folder
   as a backup.
3. Load `grants.jsonl` into the writer's own editor window (a Windows Forms text box). The
   contents may be invalid. Notepad isn't used: on Windows 11, `System32\notepad.exe` is a stub
   that starts the Store app and exits at once, so the writer couldn't wait for editing to
   finish.
4. Validate the **edited result** fully (section 7.3). If it is invalid, show the errors and
   offer to reopen or discard. Nothing invalid is ever saved.
5. Show a **line diff**: every removed line and every added line, in full. A changed command,
   user, expiry or revoke under the same grant ID appears as one removed line and one added
   line, so no change can hide.
6. On confirmation, swap it in exactly as in step 5 of section 6.1. Cancelling at any point
   leaves the original unchanged.

### 6.4 Confirmation dialog

The dialog is built only from the parsed fields:

> **Allow these exact commands** (through tool `Bash`):
> ```
> git push --force-with-lease origin feature/x
> ```
> **Starting in:** any folder of the git repo at `E:\Source\Mine\proj`
> **For user:** PC\aaron (S-1-5-21-…-1001) **On AI hosts:** all
> **Until:** 2026-11-19 18:32 local time (30 minutes)
> **Name:** push-feature-x
>
> ─── AI's stated reason (not checked) ───
> The rebase rewrote history, so a normal push is rejected.

- **Commands are shown exactly.** They are in a fixed-width box, never truncated, with the box
  scrolling if needed. Tabs, carriage returns and other control characters are shown as
  visible markers such as `⇥` or `␍`, and leading and trailing spaces are marked.
- `expires: never` shows **"Until revoked (no expiry)"** in bold, followed by "This is an
  indefinite permission."
- A `tool` of `shell` gets a note: "This host doesn't say which shell runs the command."

## 7. Formats and validation

### 7.1 Request block (written by the AI)

```json
{"v":1,"name":"push-feature-x",
 "commands":["git push --force-with-lease origin feature/x"],
 "tool":"Bash","where":"repo","cwd":"E:\\Source\\Mine\\proj",
 "hosts":null,"expires":"30m","why":"The rebase rewrote history, so a normal push is rejected."}
```

| Field | Required | Type and constraints |
|---|---|---|
| `v` | yes | integer `1` |
| `name` | yes | string matching `^[a-z0-9][a-z0-9-]{0,39}$` |
| `commands` | yes | array of 1–20 strings. Each is 1–8000 characters, contains no NUL, and is not whitespace-only. No duplicate entries. Compared **exactly**: no trimming, no whitespace changes, same line endings. |
| `tool` | yes | string of 0–40 characters: the tool name the hook sees (section 7.4). An empty string means the host sends no tool name. |
| `where` | yes | `"dir"`, `"repo"` or `"any"` |
| `cwd` | for `dir` and `repo` | absolute Windows path. Must be absent or null for `any`. |
| `hosts` | yes | null (all hosts), or a non-empty array without duplicates drawn from `claude`, `codex`, `cursor`, `windsurf`, `devin`, `antigravity` |
| `expires` | yes | `^[1-9][0-9]{0,3}[mhd]$` (e.g. `30m`, `2h`, `1d`), `"never"`, or an ISO-8601 timestamp **with** a timezone offset |
| `why` | yes | string of 0–1000 characters |

Strictness rules:

- **Unknown fields are rejected.**
- **Duplicate keys are rejected.** Python uses an `object_pairs_hook`. The writer pre-scans each
  JSON object's keys, since its parser keeps only the last duplicate. A shared fixture tests
  this.

### 7.2 Grants file (written only by the writer, or by `edit` after validation)

JSON Lines, one object per line, generated by the writer in a canonical form: fixed key
order, UTF-8, `\n` line endings, no blank lines.

```json
{"v":1,"type":"grant","id":"g-20261119T180211Z-3fa9c2d1","name":"push-feature-x","ts":"2026-11-19T18:02:11Z","user":"S-1-5-21-…-1001","user_display":"PC\\aaron","commands":["git push --force-with-lease origin feature/x"],"tool":"Bash","where":"repo","path":"E:\\Source\\Mine\\proj","hosts":null,"expires":"2026-11-19T18:32:11Z","why":"…"}
{"v":1,"type":"revoke","id":"r-20261119T181000Z-77b0e4aa","ts":"2026-11-19T18:10:00Z","user":"S-1-5-21-…-1001","name":"push-feature-x"}
```

**Stored `grant` line:** every field is required, and no others are allowed.

| Field | Type and constraints |
|---|---|
| `v` | integer `1`. A JSON `true` is rejected, not treated as 1. |
| `type` | `"grant"` |
| `id` | `^g-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`, unique among **all** lines |
| `name` | as in section 7.1 |
| `ts` | UTC timestamp `YYYY-MM-DDTHH:MM:SSZ` |
| `user` | a valid SID string, `^S-1-[0-9]+(-[0-9]+)+$` |
| `user_display` | string of 1–256 characters, for display only |
| `commands`, `tool`, `hosts`, `why` | as in section 7.1 |
| `where` | `"dir"`, `"repo"` or `"any"` |
| `path` | absolute Windows path for `dir` and `repo`; `null` for `any` |
| `expires` | UTC timestamp as for `ts`, or `null` (until revoked) |

**Stored `revoke` line:** every field is required, and no others are allowed.

| Field | Type and constraints |
|---|---|
| `v` | integer `1` |
| `type` | `"revoke"` |
| `id` | `^r-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`, unique among **all** lines |
| `ts` | UTC timestamp, as above |
| `user` | a valid SID string |
| `name` | a name as in section 7.1, or `"*"` for all of this user's earlier grants |

How a request is converted into a grant:

- `expires` becomes an absolute UTC time ending in `Z`, or **`null` for `never`**.
- `path` is `cwd` for `dir`, the discovered repo root for `repo`, and null for `any`.
- `id` is the type prefix (`g-` or `r-`), the UTC time and 8 random hex digits. IDs are unique
  within the file.
- `user` is the `-ForUser` SID. The writer checks that it is a valid SID string and shows it in
  the confirmation.

### 7.3 Reading and validating the file (hook, writer, `edit`)

The whole file is rejected, so **no grants apply**, if:

- the file is over 1 MB, or isn't valid UTF-8; or
- any line:
  - isn't valid JSON, or has a duplicate key (including keys that are only duplicates once
    escapes are decoded, e.g. a second `name` key with one letter written as a `\u` escape);
  - doesn't match the stored `grant` or `revoke` table in section 7.2;
  - has an `id` that appears more than once among grants and revokes together; or
  - is blank.

The rejection message gives the line number. A broken revoke can therefore never bring a grant
back. Hand edits go through `edit`, which applies these same rules before saving.

**A grant G is active** when **both** of these hold:

1. no revoke R appears *after* G in the file where R's `user` equals G's `user` and R's `name`
   is G's `name` or `*`; and
2. G's `expires` is null, or the current UTC time is before it.

### 7.4 Matching

The hook allows a command under a grant when the grant is active and **all** of these hold:

1. the grant's `user` equals the hook process's own user SID;
2. `hosts` is null or includes this adapter's host name;
3. `tool` equals the tool name the core receives (table below);
4. the payload command equals one of `commands` **exactly**;
5. the location matches, comparing paths after `os.path.normcase(os.path.abspath(...))`:
   - `dir`: the payload `cwd` is exactly `path`;
   - `repo`: the payload `cwd` is `path` or inside it, compared **folder by folder**, so
     `C:\repo` does not cover `C:\repo-other`;
   - `any`: always.

**How things are compared:**

- **Commands and tool names** are compared **ordinally and case-sensitively**, code unit by code
  unit (`==` in Python, `[string]::Equals(a, b, [StringComparison]::Ordinal)` in .NET). This
  never uses language- or culture-aware comparison.
- **Paths** are the only case-insensitive comparison.

**If several active grants match**, the first one in the file is reported and logged. Any of
them would allow the command, but the log should name the same one every time.

The path comparison is purely by name. Junctions and symlinks are **not** followed to their
targets, so a grant for one path doesn't cover another path that leads to the same folder.

`where` limits the **starting folder**, not which files the command touches. Exact text doesn't
lock down what the command *does*: a script it runs, or the program a name resolves to, can
still change. Both points are documented.

**Tool name seen by the core, by host** (the adapters are unchanged):

| Host | Tool name the core sees | Can it tell Bash from PowerShell? |
|---|---|---|
| Claude Code | `Bash` or `PowerShell` (the payload's `tool_name`) | Yes |
| Codex | the payload's `tool_name`, e.g. `shell` | No |
| Cursor | the payload's `tool_name` if present, otherwise empty | No |
| Windsurf / Cascade | `shell` (set by the adapter) | No |
| Devin | `shell` (set by the adapter) | No |
| Antigravity | `shell` (set by the adapter, not the native `run_command`) | No |

The deny message's pre-filled request always uses the tool name the core actually saw, so a
request copied from it matches on retry through the same host. The hook help block sets
`hosts` to the current host only. The AI or user can widen it.

## 8. Changes to the review flow (`review_core.review_payload`)

### 8.1 Flow

```
parse error / out-of-scope               → unchanged
if exceptions.enabled and command mentions the store (section 4.2):
    final = deny, flag exception-store-access → finalize and return (no external review)
local = local_review(...)                → unchanged
grant = None
if exceptions.enabled and running on Windows and local has no non-liftable flag:
    grant = exception_grants.find_grant(command, cwd, host, tool_name(payload))
            # any error → None, plus a note in the reason
if grant:
    final = Review(decision="allow", source="grant",
                   headline=f"Allowed by your exception grant '{grant.name}'.",
                   particulars=[scope summary, expiry or "until revoked"],
                   flags=["exception-grant", "exception-grant-id:" + grant.id])
else:
    external review + combine_reviews    → unchanged
final = finalize(final, ...)             → NEW shared step:
                                           refused-.env note, grant-help line, log_review
return ReviewResult(event_name, command, cwd, description, final)
```

- Grants are checked **whatever the local decision was**. Otherwise a command the local review
  allows but the external reviewer denies could never be unlocked.
- A matching grant **skips the external review**. The user has already decided, so there's no
  need to spend an API call.
- `find_grant` catches its own errors and returns no grant. This is a deliberately narrow
  broad-`except` that isolates the grant code; it can never produce an allow.
- Reading the grants file is bounded by the 1 MB cap. The hook never waits on a lock.
- Every grant allow is decision-logged with the grant's unique `id`, so reused names stay
  attributable.

### 8.2 Grant-help line on deny and ask (EG-011)

`Review` gains a field `extra_lines: List[str]`. `render_reason(review)` always adds those lines
**after** trimming particulars to ten, so they are never cut off. The adapters keep calling
`render_reason(review)` unchanged and get the extra lines automatically.

`finalize` sets `extra_lines` when **all** of these hold:

- exceptions are enabled and supported;
- the decision is `deny` or `ask`;
- the command is non-empty; and
- no flag that can't be lifted is present.

The line it adds looks like this:

```
If this command is needed, ask the user for an exception grant. Fill in name and why, then give the user this block:
{"v":1,"name":"","commands":["<exact command, JSON-escaped>"],"tool":"<tool name seen>","where":"dir","cwd":"<cwd>","hosts":["<this host>"],"expires":"30m","why":""}
```

How `cwd` is filled in:

- **A drive-letter Windows path:** it is cleaned up first (e.g. `C:/a/./b` becomes `C:\a\b`).
- **Missing, or not a Windows path** (some hosts send `/e/Source`): `cwd` is left as `""`, and
  one more line says: "This host reported the folder as '\<value\>', which is not a Windows
  path. Fill in the Windows folder in cwd." An empty `cwd` fails validation, so the request
  can't be approved until it's filled. The scope is never silently widened to `any`.

## 9. The `aiallow` CLI

It lives at `.claude/hooks/aiallow.py`, with `setup-grants.ps1` next to it, and is copied by the
installers. An `aiallow.cmd` wrapper calls the configured interpreter. It runs unelevated and
holds no authority.

| Command | What it does |
|---|---|
| `aiallow add` | Launches the writer's `add` action (UAC prompt), waits for it, then re-reads the grants file and prints the result. |
| `aiallow list` | This user's active grants: name, commands, scope, and time left or "until revoked". |
| `aiallow history [--since 7d]` | Grants and revokes from the grants file, plus grant allows from the decision log if `policy.log_path` is on, matched by grant `id`. |
| `aiallow revoke <name>` / `aiallow revoke --all` | Launches the writer's revoke action. |
| `aiallow edit` | Launches the writer's `edit` repair action (section 6.3). |
| `aiallow setup [--reset]` | Section 5, then an unelevated `check`. |
| `aiallow check` | Runs the unelevated integrity check and reports what passed or failed. |

Whether Claude Code's `! aiallow …` works from inside a session will be tested after
implementation and documented then. Until then, the documented way is a separate terminal.

## 10. Implementation phases

| Phase | Files | Content |
|---|---|---|
| 1. Config | `.claude/hooks/config.py`, `config.example.yaml`, `tests/test_config.py` | `exceptions` defaults, an `ExceptionSettings` dataclass, type rules. |
| 2. Grants core | new `.claude/hooks/exception_grants.py`, new `tests/test_exception_grants.py`, new `tests/fixtures/grants/` | Integrity rule (Windows, `ctypes`), strict reader, active-grant logic, matching. Pure logic separated from OS calls. |
| 3. Hook integration | `.claude/hooks/review_core.py`, `tests/test_review_core.py`, adapter tests | `exception-store-access` rule, `Review.extra_lines`, `render_reason`, `finalize`, grant lookup. |
| 4. Writer and setup | new `grant-writer/grant-writer.ps1`, new `.claude/hooks/setup-grants.ps1`, new `tests/test_grant_writer.py` | Section 5 and section 6, using .NET calls only. |
| 5. CLI | new `.claude/hooks/aiallow.py`, `aiallow.cmd`, new `tests/test_aiallow.py` | Section 9. Launching processes goes through one function the tests can swap out. |
| 6. Install and docs | `install.ps1`, `install.sh` (prints "grants not supported on this platform"), `README.md`, `SECURITY.md` | Copy the files. Print `aiallow setup` as an optional step; the installer itself never elevates. Document the request format, the threat model, what is and isn't limited, and the dependence on UAC being on. |

**Not in scope:**

- prefix and pattern grants,
- citation,
- use limits,
- Linux, macOS and WSL support,
- adapter code changes,
- existing heuristics, other than the one new rule,
- reviewing non-shell tools,
- protection against a hostile AI,
- new Python dependencies.

## 11. Verification

**Automated (pytest with the mypython312 interpreter, plus `ruff check .` and CI):**

- **Shared fixtures** (`tests/fixtures/grants/`): request and grant-file cases, each marked
  valid or invalid. Request cases go through Python and the writer's `validate-request`. Whole
  files go through Python and `validate-file`. **Both sides must agree on every case**:
  - `v` given as `true` instead of `1`, escaped duplicate keys, emoji and other characters
    outside the Basic Multilingual Plane in commands, and invalid UTF-8;
  - a repeated revoke ID, and a grant and a revoke sharing an ID;
  - an invalid SID, and a grant missing `user_display`;
  - empty or whitespace-only commands, duplicate commands, wrong types, duplicate keys,
    unknown fields;
  - bad `hosts` or `where` values, `cwd` given with `any`;
  - timestamps without a timezone, and `never` / `null` expiry;
  - an over-length name;
  - a valid grant followed by a malformed revoke;
  - a truncated last line, blank lines, duplicate IDs;
  - a revoke of `*` followed by a new grant, and a revoke by another user (which has no effect).
- **Matching:**
  - exact matching is whitespace-sensitive: quoted double spaces, tabs, CRLF vs LF, trailing
    space;
  - each command in a multi-command grant;
  - tool mismatch, e.g. `Bash` vs `PowerShell` and `shell` vs `run_command`;
  - host and user mismatches;
  - expiry at the boundary, and `null` expiry;
  - `dir`/`repo`/`any` with case and separator variants;
  - `C:\repo` vs `C:\repo-other`;
  - with several grants matching, the first in the file is the one reported.
- **Integrity rule on a real filesystem, no admin needed.** These are rejected:
  - a temp folder and file the user owns;
  - a junction or symlink on the path.

  (Files over 1 MB are a content check, covered by the shared fixtures.)

  `C:\Windows\System32` (TrustedInstaller-owned, user can't write) passes the owner and
  write-rights checks for a read-only file in it. Pure-logic tests feed synthetic ACE lists
  for: an unexpected write entry, permission-changing rights without append rights, an
  inherit-only entry (ignored), a deny entry (ignored), a NULL DACL, a non-standard entry type,
  and an untrusted owner.
- **Writes that must fail do fail**, unelevated:
  - the writer refuses a destination that fails the integrity rule;
  - an ordinary append to the real protected grants file is denied by the OS;
  - the writer exits without writing when another process holds the mutex;
  - `aiallow` refuses to launch a writer script the user owns, before any UAC request.

  The successful admin write isn't tested automatically, and the writer has no test-only
  switch.
- **Review flow:**
  - a grant gives a `ReviewResult` with `source="grant"` and the grant ID in its flags, and is
    decision-logged;
  - the refused-`.env` note is kept;
  - the external reviewer is not called;
  - `exception-store-access` can't be lifted;
  - the help line appears with more than ten particulars and is left out where section 8.2
    says so;
  - for every adapter, the help line's request, once granted, matches a retry of the same
    payload through that adapter and produces that adapter's own allow output.
- **Writer `validate-request` action** (unelevated): the description text for each field
  combination, including the control-character markers, the indefinite-expiry wording and the
  `shell` note.

**Manual, once before release (Windows).** These are **release requirements**. The validation-only
tests above don't prove the successful write path or the permission handling.

1. Fresh `aiallow setup`, then `aiallow check` reports "protected". An unelevated append fails.
2. Run setup again: it updates, and `grants.jsonl` is unchanged.
3. Setup against a pre-existing folder with an extra permission entry stops without changing
   anything.
4. Run a blocked command, get a request from the AI, run `aiallow add`, then retry: the
   command is allowed. A different command is not.
5. Two `aiallow add` windows: the second reports "Another grant window is open". An add followed
   by a revoke keeps both lines. `setup --reset` while an add window is open is refused.
6. **Repair:** `edit` saving an edited result with a syntax error is refused, and the file is
   unchanged. Starting from an already-broken file (malformed JSON; an invalid revoke), `edit`
   opens it, and saving a fixed version succeeds. A changed command or expiry under the same
   ID shows as a removed and an added line. Cancelling leaves the file unchanged. An oversized
   file is sent to `--reset`, and the backup folder keeps the history.
7. `aiallow revoke --all` makes the command blocked again.
8. **Normal update:** on a valid installation, `aiallow setup` updates the writer, its
   permissions verify, and `grants.jsonl` is unchanged.
   **Broken writer:** give `grant-writer.ps1` an extra write permission for Users, or make the
   user its owner. Then:
   - `aiallow add` refuses before any UAC prompt;
   - plain `aiallow setup` refuses without changing anything;
   - `aiallow setup --reset` recovers, and the backup folder keeps the old history.
9. A tampered `aiallow.py`, and a module placed in `Documents\WindowsPowerShell\Modules`, have
   no effect on what the writer shows or writes.
10. With the AI tool running elevated, grants are ignored.

## 12. Open questions

None. The `!` shortcut is deferred to testing after implementation (section 9).

## 13. Disposition of review findings

| Finding | Status | Handling |
|---|---|---|
| EG-001 Elevated code the agent can edit; setup and update trust | Addressed | Day-to-day operations run only the protected writer: `System32` PowerShell, `-NoProfile`, .NET calls only, no Git. Setup and update are a declared installer exception (section 1.2). Update keeps grants; reset renames the folder aside. The repo root is found by checking for `.git` only. (Sections 1.2, 5, 6) |
| EG-002 What "protected" means | Addressed | One integrity rule (section 4): owner, reparse points, DACL write-type rights for file and folder, rename/replace rights on every parent, inheritance protection, size, elevated reader. Setup inspects before changing anything, and creates the folder with its full permissions in one call. The writer applies the full rule. The check-then-read gap is accepted (section 4.3). |
| EG-003 POSIX confirmation and sudo | Removed from scope | Windows only in v1. |
| EG-004 Use limits rest on mutable state | Resolved | Use limits and the activity log removed. |
| EG-005 Skipped lines can undo revocation | Resolved | Any invalid line rejects the whole file. Version and revoke semantics defined, now per user. (Section 7.3) |
| EG-006 Normalization merges distinct commands | Resolved | Exact raw-string comparison. (Sections 7.1, 7.4) |
| EG-007 Prefix matching | Removed from scope | Prefix grants cut. A grant can list up to 20 exact commands instead. |
| EG-008 Approval-by-ID trust gaps | Resolved | Full requests, writer-generated description, mandatory confirmation. |
| EG-009 No user binding | Resolved | SID binding. Revokes and `list` are limited to the user. (Sections 6.2, 7.3, 7.4) |
| EG-010 Concurrent writers can lose updates | Addressed | A named mutex (revision 4; previously `writer.lock`) is held from read through confirm to replace. Size checked before writing. Setup creates the file. Replace failures are re-read and reported. `edit` uses the same lock. Revoke timing defined. (Section 6.1) |
| EG-011 Finalization and rendering | Addressed | `Review.extra_lines`, which `render_reason` always includes after trimming. Shared `finalize`. (Section 8) |
| EG-012 Config and setup edge cases | Addressed | Type rules. Separate administrative and unelevated validation modes. Setup creates the first file. Wrapper and interpreter specified. (Sections 3, 4.1, 5, 9) |
| EG-013 Adapter tool identity | Addressed | `tool` means the name the core sees. Table per host. The help block uses the seen name and the current host. The `shell` limitation is shown to the user. Citation removed. (Sections 6.4, 7.4, 8.2) |
| EG-014 Semantic validation contract | Addressed | A full field table with types, bounds and enums. Unknown fields and duplicate keys rejected. Timestamp rules. `never` stored as `null`, and covered by the active-grant rule. Canonical writer output. Shared fixtures for both implementations. (Sections 7, 11) |
| Rev 3: EG-001/002 Writer file integrity | Addressed | The integrity rule covers `grant-writer.ps1` by its own permissions. Setup and update set and verify those permissions. `aiallow` checks the writer before UAC. `writer.lock` replaced by a named mutex, so it has no file integrity to check. (Sections 4, 4.1, 5, 6, 6.1) |
| Rev 3: EG-015 Repair editing | Addressed | Filesystem protection is separate from content validity. `edit` accepts invalid current contents, and only a valid edited result is saved. A line diff makes every change visible. An oversized file goes to `--reset` with a backup kept. (Sections 4, 6.3, 7.3) |
| Rev 3: EG-010 Reset coordination | Addressed | A named mutex is shared by every writer, setup, update and reset, and doesn't depend on the folder. Reset never trusts files in the old folder. Backup name collisions and partial-install failures are defined. (Sections 5, 6.1) |
| Rev 3: EG-014 Stored-file validation entry point | Addressed | `validate-request` and `validate-file` are read-only modes backed by the production validation code. Full stored `grant` and `revoke` field tables. (Sections 6.2, 7.2, 7.3, 11) |
| Rev 3: implementation notes | Addressed | Folder-by-folder repo containment. Junctions not followed (documented). JSON fixtures for `v` type, escaped duplicate keys and non-BMP text. Swap failures re-read and reported, never assumed. First matching grant logged. Successful-write and permission checks are release requirements. (Sections 6.1, 7.3, 7.4, 11) |
| Rev 4: EG-016 Mutex permissions and failures | Addressed | The doc no longer says the mutex has no permissions; it has no *filesystem* dependency. Access-denied and wrong-object-type errors stop the operation and are reported separately from contention. No fallback. `try`/`finally` release, only if acquired. (Section 6.1) |
| Rev 4: EG-012 Pre-UAC check vs setup/reset; update test | Addressed | The pre-UAC writer check applies to `add`, `revoke` and `edit` only. Setup and reset are exempt, and nothing switches to them automatically. Manual test 8 now separates a normal update from broken-writer recovery. (Sections 4.1, 11) |
| Plan review amendments | Adopted | Parent folders also fail on a NULL DACL or unusual entry types. Both sides evaluate raw binary descriptors. A custom `grants_path` is set up by hand, and setup refuses it. A non-Windows `cwd` gives an empty `cwd` plus a fill-in note, never a silent `any`. (Sections 3, 4, 8.2) |
| Rev 4: editorial notes | Addressed | Escaped-duplicate example fixed. The size check moved into the content tests. POSIX lock aside removed. Ordinal comparison for commands and tool names. Case-insensitive comparison for paths only. (Sections 6.1, 7.3, 7.4, 11) |
| Smaller points | Addressed | Revokes limited to the user. Grant `id` in flags and the decision log. Exact command display with control-character markers. AI reason visually separated. `never` described as indefinite. |
