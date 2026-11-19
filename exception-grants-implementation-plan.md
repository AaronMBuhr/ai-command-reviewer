# Exception Grants: Implementation Plan (revision 3)

Revision 2 answered the first plan review (PLAN-001 to PLAN-009 and its clarifications).
Revision 3 answers the second (PLAN-010 to PLAN-013) and adds the review's implementation
checkpoints as section 14. Section 13 maps each finding to its fix.

Audience: a developer new to this codebase and to Windows security APIs.
Source of truth for *what* to build: `exception-grants-design.md` (revision 4, approved with
notes). This plan says *how*, and records every decision so you never have to guess. **If
this plan and the design disagree, stop and ask. Don't pick one yourself.**

---

## 0. Before you start

### 0.1 Ground rules

- **Python must stay 3.9-compatible.** CI runs 3.9, 3.11 and 3.13 on Ubuntu and Windows.
  - Use `typing` forms: `Optional[str]`, `List[str]`, `Dict[str, Any]`. This is the project's
    lint convention (see `pyproject.toml`).
  - Don't use `match` statements or `X | Y` type unions at runtime; both need 3.10.
- **No new Python dependencies.** Use the standard library only. `ctypes` is fine.
- **PowerShell scripts that run elevated must use .NET calls only**, no cmdlets. See section 6.1
  for the exact rules.
- **Run locally before every push:**
  ```powershell
  & 'C:\Users\aaron\anaconda3\envs\mypython312\python.exe' -m pytest
  & 'C:\Users\aaron\anaconda3\envs\mypython312\python.exe' -m ruff check .
  ```
  There is no `python` on PATH on the main dev machine; use that interpreter path.
- **Keep `exceptions.enabled: false` in your own config while developing.** When it is on, the
  hook denies any shell command that mentions `aiallow`, `grant-writer`, `setup-grants` or the
  grants folder, and that includes your own work on these files.
- One phase per pull request. Each phase lists a "done when" checklist. Don't start the next
  phase until the current one's checklist passes.
- **Every merged phase must leave the product installable and working with exceptions
  disabled.** If a phase adds a module that a hook imports, that same phase adds it to both
  installers. A test enforces this (section 6.5).
- Tests must never depend on the current directory: `tests/conftest.py` changes it for every
  test. Anchor paths with `REPO = Path(__file__).resolve().parent.parent`.

### 0.2a Accepted design amendments

These came from planning and the plan review, and are already reflected in
`exception-grants-design.md`:

1. The store-access deny check runs in `review_payload`, only while exceptions are enabled on
   Windows (A12).
2. `edit` uses the writer's built-in editor window, not Notepad (A14).
3. Paths are drive-letter absolute only, so no UNC paths (D3).
4. A `cwd` that isn't a Windows path gives `"cwd":""` plus a fill-in note, never `any` (D4).
5. Parent folders also fail on a NULL DACL or unusual entry types. Both sides evaluate raw
   binary security descriptors (I5, I9).
6. A custom `grants_path` is set up by hand, and `aiallow setup` refuses it (A16).

### 0.2 Glossary

| Term | Meaning here |
|---|---|
| **UAC** | The Windows "Do you want to allow this app to make changes?" prompt. Clicking Yes runs a program with admin rights. |
| **Elevated** | Running with admin rights after a UAC Yes. |
| **SID** | A Windows security identifier, e.g. `S-1-5-32-544` (Administrators). Every user and group has one. |
| **DACL** | A file or folder's permission list. |
| **ACE** | One entry in a DACL: allow or deny, which SID, and which rights (a bitmask). |
| **Inherit-only ACE** | An ACE that applies only to things created *inside* a folder, not to the folder itself. Flag `0x08`. |
| **Protected DACL** | A DACL that doesn't inherit entries from its parent folder. |
| **SDDL** | Windows' text notation for security settings, e.g. `O:BAD:PAI(A;OICI;FA;;;BA)`. |
| **Reparse point** | A symlink or junction. File attribute `0x400`. |
| **Named mutex** | A lock object kept by Windows and found by name. Only one process can hold it at a time. |
| **Grant** | One line in `grants.jsonl` allowing exact commands for one user, until it expires or is revoked. |
| **Request block** | The JSON the AI produces, which the user copies to the clipboard. |

### 0.3 Reading order

The sections below are grouped by **module**, not by phase. Build in the phase order given in
section 12: config (section 5), then pure logic (section 3), then Windows integrity
(section 4), and so on.

### 0.4 Files you will create or change

| File | New or changed | Phase |
|---|---|---|
| `.claude/hooks/config.py` | changed | 1 |
| `config.example.yaml` | changed | 1 |
| `.claude/hooks/exception_grants.py` | **new** | 2, 3 |
| `.claude/hooks/review_core.py` | changed | 4 |
| `grant-writer/grant-writer.ps1` | **new** | 5 |
| `.claude/hooks/setup-grants.ps1` | **new** | 6 |
| `.claude/hooks/aiallow.py` | **new** | 7 |
| `install.ps1`, `install.sh`, `README.md`, `SECURITY.md` | changed | 8 |
| `tests/test_config.py` | changed | 1 |
| `tests/test_exception_grants.py` | **new** | 2, 3 |
| `tests/test_grant_integrity.py` | **new** | 3 |
| `tests/test_review_core.py`, `tests/test_adapters.py` | changed | 4 |
| `tests/test_grant_writer.py` | **new** | 5, 6 |
| `tests/test_aiallow.py` | **new** | 7 |
| `tests/fixtures/grants/` | **new** | 2 |
| `tests/fixtures/acl/` (cases plus `make_fixtures.py`) | **new** | 3 |
| `tests/test_installers.py` | **new** | 4 |
| `install.ps1`, `install.sh` (add `exception_grants.py` only) | changed | 4 |

Adapter files (`*-hook.py`) are **not** changed.

---

## 1. Decision record

Every decision below is final for v1. Each has a short reason. The design section is given
where one applies.

### 1.1 Architecture

| # | Decision | Why |
|---|---|---|
| A1 | Threat model: a guardrail against a well-meaning but mistaken AI, not a hostile one. | An AI determined to get around the hook can already edit the hook itself. (Design 1.1) |
| A2 | Windows only in v1. On other platforms, grants are off and a note is shown. | The user runs Windows. The POSIX writer, sudo and confirmation rules were the source of several review findings. |
| A3 | Grants live in `C:\ProgramData\cc-ai-review\grants.jsonl`, writable by admins only. The path is configurable. | The AI runs as the user, so anything the user can write unelevated, the AI can write too. |
| A4 | Only `grant-writer.ps1`, running elevated, writes grants. `aiallow` never passes request contents; the writer reads the clipboard itself. | A tampered or buggy unelevated CLI can't change what gets approved. |
| A5 | The writer runs under `System32` `powershell.exe` 5.1 with `-NoProfile`, using .NET calls only. | Nothing from user-writable folders (profiles, modules) runs elevated. |
| A6 | Setup and update are the one declared exception: a user-run installer, elevated. | First install has to get the writer from somewhere. (Design 1.2, 5) |
| A7 | All writers, setup, update and reset share one named mutex, `Global\cc-ai-review-grants`. | It survives the folder being renamed by reset, and it has no file to protect. |
| A8 | No activity log, no use counts. History comes from the grants file plus the existing decision log. | The user asked for no worthless complexity. Use counts would need a file the AI can write. |
| A9 | The hook reads the grants file without taking a lock. | The writer swaps the file in one atomic step (`File.Replace`), so readers never see half a file. |
| A10 | Grants are checked in `review_payload` before the external review. A match skips the external review. | The user already decided. This saves an API call. |
| A11 | No adapter code changes. The help line reaches the user through `Review.extra_lines`, which `render_reason` always prints. | Six adapters; zero churn. |
| A12 | The store-access deny check lives in `review_payload` and runs only when exceptions are enabled on Windows. | `local_review` doesn't receive the grants path. Running the check while disabled would block work on this repo. |
| A13 | An invalid exceptions config raises `ConfigError`, like any other config error. | Matches the existing project rule: a config the user wrote that can't be honored fails closed. |
| A14 | `aiallow edit` uses a **built-in editor window** in the writer (a Windows Forms text box), not Notepad. | On Windows 11, `System32\notepad.exe` is a stub that starts the Store app and exits at once, so "wait for Notepad to close" doesn't work. The built-in window also avoids an elevated file-open dialog. |
| A15 | `aiallow` finds `powershell.exe` with `GetSystemDirectoryW`, not the `%SystemRoot%` environment variable. | Environment variables are user-controlled. The API isn't. |
| A16 | `aiallow setup` provisions only the default store. A custom `grants_path` is set up by hand: setup refuses it with an explanation, and `check` reports its state. | Provisioning arbitrary admin locations adds risk and code for an advanced case. |
| A17 | A phase that makes a hook import a new module also adds that module to `install.ps1` and `install.sh`. | Each merged phase must install and run (PLAN-001). |
| A18 | Elevated PowerShell scripts call no cmdlets at all, `Set-StrictMode` included. An AST test enforces it: every command invocation must name a function the script defines. | Cmdlets can come from user-writable module folders. A parser-based check can't be fooled by comments or strings (PLAN-009). |
| A19 | Tests never run setup or the writer's write actions against the real `ProgramData` store. Real install, failure and permission checks happen only in the disposable-VM release checks. | The test suite must not change the machine (PLAN-004). |

### 1.2 Data and validation

| # | Decision | Why |
|---|---|---|
| D1 | Commands are matched by exact, ordinal, case-sensitive string equality. No trimming or normalization. | Normalization merged distinct commands (review EG-006). |
| D2 | Tool names are matched exactly, using the name the core sees (`tool_name(payload)`). | Adapters rename some tools to `shell`. Whatever the core sees is the only consistent identity. |
| D3 | Paths are compared case-insensitively, component by component, after `ntpath.normpath`. Only drive-letter absolute paths are allowed (`C:\...`), not UNC or `\\?\` paths. | Windows paths are case-insensitive. Folder-by-folder comparison stops `C:\repo` matching `C:\repo-other`. UNC is out of scope for v1. |
| D4 | If the payload `cwd` isn't a drive-absolute path, `dir` and `repo` grants never match. The help block keeps `"where":"dir"` with `"cwd":""`, and adds a note asking for the Windows folder. A valid `cwd` is cleaned with `ntpath.normpath` before it goes into the help block. | Some hosts send POSIX-style paths such as `/e/Source`. Guessing a translation could match the wrong folder, and silently widening to `any` changes the scope (PLAN-007). |
| D5 | The file must be at most 1 MB, UTF-8 without a BOM, `\n` line endings only, every line ending in `\n`, with no blank lines. An empty file is valid. | Strict and simple. A truncated last line fails. The writer always writes this form. |
| D6 | Any invalid line rejects the **whole file**, so no grants apply. | A broken revoke must never bring a grant back. |
| D7 | Unknown fields, duplicate keys (compared after escapes are decoded), `NaN`/`Infinity`, lone surrogates, and `v` values that aren't the integer 1 are all invalid. | Python's `json` and .NET's reader must reach the same verdict. |
| D8 | Durations are `^[1-9][0-9]{0,3}[mhd]$`. ISO timestamps in requests are `YYYY-MM-DDTHH:MM:SS` followed by `Z` or `±HH:MM`, with no fractional seconds. Stored timestamps are `YYYY-MM-DDTHH:MM:SSZ` only. | Python 3.9's `fromisoformat` doesn't accept `Z`. A narrow format is easy to parse identically in both languages. |
| D9 | `expires: "never"` is stored as `null`. A request whose absolute expiry is already in the past is rejected. | Design 7.2. |
| D10 | IDs are `g-` or `r-`, then `yyyyMMddTHHmmssZ`, then `-`, then 8 lowercase hex digits from a cryptographic random source. IDs are unique across all lines. On a collision, generate again. | Readable, sortable and unique. |
| D11 | Each validation error has a stable **code** (section 2.3). Python and the writer must report the same first error code for every shared fixture. | Stronger than agreeing on valid/invalid alone, and it makes disagreements easy to debug. |
| D12 | When several grants match, the first one in file order is reported. | Reproducible attribution. |
| D13 | Canonical stored form: keys in table order, no spaces, `"` `\` and U+0000–U+001F escaped (`\n` `\r` `\t` `\b` `\f` short forms, otherwise `\u00XX`), plus U+2028 and U+2029 as `\u2028` and `\u2029`. Every other character is written as raw UTF-8. | One deterministic output from the writer. |
| D14 | The help block is built with `json.dumps(..., ensure_ascii=True, separators=(",", ":"))`. | It shows safely in any terminal, hides no invisible characters, and decodes back to the exact command. |
| D15 | During `edit`, the editor's text has `\r\n` turned into `\n` and gets a final `\n` before validation. | Windows text boxes use CRLF. A raw CR is never part of a command, because commands store CR as the escape `\r`. |
| D16 | **Revised after R3 was confirmed (user-approved).** The writer parses JSON with a small hand-written recursive-descent parser (a PowerShell class) that follows the grammar Python's `json` module accepts: whitespace is space, tab, LF and CR; raw control characters in strings are errors; escapes are the RFC 8259 set with exactly four hex digits for `\u`, and a high-plus-low surrogate escape pair becomes one character; numbers follow `-?(0\|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?`; `NaN`/`Infinity` are errors; nothing may follow the top-level value. Duplicate keys are reported when their object closes, which is exactly when Python's `object_pairs_hook` runs, so an earlier syntax error wins in both. | `JsonReaderWriterFactory` accepts `NaN`, trailing commas, empty input and two top-level values, and loses trailing commas from its output entirely (R3). |
| D17 | Parsed JSON objects in PowerShell are stored in `System.Collections.Specialized.OrderedDictionary` built with `[StringComparer]::Ordinal`. Keys are always read with `$d['key']` and `$d.Contains('key')`, never `$d.key`. Never use `@{}` or `[ordered]@{}`. | PowerShell hashtables ignore key case, so `name` and `Name` would merge into one key while Python keeps both (PLAN-002). |
| D18 | Length limits count **Unicode code points**. In Python that is `len(s)`. In .NET, count characters and treat a surrogate pair as one. | Python and .NET string lengths differ for emoji and other non-BMP characters. |
| D19 | SID rule, shared by both sides: `^S-1-(0\|[1-9][0-9]{0,14})(-(0\|[1-9][0-9]{0,9})){1,15}$`. The authority must be below 2^48, and each sub-authority at most 4294967295. No .NET constructor decides validity. | A regex alone allows numbers too large to be real, and the constructor's rules are undocumented (review clarification). |
| D20 | The repair diff uses the longest-common-subsequence table only when old lines × new lines ≤ 1,000,000. Above that, every old line is shown as removed and every new line as added. Compute the product as `[long]` before choosing, so it can't overflow. | The 1 MB cap bounds bytes, not the size of the comparison table (PLAN-003, PLAN-010). |
| D21 | *(Found during implementation.)* JSON nested deeper than 64 levels is `json-syntax`, checked by a bracket scan outside strings before parsing. | Python's own limit depends on the interpreter's recursion limit, and a PowerShell recursive walker could overflow its stack. A fixed limit is the same on both sides. |
| D22 | *(Found during implementation.)* An integer literal longer than 100 characters is treated as an out-of-range integer (so `v` gives `bad-value`). | Python 3.11+ refuses to convert very long digit strings and 3.9 doesn't, so the verdict would otherwise depend on the interpreter. |
| D23 | *(Found during implementation.)* Every regex is anchored with `\A` … `\Z` (Python) or `\A` … `\z` (.NET), and uses `[0-9]`, never `\d`. "Whitespace-only" means every character is in a fixed set: Python's `str.isspace()` set, spelled out in both implementations. | `$` also matches before a trailing newline in both languages, so `"push\n"` would pass a `^…$` name check. `\d` matches non-ASCII digits. .NET's `Char.IsWhiteSpace` differs from Python's `isspace` (U+001C–U+001F). |
| D24 | *(Found during implementation.)* **Every** string field rejects lone surrogates with `bad-value`: `commands`, `tool`, `why`, `user_display`, `cwd` and `path`. (`name`, `id`, `ts`, `user`, `where`, `hosts` and `expires` can't hold one, because their regexes or value lists allow only ASCII.) | Section 3.2 named only `commands`. One rule for all fields is simpler to mirror, and a lone surrogate can't be written as valid UTF-8 anyway. |

### 1.3 Integrity rule (algorithm)

| # | Decision |
|---|---|
| I1 | **Trusted SIDs:** `S-1-5-32-544` (Administrators), `S-1-5-18` (SYSTEM), and `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464` (TrustedInstaller). |
| I2 | **`WRITE_MASK`** = `0x2 \| 0x4 \| 0x10 \| 0x40 \| 0x100 \| 0x10000 \| 0x40000 \| 0x80000 \| 0x10000000 \| 0x40000000`. |
| I3 | **`ANCESTOR_MASK`** = `DELETE 0x10000 \| FILE_DELETE_CHILD 0x40 \| WRITE_DAC 0x40000 \| WRITE_OWNER 0x80000 \| GENERIC_ALL 0x10000000`. |
| I4 | **Protected object** (the grants folder, the grants file, the writer script): the owner is trusted; it is not a reparse point; it has a DACL (not NULL); its ACE types are only `0` (allow) or `1` (deny); and no allow ACE that isn't inherit-only gives an untrusted SID any `WRITE_MASK` bit. The folder must also have a protected DACL. |
| I5 | **Ancestor** (every parent folder up to the drive root): the owner is trusted; it is not a reparse point; it has a DACL (not NULL); its ACE types are only `0` or `1`; and no allow ACE that isn't inherit-only gives an untrusted SID any `ANCESTOR_MASK` bit. Deny ACEs are always ignored, because they only take rights away. Unusual ACE types fail rather than being ignored (PLAN-005). |
| I4a | **Problem order** (both sides, both roles): `malformed` (and stop), `owner`, `reparse`, `null-dacl` (and stop checking entries), `ace-type` (first unusual entry only), `write-right` (first offending allow entry only), then `not-protected` (folder role only). The first problem is the one fixtures compare, so the order is part of the contract. |
| I6 | **Elevated reader:** the hook and `aiallow check` treat their own elevated token as "not protected". The writer and setup skip this check, since they're meant to be elevated. |
| I7 | Integrity checks the filesystem only. Size and content are validated separately (`validate_file_bytes`). |
| I9 | Both sides evaluate the **raw self-relative binary security descriptor**. Python parses the bytes itself with `struct` (section 4.1). The writer uses `RawSecurityDescriptor`. Shared hex fixtures in `tests/fixtures/acl/` must get the same verdict from both. |
| I8 | Every file the writer or setup creates gets its owner set **explicitly** to Administrators and its DACL set explicitly. Don't trust defaults: an elevated admin's new files are often owned by the user's own account, which would fail I4. |

---

## 2. Shared fixtures and error codes (do this first, inside Phase 2)

### 2.1 Layout

```
tests/fixtures/grants/
  cases.json                 # the manifest
  requests/<name>.json       # request blocks (raw bytes, may be invalid)
  files/<name>.jsonl         # whole grants files (raw bytes, may be invalid)
  descriptions/<name>.txt    # expected writer description text (Phase 5)
```

**`cases.json`** is a list of entries like this:

```json
{"id":"req-empty-command","kind":"request","path":"requests/empty-command.json",
 "valid":false,"code":"bad-value","field":"commands","now":"2026-11-19T18:00:00Z",
 "for_user":"S-1-5-21-1-2-3-1001"}
```

- `kind` is `request`, `file` or `conversion`.
- `code`, `field` and `line` describe the **first** error. `line` applies to files only.
- `now` and `for_user` let tests control time and identity.
- Valid file cases may add `"active":{"<sid>":[…grant ids…]}`.
- `conversion` cases add `"record":{…}` (the expected converted grant) or a conversion error
  `code`/`field`, and optionally `"description":"<name>.txt"`.

**Two layers, two kinds of case (PLAN-011).** Request validation has two layers:

1. **Text validation** (Python section 3.2, writer `Test-Request`): checks the JSON and every
   field by its text alone. It never touches the filesystem. `request` cases test only this.
   Their paths are fixed, lexical Windows paths such as `C:\cc-fixture\work`, with **no
   placeholders**. They run on Ubuntu and Windows, and Python and the writer must agree on
   every one.
2. **Conversion** (writer only, `ConvertTo-Grant`): checks that the `cwd` folder exists, finds
   the repo root, and builds the stored record. `conversion` cases test only this. They are
   **Windows only** and use the placeholders below.

Never relax the Windows-path rule on Ubuntu to make a fixture pass.

**Store the fixture files as raw bytes.** Use `.gitattributes` with `tests/fixtures/grants/** -text`
so Git never changes their line endings.

**Placeholders (conversion cases only).** Conversion checks that `cwd` folders exist and finds
repo roots, so `cwd` values in `conversion` fixtures may use these placeholders:

- `{TMP}`: an empty temp folder;
- `{TMP_REPO}`: a temp folder containing a `.git` folder;
- `{TMP_REPO}\sub`: a subfolder of that repo.

The test creates real Windows temp folders and substitutes their paths into the request (and
into the expected `record`'s `path`) before running the writer. Substitute with proper JSON
escaping (backslashes doubled).

**Comparing converted records.** For valid conversion cases, `"record"` lists the expected grant
**without** `id`, `ts` and `user_display`. The test compares every other field exactly. It
checks `id` against `GRANT_ID_RE`, checks that `ts` equals the fixture's `now`, and checks that
`user_display` is a non-empty string. The writer has no option for predictable IDs.

**ACL fixtures** (`tests/fixtures/acl/cases.json`): each entry has these fields:

- `hex`: a self-relative security descriptor, hex-encoded;
- `role`: `folder`, `file` or `ancestor`;
- `ok`: true or false;
- `problem`: a stable code: `owner`, `reparse`, `null-dacl`, `ace-type`, `write-right`,
  `not-protected` or `malformed`.

Generate the hex once on Windows with a helper script, `tests/fixtures/acl/make_fixtures.py`,
using `ConvertStringSecurityDescriptorToSecurityDescriptorW` on a list of SDDL strings. Commit
both the script and the output. Include:

- the setup SDDL (OK for each role);
- a Users write entry; Users with `WRITE_DAC` only; Users with `FILE_APPEND_DATA` only;
- an inherit-only write entry (OK); a deny entry (OK);
- a NULL DACL; a callback ACE (`XA`); an object ACE (`OA`);
- an untrusted owner;
- an unprotected folder DACL;
- `C:\ProgramData`'s real SDDL as an ancestor (OK); an ancestor with Users `DELETE`;
- a truncated descriptor (`malformed`);
- **nested sizes** (`malformed`), made by editing the generated bytes: an ACE whose SID runs
  past its `AceSize`; ACEs that run past the ACL's `AclSize`; an `AclSize` past the end of the
  buffer; a SID `SubAuthorityCount` of 0 and of 16.

### 2.2 Minimum fixture list

**Requests:**
- valid minimal; valid with all fields;
- `"expires":"never"`; ISO expiry with `+02:00`; ISO expiry without a zone *(invalid)*;
  expiry already in the past *(invalid)*;
- empty `commands` array; empty string command; whitespace-only command; duplicate commands;
  21 commands; a command of 8001 characters;
- a command containing a NUL; a command with a lone surrogate escape; a command with emoji
  (valid); a command with a tab and an escaped CRLF (valid, kept exactly);
- `cwd` with `where: any` *(invalid)*; `cwd` missing for `dir`; a relative `cwd`; a UNC `cwd`;
- `hosts: []`; an unknown host; a duplicate host;
- `v` given as `true`, `1.0` or `2`;
- an unknown field; a duplicate key; a duplicate key that differs only by a `\u` escape;
- keys `name` and `Name` in both orders (an `unknown-field` on `Name`); `v` and `V`; a
  mixed-case unknown field such as `Commands`;
- a command of exactly 8000 code points made of emoji (valid, but 16000 UTF-16 units), and the
  same with 8001 (invalid); a `why` of exactly 1000 emoji (valid);
- SIDs: valid; a leading zero; a sub-authority of 4294967296; an authority of 2^48; 16
  sub-authorities (all invalid except the first);
- the name `Push` (uppercase) *(invalid)*; a 41-character name;
- `why` of 1001 characters; `tool` of 41 characters;
- `NaN` as a value; a trailing comma; single quotes; a top-level array; a BOM; invalid UTF-8.

**Files:**
- empty (valid); one grant (valid); a grant then a revoke (valid, not active);
- a revoke of `*` then a new grant (the new one is active);
- a revoke by another user (no effect);
- a valid grant followed by a malformed revoke *(invalid)*;
- a truncated last line; a missing final newline; a blank line; a CRLF line ending;
- a duplicate grant ID; a grant and a revoke sharing an ID;
- a bad SID; missing `user_display`; `path` given with `where: any`;
- a timestamp without `Z`; `expires: null` (valid, until revoked);
- a file over 1 MB (generated in the test, not stored).

**Conversions** (Windows only, placeholders):
- `dir` in `{TMP}` (record `path` is that folder); `repo` from `{TMP_REPO}\sub` (record `path`
  is the repo root); `any` (record `path` is `null`);
- `repo` from `{TMP}`, which has no `.git` above it *(`bad-value` on `where`)*;
- `dir` in `{TMP}\missing`, which doesn't exist *(`bad-value` on `cwd`)*;
- `30m` expiry (record `expires` = `now` + 30 minutes); `never` (record `expires` = `null`);
  ISO expiry with `+02:00` (stored in UTC).

### 2.3 Error codes (stable strings)

| Code | Meaning |
|---|---|
| `too-large` | File over 1,048,576 bytes |
| `bom` | Starts with the UTF-8 BOM |
| `encoding` | Not valid UTF-8 |
| `cr` | Contains a raw `\r` |
| `no-final-newline` | Non-empty file not ending in `\n` |
| `blank-line` | An empty line |
| `json-syntax` | Not parseable JSON, including `NaN` and trailing commas |
| `not-object` | Top level isn't an object |
| `duplicate-key` | The same key twice in one object |
| `unknown-field` | A key not in the table |
| `missing-field` | A required key is absent |
| `bad-type` | Wrong JSON type (e.g. `v` given as `true`) |
| `bad-value` | Right type, invalid value (range, regex, enum, lone surrogate) |
| `expired` | A request's absolute expiry is already past |
| `duplicate-id` | An ID repeated within the file |

Each error reports `code`, `field` (or `null`), and `line` (1-based, files only). Validation
stops at the **first** error. Fields are checked in **table order** (sections 3.2 and 3.3),
with unknown-field and missing-field checks running before per-field checks. **The order is
part of the contract**, because the first error code must match across implementations.

---

## 3. Phase 2 — `exception_grants.py`, pure logic

**Goal:** everything that needs no Windows API. All of it runs on Ubuntu CI too.

### 3.1 Module skeleton

```python
"""Exception grants: read, validate, and match user-approved command exceptions.

See exception-grants-design.md. Pure functions first; Windows calls live in
the _win32 section and are only used on sys.platform == "win32".
"""
from __future__ import annotations

import json
import ntpath
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

MAX_FILE_BYTES = 1_048_576
KNOWN_HOSTS = ("claude", "codex", "cursor", "windsurf", "devin", "antigravity")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
DURATION_RE = re.compile(r"^([1-9][0-9]{0,3})([mhd])$")
REQUEST_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})$")
STORED_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SID_RE = re.compile(r"^S-1-(0|[1-9][0-9]{0,14})(-(0|[1-9][0-9]{0,9})){1,15}$")
# Also check numerically, after the regex (D19):
#   authority < 2**48 and every sub-authority <= 4294967295
GRANT_ID_RE = re.compile(r"^g-\d{8}T\d{6}Z-[0-9a-f]{8}$")
REVOKE_ID_RE = re.compile(r"^r-\d{8}T\d{6}Z-[0-9a-f]{8}$")
DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")


@dataclass(frozen=True)
class ValidationError:
    code: str
    field: Optional[str] = None
    line: Optional[int] = None

    def describe(self) -> str: ...      # e.g. "line 3: bad-value in 'commands'"


class GrantFileInvalid(Exception):
    def __init__(self, error: ValidationError) -> None: ...


@dataclass(frozen=True)
class Grant:
    id: str
    name: str
    ts: datetime
    user: str
    user_display: str
    commands: Tuple[str, ...]
    tool: str
    where: str                 # "dir" | "repo" | "any"
    path: Optional[str]
    hosts: Optional[Tuple[str, ...]]
    expires: Optional[datetime]
    why: str
    line: int


@dataclass(frozen=True)
class Revoke:
    id: str
    ts: datetime
    user: str
    name: str                  # a grant name, or "*"
    line: int
```

### 3.2 Request validation — `validate_request(obj, now) -> Optional[ValidationError]`

This exists in Python so the tests can prove that the help block (section 5.4) produces valid
requests, and so the fixtures can be checked on both sides. Check the fields **in this order**:

1. `obj` is a `dict`; otherwise `not-object`.
2. Unknown keys: allowed = {`v`, `name`, `commands`, `tool`, `where`, `cwd`, `hosts`,
   `expires`, `why`}. The first unknown key gives `unknown-field`.
3. Missing keys: required = all of the above except `cwd`. The first missing one, in that
   order, gives `missing-field`.
4. `v`: `type(v) is int and v == 1`. Use `type(...) is int` because `isinstance(True, int)` is
   `True` in Python. A bool gives `bad-type`, any other int `bad-value`, anything else
   `bad-type`.
5. `name`: must be a `str` (otherwise `bad-type`), matching `NAME_RE` (otherwise `bad-value`).
6. `commands`: a `list` (`bad-type`) of length 1–20 (`bad-value`). Each item must be a `str`
   (`bad-type`), be 1–8000 characters long, contain no `\x00`, not be whitespace-only
   (`s.strip() == ""`), and contain no lone surrogates (`bad-value`). No duplicates
   (`bad-value`).
7. `tool`: a `str` of 0–40 characters.
8. `where`: one of `dir`, `repo` or `any`.
9. `cwd`: if `where` is `any`, it must be absent or `None` (`bad-value`). Otherwise it must be
   present (`missing-field`), a `str`, match `DRIVE_PATH_RE`, and contain no `..` or `.`
   components (`bad-value`).
10. `hosts`: `None`, or a non-empty list of distinct strings that are all in `KNOWN_HOSTS`.
11. `expires`: a `str`. It is `"never"`, matches `DURATION_RE`, or matches `REQUEST_TS_RE` and
    parses. For an absolute time, `expires <= now` gives `expired`.
12. `why`: a `str` of 0–1000 characters.

**Lone surrogate check:** `s.encode("utf-8")` raises `UnicodeEncodeError` if the string has a
lone surrogate. Catch exactly that exception.

### 3.3 Stored record validation — `validate_record(obj) -> ValidationError | None`

- Read `type` first. It must be the string `"grant"` or `"revoke"`; otherwise `missing-field`
  or `bad-value` on `type`.
- **`grant`** key order: `v`, `type`, `id`, `name`, `ts`, `user`, `user_display`, `commands`,
  `tool`, `where`, `path`, `hosts`, `expires`, `why`. All are required.
  - `id`: `GRANT_ID_RE`.
  - `ts`: `STORED_TS_RE`, and it must parse.
  - `user`: `SID_RE`.
  - `user_display`: a `str` of 1–256 characters.
  - `path`: `None` exactly when `where` is `any`. Otherwise a drive path, as in 3.2 step 9.
  - `expires`: `None`, or `STORED_TS_RE`.
  - `commands`, `tool`, `hosts`, `why`: as in 3.2.
- **`revoke`** key order: `v`, `type`, `id`, `ts`, `user`, `name`. All are required.
  - `id`: `REVOKE_ID_RE`.
  - `name`: `NAME_RE`, or exactly `"*"`.

### 3.4 Strict JSON parsing — `parse_json_line(text) -> Any` (raises `_JsonError(code)`)

```python
def _no_duplicates(pairs):
    # Called by json for every object, with keys already unescaped. That means
    # "na\u006de" and "name" are compared as the same key -- exactly what we want.
    result = {}
    for key, value in pairs:
        if key in result:
            raise _JsonError("duplicate-key", key)
        result[key] = value
    return result

def _reject_constant(name):
    # json calls this for NaN, Infinity and -Infinity, which strict JSON forbids.
    raise _JsonError("json-syntax", None)

json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
```

Catch `json.JSONDecodeError` (a subclass of `ValueError`) and turn it into `json-syntax`.

### 3.5 Whole-file validation — `validate_file_bytes(data: bytes) -> Tuple[List[Grant], List[Revoke]]`

Raises `GrantFileInvalid` on the first error. Steps, in order:

1. `len(data) > MAX_FILE_BYTES` → `too-large`.
2. `data.startswith(b"\xef\xbb\xbf")` → `bom`.
3. Decode with `data.decode("utf-8")` (strict). `UnicodeDecodeError` → `encoding`.
4. `"\r" in text` → `cr`.
5. If `text == ""`, return empty lists.
6. If `not text.endswith("\n")` → `no-final-newline`.
7. `lines = text[:-1].split("\n")`. For each line, numbered from 1:
   - `line == ""` → `blank-line`.
   - parse (3.4), then `validate_record` (3.3), setting `line` on the error.
   - Check the `id` against a set of seen IDs; a repeat → `duplicate-id`.
   - Build a `Grant` or `Revoke`, parsing timestamps with
     `datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)`.
8. Return the records in file order.

### 3.6 Active grants — `active_grants(grants, revokes, now) -> List[Grant]`

Merge both lists by `line`, then walk them in file order:

```
active = []                                    # file order
for record in sorted(grants + revokes, key=line):
    if record is a Grant:
        active.append(record)
    else:  # Revoke
        keep only grants g in active where NOT (g.user == r.user and
                                               (r.name == "*" or g.name == r.name))
return [g for g in active if g.expires is None or now < g.expires]
```

This is correct because a revoke only affects grants *earlier* in the file. Grants added later
are appended afterwards, so the revoke never sees them.

### 3.7 Paths — `canonical_path(p) -> Optional[Tuple[str, ...]]`

```python
def canonical_path(p: str) -> Optional[Tuple[str, ...]]:
    # Returns lowercase path components, e.g. ("c:", "src", "repo").
    # Returns None for anything that is not a drive-letter absolute path.
    if not DRIVE_PATH_RE.match(p):
        return None
    normalized = ntpath.normpath(p)          # "C:/a/./b/../c" -> "C:\a\c"
    parts = [part for part in normalized.split("\\") if part]
    return tuple(part.lower() for part in parts)
```

- **Why `ntpath` and not `os.path`:** `ntpath` applies Windows rules on every OS, so the tests
  behave the same on Ubuntu CI.
- **Why `.lower()` and not `os.path.normcase`:** `normcase` does nothing on Linux. Windows path
  case-insensitivity is close enough to Unicode `lower()` for this purpose.

`location_matches(grant, cwd)`:
- `any` → `True`.
- Otherwise compute `c = canonical_path(cwd)` and `g = canonical_path(grant.path)`. If either is
  `None`, return `False`.
- `dir` → `c == g`.
- `repo` → `c[:len(g)] == g`. This prefix comparison is on *components*, so `C:\repo` never
  matches `C:\repo-other`.

### 3.8 Matching — `first_match(active, command, cwd, host, tool, user) -> Optional[Grant]`

Return the first grant `g` in `active` where **all** of these hold:

- `g.user == user`
- `g.hosts is None or host in g.hosts`
- `g.tool == tool` (exact)
- `command in g.commands` (exact; Python `==` on `str` is ordinal and case-sensitive)
- `location_matches(g, cwd)`

### 3.9 Help lines — `help_lines(command, cwd, host, tool) -> List[str]`

```python
lines = ["If this command is needed, ask the user for an exception grant. "
         "Fill in name and why, then give the user this block:"]
if canonical_path(cwd) is not None:
    clean_cwd = ntpath.normpath(cwd)             # "C:/a/./b" -> "C:\a\b" (PLAN-007)
else:
    clean_cwd = ""                               # decision D4: never widen to "any"
request = {"v": 1, "name": "", "commands": [command], "tool": tool,
           "where": "dir", "cwd": clean_cwd,
           "hosts": [host], "expires": "30m", "why": ""}
lines.append(json.dumps(request, ensure_ascii=True, separators=(",", ":")))
if clean_cwd == "":
    lines.append(f"This host reported the folder as {cwd!r}, which is not a Windows path. "
                 "Fill in the Windows folder in cwd.")
return lines
```

The key order follows the request table. The output is deliberately **not** a valid request:
`name` is empty, and `cwd` may be empty. **Don't promise that filling in the name always makes
it valid.** The command itself may still break a rule, for example by being over 8000 code
points. The tests check that:

- with a normal Windows `cwd` and a short command, filling in `name` gives a valid request;
- with a POSIX-like `cwd`, the request is invalid until `cwd` is filled;
- with an over-long command, it stays invalid.

### 3.10 Store mention check — `mentions_protected_store(command, grants_path) -> bool`

```python
folder = ntpath.dirname(grants_path).lower()
needles = {folder, folder.replace("\\", "/"), "aiallow", "grant-writer", "setup-grants",
           ntpath.basename(grants_path).lower()}
lower = command.lower()
return any(needle and needle in lower for needle in needles)
```

This is a simple substring test, which is enough under the guardrail model.

### Phase 2 tests (`tests/test_exception_grants.py`)

- Every `cases.json` entry: Python's verdict and first error code must match the manifest.
- `active_grants` and `first_match` unit tests from design section 11 ("Matching").
- `canonical_path`: case, slash direction, `..`, UNC (returns `None`), `/e/Source` (returns
  `None`).
- `help_lines`: the three cases in 3.9. Emoji and tab commands come back exactly after JSON
  decoding. A `cwd` with `.` components is cleaned.
- `mentions_protected_store`: forward and back slashes, mixed case.

**Done when:** every fixture passes on Ubuntu and Windows CI; `ruff` is clean.

---

## 4. Phase 3 — Windows integrity and identity (`exception_grants.py`, `_win32` section)

### 4.1 Pure evaluator (testable on any OS)

```python
@dataclass(frozen=True)
class Ace:
    type: int     # 0 allow, 1 deny, anything else = unusual
    flags: int    # 0x08 = INHERIT_ONLY
    mask: int
    sid: str

@dataclass(frozen=True)
class ObjectSecurity:
    owner_sid: Optional[str]
    dacl_present: bool        # False means a NULL DACL
    dacl_protected: bool
    aces: Tuple[Ace, ...]
    is_reparse: bool

def parse_security_descriptor(data: bytes, is_reparse: bool) -> ObjectSecurity: ...
def protected_object_problems(sec: ObjectSecurity, require_protected_dacl: bool) -> List[str]: ...
def ancestor_problems(sec: ObjectSecurity) -> List[str]: ...
```

Implement rules I4 and I5 exactly. Each problem is a pair: a stable code from the ACL fixture
list (2.1) and a readable message, such as
`("write-right", "Users can write to C:\\ProgramData\\cc-ai-review\\grants.jsonl")`. An empty
list means OK.

**`parse_security_descriptor`** is plain Python with `struct`, so it is testable on every OS.
It reads a **self-relative** descriptor. All integers are little-endian except the SID
authority.

```
SECURITY_DESCRIPTOR (self-relative), 20 bytes:
  Revision u8 (must be 1) | Sbz1 u8 | Control u16 | OffsetOwner u32 | OffsetGroup u32
  | OffsetSacl u32 | OffsetDacl u32
  Control bits: SE_DACL_PRESENT 0x0004, SE_DACL_PROTECTED 0x1000, SE_SELF_RELATIVE 0x8000
  NULL DACL  <=>  (Control & SE_DACL_PRESENT) == 0  or  OffsetDacl == 0

ACL header, 8 bytes:  AclRevision u8 | Sbz1 u8 | AclSize u16 | AceCount u16 | Sbz2 u16
Each ACE:             AceType u8 | AceFlags u8 | AceSize u16, then the body
  type 0 (allow) / 1 (deny): Mask u32, then the SID
  any other type: keep (type, flags) with mask=0 and sid=""; rule I4/I5 rejects it

SID: Revision u8 (must be 1) | SubAuthorityCount u8 (1..15)
     | IdentifierAuthority 6 bytes BIG-endian | SubAuthority u32 x count
  string form: "S-1-<authority>-<sub1>-<sub2>..."
```

Check every offset and size against `len(data)` **before** reading it. Also check
**containment**: the ACL's `AclSize` must fit inside the buffer, every ACE must fit inside
`AclSize`, and an ACE's SID must fit inside that ACE's `AceSize`. Any out-of-range read, a
containment failure, `SE_SELF_RELATIVE` not set, or `AceSize` smaller than its header gives a
`malformed` problem.
A malformed descriptor never counts as OK.

### 4.2 Windows reader — `read_object_security(path) -> ObjectSecurity`

This only fetches the bytes; all interpretation happens in the pure parser above. Use
`ctypes.WinDLL("advapi32", use_last_error=True)` and `kernel32`:

1. `GetNamedSecurityInfoW(path, SE_FILE_OBJECT=1, OWNER_SECURITY_INFORMATION=0x1 | DACL_SECURITY_INFORMATION=0x4, None, None, None, None, byref(pSD))`.
   A non-zero return value is an error, so raise `OSError(ret)`. The returned descriptor is
   self-relative.
2. `n = GetSecurityDescriptorLength(pSD)`, then `data = ctypes.string_at(pSD, n)`.
3. **Always** `LocalFree(pSD)` in a `finally` block.
4. Get `is_reparse` from `os.lstat(path).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT`.
5. Return `parse_security_descriptor(data, is_reparse)`.

Declare `argtypes` and `restype` for every function. 64-bit pointers get truncated without
them.

### 4.3 Token helpers

- `current_user_sid() -> str`: `OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY=0x8)`, then
  `GetTokenInformation(TokenUser=1)` (call it once to get the size, again to fill a buffer),
  then `ConvertSidToStringSidW`.
- `is_elevated() -> bool`: `GetTokenInformation(TokenElevation=20)` into a DWORD. Close the
  token handle in `finally`.

### 4.4 The check — `check_store(grants_path, writer_path=None, elevated_ok=False) -> List[str]`

Returns a list of problems; empty means protected.

1. If not on Windows, return `["Exception grants are not supported on this platform."]`.
2. If not `elevated_ok` and `is_elevated()`, add "running elevated" and return.
3. If the folder or file doesn't exist, return
   `["Exception grants are not set up. Run: aiallow setup"]`.
4. Check the folder with `protected_object_problems(require_protected_dacl=True)`.
5. Check the grants file with `protected_object_problems(require_protected_dacl=False)`.
6. If `writer_path` is given, check it with `require_protected_dacl=False`.
7. For each ancestor in `Path(folder).parents`, up to and including the drive root, apply
   `ancestor_problems`.
8. Any `OSError` while reading security adds `"could not read security of <path>: <err>"`.
   Any error counts as a problem.

### 4.5 Lookup used by the hook — `find_grant(settings, command, cwd, host, tool, now=None) -> Lookup`

```python
@dataclass(frozen=True)
class Lookup:
    grant: Optional[Grant]
    note: Optional[str]      # shown to the user when grants were skipped

def find_grant(...) -> Lookup:
    try:
        problems = check_store(settings.grants_path)
        if problems:
            return Lookup(None, "Exception grants ignored: " + problems[0]
                                + ". Run: aiallow check")
        with open(settings.grants_path, "rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)   # bounded read
        grants, revokes = validate_file_bytes(data)
        now = now or datetime.now(timezone.utc)
        active = active_grants(grants, revokes, now)
        return Lookup(first_match(active, command, cwd, host, tool, current_user_sid()), None)
    except GrantFileInvalid as exc:
        return Lookup(None, f"Exception grants ignored: grants file invalid ({exc.error.describe()})."
                            " Fix with: aiallow edit")
    except Exception as exc:  # noqa: BLE001 -- isolates grant code; can only mean "no grant"
        return Lookup(None, f"Exception grants ignored: {type(exc).__name__}: {exc}")
```

The broad `except` is deliberate and must keep its comment. It is the only one in this module.

### Phase 3 tests (`tests/test_grant_integrity.py`)

- **ACL fixtures, all OSes:** every `tests/fixtures/acl/cases.json` entry runs through
  `parse_security_descriptor` plus the role's check. The verdict and first problem code must
  match. (The writer runs the same fixtures in Phase 5.)
- **Pure evaluator, all OSes:** each rule in I4 and I5. That includes:
  - an inherit-only write ACE (OK);
  - a deny ACE (OK);
  - `WRITE_DAC` alone for Users (fails);
  - `FILE_APPEND_DATA` alone (fails);
  - an unusual ACE type (fails);
  - a NULL DACL (fails);
  - an untrusted owner (fails);
  - an unprotected folder DACL (fails);
  - an ancestor where Users have `ADD_SUBDIR` only (OK);
  - an ancestor where Users have `DELETE` (fails);
  - an ancestor with a NULL DACL or an unusual ACE type (fails);
  - truncated or inconsistent descriptor bytes (`malformed`, fails, never raises).
- **Windows only** (`@pytest.mark.skipif(sys.platform != "win32", ...)`):
  - a temp folder and file the user owns are rejected, with an owner problem;
  - a junction (`_winapi.CreateJunction`, standard library) inside the path is rejected;
  - `read_object_security(r"C:\Windows\System32\drivers\etc\hosts")` returns a trusted owner,
    and `protected_object_problems` reports no write problems;
  - `current_user_sid()` matches `SID_RE`;
  - `is_elevated()` returns a bool.

**Done when:** the pure tests pass everywhere, and the Windows tests pass locally and on Windows
CI. (Windows CI runners are elevated, so mark the "not elevated" assertions to skip when
`is_elevated()` is true.)

---

## 5. Phase 1 (do before Phase 2) — Config

### 5.1 `config.py`

Add `import ntpath` and `import re` at the top, then add the following:

```python
DEFAULTS["exceptions"] = {"enabled": False, "grants_path": None}

DEFAULT_GRANTS_PATH = r"C:\ProgramData\cc-ai-review\grants.jsonl"

@dataclass(frozen=True)
class ExceptionSettings:
    enabled: bool
    grants_path: str        # always absolute after resolution

_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")   # same rule as exception_grants (D3)

@property
def exceptions(self) -> ExceptionSettings:   # on Config
    raw = self.data.get("exceptions")
    # Only "absent" and null mean defaults. `false`, 0, "", [] and other scalars are
    # mistakes and must fail closed (A13, PLAN-006). Don't write `... or {}` here:
    # that would quietly turn `exceptions: false` into the defaults.
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"exceptions must be a mapping, got {raw!r}.")
    enabled = coerce_bool(raw.get("enabled", False), "enabled", section="exceptions")
    path_value = raw.get("grants_path")
    if path_value is None:
        path = _default_grants_path()
    elif isinstance(path_value, str) and path_value.strip():
        path = os.path.expandvars(os.path.expanduser(path_value.strip()))
    else:
        raise ConfigError("exceptions.grants_path must be a path or null, got "
                          f"{path_value!r}. If you set it via an environment variable, "
                          "'off'/'false' are read as booleans.")
    # A drive letter is required, not just "absolute": ntpath.isabs("\\x") is True on
    # some Python versions, but a rooted path without a drive is not allowed (D3).
    if not _DRIVE_PATH_RE.match(path):
        raise ConfigError(f"exceptions.grants_path must start with a drive letter, "
                          f"e.g. C:\\..., got {path!r}.")
    return ExceptionSettings(enabled=enabled, grants_path=ntpath.normpath(path))
```

`DEFAULTS` contains an `exceptions` mapping, and `deep_merge` replaces a mapping with a
non-mapping overlay. So `exceptions: false` in YAML arrives here as `False` and is rejected, as
intended.

- `_default_grants_path()` uses the `ProgramData` folder from
  `SHGetKnownFolderPath(FOLDERID_ProgramData)` through `ctypes` when on Windows. If that fails,
  or on other OSes, it falls back to `DEFAULT_GRANTS_PATH`. **Don't read `%ProgramData%`**: the
  environment is user-controlled (same reasoning as A15).
- `coerce_bool` currently prefixes its messages with `policy.`. Add an optional `section`
  parameter (default `"policy"`) so the message reads `exceptions.enabled`. This is the only
  change to `coerce_bool`.

### 5.2 `config.example.yaml`

Add an `exceptions:` block with the comments from design section 3, including "Windows only"
and "run `aiallow setup` first".

### Phase 1 tests (`tests/test_config.py`)

- The default is disabled, with the default path.
- YAML `enabled: true`.
- Environment variable `CC_AI_REVIEW__EXCEPTIONS__ENABLED=false` → disabled.
- `grants_path: off` set through the environment gives a `ConfigError` whose message mentions
  booleans.
- A relative path gives a `ConfigError`, and so does a rooted path without a drive (`\x\g.jsonl`).
- An absent section and `exceptions: null` give the defaults.
- `exceptions: false`, `0`, `""`, `[]`, `5` and `"yes"` each give a `ConfigError`.
- An invalid `enabled` value's error message starts with `exceptions.enabled`, not `policy.`.

**Done when:** these tests pass, and the existing config tests are unchanged and passing.

---

## 6. Phase 4 — Hook integration (`review_core.py`)

### 6.1 `Review` and `render_reason`

1. Add `extra_lines: List[str] = field(default_factory=list)` to `Review`.
2. In `render_reason`, after the footer line, append each item of `review.extra_lines`. Don't
   apply the ten-particular limit to them.
3. Existing tests must still pass unchanged. `extra_lines` defaults to empty, so output is
   identical when it isn't used.

### 6.2 `NON_LIFTABLE_FLAGS`

Add this constant:

```python
NON_LIFTABLE_FLAGS = frozenset({"exception-store-access", "missing-command", "hook-input-parse-error"})
```

### 6.3 Refactor the tail of `review_payload` into `_finalize`

Move the refused-`.env` note and `log_review` from the end of `review_payload` into:

```python
def _finalize(final: Review, *, config: Config, policy: Policy, exceptions: ExceptionSettings,
              command: str, cwd: str, description: str, host: str, tool: str,
              grant_note: Optional[str]) -> Review:
    # 1. refused .env note (existing code, moved here unchanged)
    # 2. exception help/notes
    if _exceptions_active(exceptions) and final.decision in ("deny", "ask") \
            and command and not (set(final.flags) & NON_LIFTABLE_FLAGS):
        if grant_note:
            final.extra_lines.append(grant_note)
        final.extra_lines.extend(exception_grants.help_lines(command, cwd, host, tool))
    elif exceptions.enabled and sys.platform != "win32" and final.decision in ("deny", "ask"):
        final.extra_lines.append("Exception grants are not supported on this platform.")
    # 3. log_review(...)  (existing call, moved here unchanged)
    return final
```

`_exceptions_active(s)` is `s.enabled and sys.platform == "win32"`.

The parse-error and out-of-scope early returns stay as they are. They already log, and they
never get grants.

### 6.4 New flow in `review_payload`

The code after the out-of-scope check becomes:

```python
exceptions = config.exceptions
tool = tool_name(payload)
grant_note: Optional[str] = None

if _exceptions_active(exceptions) and \
        exception_grants.mentions_protected_store(command, exceptions.grants_path):
    final = Review(decision="deny",
                   headline="Blocked: this command touches the exception-grant store or tools.",
                   particulars=["Only the user may run aiallow or change grants."],
                   flags=["exception-store-access"])
    final = _finalize(final, ..., grant_note=None)
    return ReviewResult(event_name, command, cwd, description, final)

local = local_review(command, cwd, description, policy)

grant = None
if _exceptions_active(exceptions) and not (set(local.flags) & NON_LIFTABLE_FLAGS):
    lookup = exception_grants.find_grant(exceptions, command, cwd, host, tool)
    grant, grant_note = lookup.grant, lookup.note

if grant is not None:
    final = Review(decision="allow", source="grant",
                   headline=f"Allowed by your exception grant '{grant.name}'.",
                   particulars=[exception_grants.scope_summary(grant)],
                   flags=["exception-grant", "exception-grant-id:" + grant.id],
                   dont_ask_again_safe=False)
else:
    ...  # existing external review + combine_reviews code, unchanged
final = final.clamp()
final = _finalize(final, ..., grant_note=grant_note)
return ReviewResult(event_name, command, cwd, description, final)
```

`scope_summary(grant)` returns text like
`"Grant g-…: exact command, any folder of repo C:\x, until 2026-11-19 18:32 UTC"`, or
`"…, until revoked"` when there is no expiry.

**`import exception_grants` must not import any Windows-only module at load time.** Ubuntu CI
imports `review_core`, so any `ctypes.WinDLL` calls must happen inside functions.

### Phase 4 tests

**In `tests/test_review_core.py`,** monkeypatch `exception_grants.check_store` to return `[]`,
`exception_grants.current_user_sid` to return a fixed SID, and point `grants_path` at a temp
file with fixture contents. Mark these tests Windows-only, or also patch
`_exceptions_active`. Test that:

- a matching grant gives `allow`, `source == "grant"`, the ID in the flags, and is
  decision-logged;
- the external reviewer is never called (reuse the `no_network` fixture pattern);
- a non-matching command gets normal review plus the help line;
- the help line still appears with more than ten particulars;
- `exception-store-access` is denied and has no help line;
- an invalid file adds the note and the help line, and grants nothing;
- with exceptions disabled, output is byte-for-byte the same as before.

**In `tests/test_adapters.py`,** for each of the six adapters:

1. Run a denied payload and parse the help block from the adapter's reason text.
2. Fill in `name`, then convert it to a stored grant with a test helper that mirrors the
   writer's conversion.
3. Write it to the temp grants file.
4. Run the same payload again. Assert the adapter's own allow output.

### 6.5 Installers in this phase (A17, PLAN-001)

`review_core.py` now imports `exception_grants`, so **this phase** adds `exception_grants.py` to
the copy lists in both `install.ps1` and `install.sh`. The CLI, writer, setup and docs still
wait for Phase 8.

Add `tests/test_installers.py`, which runs on every OS and uses no installation:

1. Parse the copy lists from `install.ps1` (the `foreach ($f in @(...))` list) and `install.sh`
   (the `for f in ...; do` list) with regexes.
2. Use the standard `ast` module to find every top-level `import X` / `from X import` in each
   installed hook file. Keep only names that match a `.py` file in `.claude/hooks/`.
3. Assert that every such module appears in both copy lists.

This catches a forgotten installer entry at test time, without touching the machine.

Also add one check that runs the **installed copy**: copy only the files listed by
`install.ps1` into a temp folder, then run
`python <temp>\safe-command-review-hook.py < examples\hook-input-safe-readonly.json` with
exceptions disabled, and assert a valid decision. This tests the copied set of files, not
imports from the checkout.

**Done when:** all of the above pass, and the full existing suite passes unchanged.

---

## 7. Phase 5 — `grant-writer/grant-writer.ps1`

### 7.1 Rules for this script (it runs elevated)

1. **No cmdlets.** Not even `New-Object`, `Write-Host` or `ConvertFrom-Json`.
   - Use `[Type]::new(...)` and .NET methods.
   - Use `foreach (...) {}` loops, not pipelines.
   - Allowed: language keywords, variables, `try`/`catch`/`finally`, `param()`, `exit`.
   - **This includes `Set-StrictMode`, which is a cmdlet too.** Don't use it. Instead, test
     variables explicitly, and rely on `$ErrorActionPreference` and `try`/`catch`.
   - Don't use `& $scriptblock` either. Write the mutex handling inline in `Invoke-Main`
     (function 10).
2. The first lines must be:
   ```powershell
   param([string]$Action, [string]$ForUser, [string]$Name, [string]$GrantsPath,
         [string]$RequestFile, [string]$GrantsFile, [string]$AclFile, [string]$OldFile,
         [string]$NewFile, [string]$Now, [switch]$LibraryOnly)
   $ErrorActionPreference = 'Stop'   # a variable assignment, not a cmdlet
   ```
3. Load assemblies by **full name only**, so they come from the protected Global Assembly Cache:
   ```powershell
   [void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
   [void][System.Reflection.Assembly]::Load('System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
   [void][System.Reflection.Assembly]::Load('System.Runtime.Serialization, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
   ```
4. Never read the config, never run Git, and never start another process.
5. `-Now` and `-ForUser` are accepted by the validate actions so tests can set them. Write
   actions **ignore `-Now`** and always use `[DateTime]::UtcNow`.

### 7.2 Exit codes (shared with `aiallow`)

| Code | Meaning |
|---|---|
| 0 | Success |
| 10 | User cancelled in the writer's dialog |
| 20 | Request invalid |
| 21 | Grants file invalid (add/revoke) |
| 30 | Integrity check failed |
| 40 | Another grant window is open (mutex busy) |
| 41 | Mutex error (access denied, or wrong object type) |
| 50 | Write failed; re-read shows the file unchanged |
| 51 | Write failed; re-read shows the new content present |
| 52 | Write failed; re-read itself failed (outcome unknown) |
| 60 | Unexpected error |

Write actions also show a MessageBox describing the result. Validate actions print one JSON
object to stdout and show no UI.

### 7.3 Functions to write (in this order)

1. **`Read-StrictJson([string]$text)`.** Validate UTF-8 first: read the bytes with
   `[System.Text.UTF8Encoding]::new($false, $true)`, where `$true` means throw on invalid bytes.
   Then create the reader:
   ```powershell
   $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
   $reader = [System.Runtime.Serialization.Json.JsonReaderWriterFactory]::CreateJsonReader(
       $bytes, [System.Xml.XmlDictionaryReaderQuotas]::Max)
   ```
   The reader presents JSON as XML. Walk it recursively:
   - Each element has a `type` attribute: `object`, `array`, `string`, `number`, `boolean` or
     `null`.
   - An object's key is the element's local name, unless that name is `item` with an `item`
     attribute; then the attribute value is the key. This is how keys that aren't valid XML
     names are carried.
   - Keep a `[System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)` per
     object. A repeated key → `duplicate-key`.
   - Use `[System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::Ordinal)`
     for objects (D17).
     - **Never use `@{}` or `[ordered]@{}`.** They ignore key case, so `name` and `Name` would
       merge into one entry.
     - Read keys only with `$d['key']` and `$d.Contains('key')`. Iterate them with
       `foreach ($k in $d.Keys)`.
   - Use `[System.Collections.Generic.List[object]]` for arrays and `[string]` for strings.
   - For numbers, keep the **raw text** in a small marker class, so `v` can be checked as
     exactly `1`:
     ```powershell
     class JsonNumber { [string]$Text; JsonNumber([string]$t) { $this.Text = $t } }
     ```
     (A `class` definition is a language feature in PowerShell 5, not a cmdlet.)
   - For booleans, use `[bool]`. For null, use `$null`.
   - Wrap reader exceptions as `json-syntax`.
2. **`Test-Request($obj, $now)`.** The same order and codes as Python section 3.2. Compare
   strings with `[string]::Equals($a, $b, [StringComparison]::Ordinal)`. PowerShell's `-eq` is
   case-insensitive and **must not** be used for commands, tools, names, keys or schema
   membership. Test whether a key is allowed with a `HashSet[string]` built with
   `[StringComparer]::Ordinal`, not with `-in` or `-contains`, which also ignore case.

   Check for lone surrogates with `[System.Text.UTF8Encoding]::new($false, $true).GetBytes($s)`
   in a `try`/`catch`.

   **Lengths are code points (D18):**
   ```powershell
   function Get-CodePointCount([string]$s) {
       $count = 0
       for ($i = 0; $i -lt $s.Length; $i++) {
           # A high surrogate followed by a low surrogate is one character (e.g. an emoji).
           if ([char]::IsHighSurrogate($s[$i]) -and $i + 1 -lt $s.Length -and
               [char]::IsLowSurrogate($s[$i + 1])) { $i++ }
           $count++
       }
       return $count
   }
   ```

   **SIDs:** use the same regex and numeric limits as Python (D19). Parse the numbers with
   `[UInt64]::Parse` and compare them to the limits. Never use the `SecurityIdentifier`
   constructor to decide whether a SID is valid.
3. **`Test-Record($obj)`** and **`Read-GrantsFile([byte[]]$data)`**, following Python sections
   3.3, 3.5 and 3.6 exactly.
4. **`ConvertTo-CanonicalJson($ordered)`.** A hand-written serializer following D13. Emit keys
   in the stored-table order (design 7.2). Never use `ConvertTo-Json`.
5. **`Get-RepoRoot($cwd)`.** Starting at `$cwd`, walk up the parent folders. Return the first
   folder where `[System.IO.Directory]::Exists("$d\.git")` or
   `[System.IO.File]::Exists("$d\.git")`. If none is found, the request is invalid for
   `where: repo` (`bad-value`, field `where`).
6. **`ConvertTo-Grant($request, $forUser, $now, $grantsSoFar)`.**
   - Resolve `expires` from the duration, `never` or the timestamp.
   - Set `path`, then `id` (D10, retrying on collision).
   - `user_display` comes from
     `[System.Security.Principal.SecurityIdentifier]::new($forUser).Translate([System.Security.Principal.NTAccount]).Value`,
     falling back to the SID string if translation throws.
   - Reject `dir`/`repo` grants whose `cwd` folder doesn't exist (`bad-value`, field `cwd`).
7. **`Format-Visible([string]$s)`.** Make invisible characters visible for the dialog:
   - `\t` → `⇥`, `\r` → `␍`, `\n` → `␊` followed by a real line break;
   - other U+0000–U+001F → U+2400 + code; U+007F → `␡`;
   - U+200B–U+200F, U+202A–U+202E, U+2060–U+2069 and U+FEFF → `⟦U+XXXX⟧`;
   - leading and trailing spaces → `·`.
8. **`Get-Description($grant)`.** Produces the exact text from design 6.4, using
   `Format-Visible` on every command. The tests compare it to
   `tests/fixtures/grants/descriptions/*.txt`.
9. **`Test-SecurityDescriptor([byte[]]$sd, [bool]$isReparse, [string]$role)`** and
   **`Test-ObjectIntegrity($path, $role)`.** The .NET version of rules I4 and I5, working on the
   **raw descriptor**, the same as Python (I9, PLAN-005):
   - Get the bytes:
     `[System.IO.File]::GetAccessControl($path, 'Owner, Access').GetSecurityDescriptorBinaryForm()`.
     For folders, use `[System.IO.Directory]::GetAccessControl`.
   - Parse them: `$raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($sd, 0)`.
     A parse exception gives `malformed`.
   - **Owner:** `$raw.Owner.Value` must be a trusted SID.
   - **NULL DACL:** `$raw.DiscretionaryAcl -eq $null`, or `ControlFlags` lacking
     `DiscretionaryAclPresent`, gives `null-dacl`.
   - **Protected:** `ControlFlags -band DiscretionaryAclProtected` (folder role only).
   - **ACEs:** `foreach ($ace in $raw.DiscretionaryAcl)`.
     - Read `[int]$ace.AceType`. A raw type other than 0 (`AccessAllowed`) or 1
       (`AccessDenied`) gives `ace-type` for **every** role.
     - Inherit-only is `[int]$ace.AceFlags -band 0x08`.
     - For types 0 and 1 the ACE is a `CommonAce`: read `$ace.AccessMask` and
       `$ace.SecurityIdentifier.Value`.
   - **Reparse:** `[System.IO.File]::GetAttributes($path) -band [System.IO.FileAttributes]::ReparsePoint`.
   - **Ancestors:** `[System.IO.Directory]::GetParent(...)` until it returns `$null`.
   - Report the same problem codes as Python, in the same order.

   `Test-SecurityDescriptor` takes bytes, so the tests can feed it the shared hex fixtures. Add
   a read-only action `validate-acl -AclFile <cases.json>` that runs every fixture and prints
   the results as JSON.
10. **The mutex, written inline in `Invoke-Main`** (no `& $scriptblock`, A18):
    ```powershell
    function Invoke-Main {
        $mutex = $null; $owned = $false
        try {
            try {
                $created = $false
                $mutex = [System.Threading.Mutex]::new($false, 'Global\cc-ai-review-grants', [ref]$created)
            } catch [System.UnauthorizedAccessException] {
                return (Show-Result 41 'Lock object exists but access is denied.')
            } catch [System.Threading.WaitHandleCannotBeOpenedException] {
                return (Show-Result 41 'Lock name is used by another kind of object.')
            }
            try { $owned = $mutex.WaitOne(0) }
            catch [System.Threading.AbandonedMutexException] { $owned = $true }  # previous holder crashed
            if (-not $owned) { return (Show-Result 40 'Another grant window is open.') }

            if ($Action -ceq 'add')    { return (Invoke-Add) }
            if ($Action -ceq 'revoke') { return (Invoke-Revoke) }
            if ($Action -ceq 'edit')   { return (Invoke-Edit) }
            return (Show-Result 60 "Unknown action.")
        } finally {
            if ($owned) { $mutex.ReleaseMutex() }
            if ($mutex -ne $null) { $mutex.Dispose() }
        }
    }
    ```
    Notes:
    - `-ceq` is the case-sensitive equality operator.
    - `Show-Result` shows a MessageBox and returns the code.
    - The validate actions are dispatched **before** `Invoke-Main` and never touch the mutex.
    - The script's last line is `exit (Invoke-Main)` for write actions. Because no `exit`
      happens inside the `try`, the `finally` always runs.
11. **`Write-GrantsAtomically($grantsPath, [byte[]]$newBytes)`**, following design 6.1 step 5:
    1. Write the temp file as `<folder>\grants.<random>.tmp` with `[System.IO.File]::WriteAllBytes`,
       then reopen it with `FileStream.Flush($true)` to force it to disk.
    2. Set the temp file's security explicitly: owner `BA`, DACL
       `D:PAI(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)`, via `FileSecurity.SetSecurityDescriptorSddlForm` and
       `[System.IO.File]::SetAccessControl`.
    3. `[System.IO.File]::Replace($temp, $grantsPath, $null)`.
    4. On any exception, **while still holding the mutex**:
       - delete the temp file if it exists;
       - re-read `grants.jsonl`;
       - if the re-read bytes equal the original bytes → 50 (unchanged);
       - if they equal `$newBytes` → 51 (the new content is present);
       - **anything else**, including a failed re-read or *different* bytes → 52 (outcome
         unknown; run `aiallow check` and `aiallow list`).
       - Never fall through to success, and never retry.
    5. On success, run `Test-ObjectIntegrity` on the grants file again. If it fails, exit 30
       with "written, but permissions are wrong — run aiallow setup".
12. **Dialogs (Windows Forms):**
    - The confirmation is a `Form` with a read-only, multiline `TextBox` in Consolas, with both
      scrollbars, showing `Get-Description`. Below it go an expiry `ComboBox` (the requested
      value, `15m`, `30m`, `1h`, `2h`, `8h`, `1d`, `7d`, `never`), then **Approve** and
      **Cancel** buttons.
    - Set `AcceptButton = Cancel` and `CancelButton = Cancel`, so Enter and Esc both cancel and
      only a mouse click (or Tab plus Space) approves.
    - Changing the expiry regenerates the description.
    - The edit window is a `Form` with an editable multiline `TextBox` (Consolas,
      `WordWrap = $false`) plus **Save…** and **Cancel**. Save runs validation; on failure it
      shows the errors and keeps the window open; on success it shows the line diff in the
      confirmation form.

### 7.4 Actions

- **`add`:** inside the mutex:
  1. run integrity on the folder, the grants file and the writer itself (`$PSCommandPath`);
  2. read and validate the file (exit 21 if invalid);
  3. read the clipboard with `[System.Windows.Forms.Clipboard]::GetText()` (empty → 20);
  4. parse it and run `Test-Request` (exit 20, showing the error);
  5. check the name isn't used by this user's active grants (20);
  6. run `ConvertTo-Grant`, then confirm;
  7. on cancel, exit 10. Otherwise append the canonical line plus `\n`, check the 1 MB limit,
     and run `Write-GrantsAtomically`.
- **`revoke`:** inside the mutex, run integrity, then read and validate. List this user's active
  grants matching `-Name` (or all of them for `*`). If there are none, show "nothing to revoke"
  and exit 0. Otherwise confirm, then append the revoke line.
- **`edit`:** inside the mutex, run integrity **only** (contents may be invalid). Then:
  - if the file is over 1 MB, show "use aiallow setup --reset" and exit 21;
  - decode the bytes leniently for display (`UTF8Encoding($false, $false)`) and open the edit
    window;
  - on Save, apply D15, then validate; on failure, show the errors and stay in the editor;
  - on success, show the line diff (D20):
    - **If old line count × new line count ≤ 1,000,000:** compute the longest common
      subsequence of the two line lists with the standard dynamic-programming table, using a
      flat `[int[]]` of size (n+1)·(m+1). Then walk back through it, marking lines only in
      the old list `-` and lines only in the new list `+`.
    - **Otherwise:** show every old line as `-` and every new line as `+`. This needs no
      table, and still shows every change.
    - The confirm window shows the diff in the same scrolling `TextBox`. Cancel is available
      throughout, and the mutex is released in `finally` whatever happens.
  - on confirm, write atomically.
- **`validate-request -RequestFile <f> [-Now] [-ForUser]`:** print
  `{"valid":…,"error":{code,field,line}|null,"conversion_error":{code,field}|null,"record":{…}|null,"description":"…"|null}`
  to stdout.
  - `valid` and `error` are the **text validation** result only (PLAN-011). They are what the
    `request` fixtures compare with Python.
  - Only when text validation passes does the writer run conversion and fill
    `conversion_error`, or `record` and `description`. Only `conversion` fixtures check
    these.
  - `-ForUser` defaults to `S-1-5-21-0-0-0-1000`, used only for display. No mutex, no
    integrity check, no UI.
- **`validate-file -GrantsFile <f> [-Now]`:** print
  `{"valid":…,"error":…,"active":{"<sid>":["<id>",…]}}`.
- **`validate-acl -AclFile <cases.json>`:** for each ACL fixture, decode the hex, run
  `Test-SecurityDescriptor`, and print `[{"id":…,"ok":…,"problem":…}]`.
- **`validate-diff -OldFile <f> -NewFile <f>`:** print the diff lines and which path was used
  (`"lcs"` or `"fallback"`).
- **`-LibraryOnly`:** define functions and return. Used only by setup's dot-source.
  - The check `if ($LibraryOnly) { return }` goes **after the last function definition and
    before any action runs**. PowerShell defines a script's functions only as execution
    reaches them, so returning earlier would leave the helpers undefined, and returning later
    would run an action inside setup.
  - The assembly loads (7.1 rule 3) run before it, which setup needs anyway.

All `validate-*` actions are read-only. They take no mutex, show no UI and need no elevation.

### Phase 5 tests (`tests/test_grant_writer.py`, Windows only)

Run the script with an **absolute** path anchored to the repo:
`REPO / "grant-writer" / "grant-writer.ps1"`. The interpreter is `<GetSystemDirectoryW()>\WindowsPowerShell\v1.0\powershell.exe`,
with the arguments `-NoProfile -ExecutionPolicy Bypass -File <abs path> -Action validate-request ...`.
Parse stdout as JSON. Test that:

- every `request` and `file` case gets the same verdict, first code, field and line as Python;
- every `conversion` case, with placeholders expanded to real temp folders, gets the expected
  `record` (compared as in 2.1), or the expected `conversion_error`, and the expected
  description;
- every ACL fixture gets the same verdict and problem code through `validate-acl` as through
  Python;
- **diff branch choice (D20, PLAN-010),** through the read-only `validate-diff` action:

  | Old lines × new lines | Product | Expected path |
  |---|---|---|
  | 5,000 × 10 | 50,000 | `lcs` |
  | 1,000 × 1,000 | 1,000,000 (exactly the limit) | `lcs` |
  | 1,000 × 1,001 | 1,001,000 | `fallback` |
  | 200,000 × 10 | 2,000,000 | `fallback` |

  For each, also check that the output lists every removed and every added line. Don't change
  the limit to make a case pass;
- every `descriptions/*.txt` golden file matches, byte for byte;
- `-Action add -GrantsPath <temp folder the user owns>` exits 30 and leaves the file
  unchanged;
- an add attempt while the test itself holds the mutex exits 40. Create the mutex in the test
  via `ctypes` `CreateMutexW`, then launch the script;
- **no-cmdlet check (A18), using PowerShell's own parser.** The test runs this unelevated
  helper script, which is test-only and never shipped:
  The helper (`tests/ps/check-no-cmdlets.ps1`) takes `-Path <script>` and, for setup only,
  `-LibraryPath <grant-writer.ps1>` (PLAN-012):
  ```powershell
  param([string]$Path, [string]$LibraryPath)
  # Collect function names defined in a file, by parsing it. Nothing is executed.
  function Get-DefinedFunctions($ast, $set) { ... FunctionDefinitionAst names into $set ... }

  $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
  $defined = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  Get-DefinedFunctions $ast $defined
  if ($LibraryPath) { Get-DefinedFunctions (parse $LibraryPath) $defined }

  $bad = @()
  foreach ($c in <every CommandAst in $ast>) {
      if (<$c is exactly the allowed import shape, and $LibraryPath was given>) { continue }
      $name = $c.GetCommandName()
      if ($c.InvocationOperator -ne 'Unknown' -or $name -eq $null -or
          -not $defined.Contains($name)) { $bad += $c.Extent.Text }
  }
  $bad   # the test asserts this output is empty, and that $errors is empty
  ```
  - **The allowed import shape** is exactly: invocation operator `Dot`, the command element is
    the variable `$SourceWriter`, and the only other element is the parameter `-LibraryOnly`.
    Anything else is reported: a second dot-source, `&`, a dot-source of anything else, or a
    command whose name is computed at run time (`GetCommandName()` returns `$null`).
  - Only one occurrence of the import shape is allowed; a second is reported.
  - The writer itself is checked **without** `-LibraryPath`, so it may contain no dot-source.
  - Function names in PowerShell are case-insensitive, so `OrdinalIgnoreCase` is correct here.
    Comments and strings aren't `CommandAst` nodes, so they can't affect the result.

  **Self-checks** on small sample scripts, run through the same helper:
  - a call to `Get-Date` is reported; `Get-Date` only inside a comment and a string is not;
  - `& $x` is reported; `. $Other -LibraryOnly` is reported;
  - with `-LibraryPath`, a sample setup that dot-sources `$SourceWriter -LibraryOnly` once
    and calls a function defined only in the library passes; a second identical dot-source is
    reported.

**Done when:** all of the above pass on Windows CI and locally.

---

## 8. Phase 6 — `setup-grants.ps1`

It follows the same rules as 7.1. Parameters:

- `-Reset`: a switch.
- `-SourceWriter <path>`: the installed copy of `grant-writer.ps1` next to `aiallow.py`.
- `-ProgramData <path>`: from `aiallow`.
- **Plan-only test inputs (PLAN-013):**
  - `-PlanOnly`: a switch;
  - `-PlanFolderExists`: a switch;
  - `-PlanIntegrityOk`: a switch;
  - `-PlanNow <yyyy-MM-ddTHH:mm:ssZ>`: the time used for the backup name;
  - `-PlanExisting <string>`: names already present in the `ProgramData` folder, separated by
    `|`. It is one string because `powershell.exe -File` doesn't pass arrays, and `|` can't
    appear in a file name.

**Sharing code with the writer.** Setup needs the writer's integrity, mutex and security
helpers. Rather than copying them, setup **dot-sources** `-SourceWriter`
(`. $SourceWriter -LibraryOnly`).

- When the writer is called with `-LibraryOnly`, it defines its functions and returns without
  doing anything (7.4).
- This is allowed **only in setup**, because setup is the declared installer exception (A6)
  and already trusts the installed source copy. The no-cmdlet test permits exactly that one
  dot-source in `setup-grants.ps1`, and none in `grant-writer.ps1`.
- **Dot-sourcing shares one scope.** The writer's `param()` block and top-level code run in
  setup's scope, so:
  - no writer parameter name may equal a setup parameter name;
  - no function name may be defined in both files. Setup's entry point is `Invoke-Setup`; the
    writer's is `Invoke-Main`;
  - setup copies its own parameters into local variables before the dot-source and uses
    only those afterwards.

  A test parses both files (without running them) and checks the first two rules.

**`Get-SetupPlan($folderExists, $integrityOk, $reset, $existingNames, $now)`** is a pure
function. It returns an `OrderedDictionary` with `action` (`fresh`, `update`, `refuse` or
`reset`) and `backup_name` (`cc-ai-review.old-<yyyyMMddTHHmmssZ>`, with `-2`, `-3`… added
while the name is in `$existingNames`, compared case-insensitively; `$null` unless the action
is `reset`). The decisions:

| `reset` | folder exists | integrity OK | action |
|---|---|---|---|
| yes | yes | either | `reset` |
| yes | no | — | `fresh` (nothing to back up) |
| no | yes | yes | `update` |
| no | yes | no | `refuse` |
| no | no | — | `fresh` |

**Dispatch order:**

1. **If `-PlanOnly`:** call `Get-SetupPlan` with the `-Plan*` values and `-Reset`, print the
   result as one line of JSON, and exit 0. This happens **first**: before the mutex, the
   dot-source, any inspection, any dialog and any change. Plan-only output is descriptive
   only. Nothing ever reads it back as permission to write.
2. **Otherwise,** ignore every `-Plan*` value. Inspect the real store and pass what you found
   to `Get-SetupPlan`, then follow the steps below.

**Steps:**

1. Take the mutex with the same inline pattern as `Invoke-Main` (40 or 41 on failure).
2. `$folder = <ProgramData>\cc-ai-review`. `aiallow` passes `-ProgramData`, which it got from
   `SHGetKnownFolderPath`. Setup also computes
   `[Environment]::GetFolderPath('CommonApplicationData')` itself. If the two differ, exit 30.
   This guards against a wrong or tampered argument without relying on environment variables
   (A15).
3. **If `-Reset`:**
   - show what will happen and confirm;
   - rename the folder to `cc-ai-review.old-yyyyMMddTHHmmssZ`, adding `-2`, `-3` and so on if
     taken, with `[System.IO.Directory]::Move`;
   - if the rename fails, stop with exit 50;
   - never open files inside the old folder.
4. **If the folder exists** (and this isn't a reset): run `Test-ObjectIntegrity` on the folder,
   `grants.jsonl` and the existing `grant-writer.ps1`, plus the ancestors.
   - **If it fails:** show the problems and "run aiallow setup --reset", then exit 30 without
     changing anything.
   - **If it passes:** update. Copy `-SourceWriter` to `<folder>\grant-writer.ps1.new`, set its
     security explicitly, then `File.Replace` it over the old writer. Leave `grants.jsonl`
     untouched.
5. **If the folder doesn't exist:** a fresh install.
   - Build a `DirectorySecurity` from the SDDL
     `O:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)` and call
     `[System.IO.Directory]::CreateDirectory($folder, $security)`.
   - Create an empty `grants.jsonl` and copy the writer. Set the security of both files
     explicitly (I8).
6. Verify: run the administrative integrity check on everything. Exit 0 if it passes, 30 if
   not.

### Phase 6 tests

Windows only, and **never against the real `ProgramData` store** (A19, PLAN-004):

- the no-cmdlet AST check, run with `-LibraryPath` set to the writer (PLAN-012);
- the scope check: no shared parameter names and no shared function names between setup and
  the writer, found by parsing both;
- **library-only loading:** a test script dot-sources the writer with `-LibraryOnly`, then
  checks that `Invoke-Main` and `Test-SecurityDescriptor` are defined, and that no action ran
  (nothing printed, exit code 0);
- **decision logic through `-PlanOnly`:** every row of the decision table, plus backup names
  when `cc-ai-review.old-<ts>` and `cc-ai-review.old-<ts>-2` already exist;
- **plan-only touches nothing (PLAN-013):** while the test itself holds the mutex, run
  plan-only with a `-SourceWriter` that doesn't exist and a `-ProgramData` that doesn't exist.
  It must still succeed with the right plan. That proves it took no mutex, loaded no library
  and inspected nothing.

Real install, partial-failure, update and reset behavior is checked **only** in the
disposable-VM release checks (section 10.3), with the before and after state recorded.

---

## 9. Phase 7 — `aiallow.py` and `aiallow.cmd`

### 9.1 Structure

An `argparse` CLI with subcommands `add`, `list`, `history [--since 7d]`,
`revoke (NAME | --all)`, `edit`, `setup [--reset]` and `check`. Exit with the writer's code
where one applies.

All process launching goes through **one** function so the tests can replace it:

```python
def run_elevated(script: str, args: List[str]) -> int:
    """Launch System32 PowerShell elevated via ShellExecuteExW and wait for it.

    Returns the child's exit code, or 11 if the user declined the UAC prompt
    (ERROR_CANCELLED = 1223).
    """
```

How to implement it:

- Fill a `SHELLEXECUTEINFOW` structure with these fields:
  - `fMask = SEE_MASK_NOCLOSEPROCESS (0x40)`;
  - `lpVerb = "runas"`;
  - `lpFile = <GetSystemDirectoryW()>\WindowsPowerShell\v1.0\powershell.exe`;
  - `lpParameters = '-NoProfile -ExecutionPolicy Bypass -Sta -WindowStyle Hidden -File "<script>" ' + args`;
  - `nShow = 1`.
- Then `WaitForSingleObject(hProcess, INFINITE)`, `GetExitCodeProcess` and `CloseHandle`.
- **Quoting:** refuse any argument containing `"`. Wrap every path in double quotes. SIDs and
  names already match strict regexes.

### 9.2 Commands

- **`add`, `revoke`, `edit`:**
  1. Load the config. If exceptions are disabled, warn that the hook will ignore grants until
     `exceptions.enabled` is `true`, then continue.
  2. Run `check_store(grants_path, writer_path=<folder>\grant-writer.ps1)`, the unelevated
     pre-UAC check. If it reports problems, print them and **stop. Don't fall back to setup.**
  3. Call `run_elevated(writer, ["-Action", action, "-ForUser", current_user_sid(), "-GrantsPath", path, ...])`.
  4. Map the exit code to a message (section 7.2).
  5. After a successful `add`, re-read the file with `validate_file_bytes` and print this
     user's newest grant using `scope_summary`.
- **`setup [--reset]`:**
  - exempt from the pre-UAC writer check;
  - **refuses if `grants_path` is not the default store path** (A16). It explains that custom
    stores are set up by hand, as in the README "advanced" section, and suggests `aiallow
    check` for verifying one;
  - `run_elevated(<hook dir>\setup-grants.ps1, ["-SourceWriter", <hook dir>\grant-writer.ps1, "-ProgramData", <known folder>] + ["-Reset"]?)`;
  - then run `check` unelevated and print the result.
- **`check`:** print each problem from `check_store` (folder, file, writer, ancestors), or
  `Protected.` Exit 0 if protected, 30 otherwise.
- **`list`:** read and validate the grants file, then print this user's active grants: name,
  commands (shown with Python's `repr()` so invisible characters show up), scope, and time left.
- **`history [--since]`:** list grant and revoke lines with their timestamps. If
  `policy.log_path` is set, also read that log for lines with `source == "grant"`, take the
  grant ID from the `exception-grant-id:` flag, and show a usage count per grant.

### 9.3 `aiallow.cmd`

Written by `install.ps1`:

```bat
@"<resolved python.exe>" "%~dp0aiallow.py" %*
```

### Phase 7 tests (`tests/test_aiallow.py`)

Monkeypatch `run_elevated`, `check_store` and `current_user_sid`. Test that:

- each subcommand calls the right script with the right arguments;
- a pre-UAC check failure stops before `run_elevated`, and for `add` it never calls setup;
- `setup` skips the pre-UAC writer check;
- exit codes map to messages;
- `list` and `history` give the right output for fixture files;
- an argument containing a quote is refused.

---

## 10. Phase 8 — Install, docs, manual release checks

### 10.1 Installers

- **`install.ps1`:**
  - add `aiallow.py` and `setup-grants.ps1` to the copied list. `exception_grants.py` was
    already added in Phase 4 (section 6.5);
  - copy `grant-writer\grant-writer.ps1` into the hook folder as the setup source;
  - write `aiallow.cmd` with the resolved interpreter;
  - print: `Optional: exception grants. Run '<hookDir>\aiallow.cmd setup' (UAC prompt), then set exceptions.enabled: true.`;
  - **never elevate on its own.**
- **`install.sh`:** already copies `exception_grants.py` (since Phase 4). Print "Exception grants
  are Windows-only in this version."

### 10.2 Docs

- **README section "Exception grants":**
  - the workflow, as four steps;
  - the request format, linking to the design table;
  - "run `aiallow` in a separate terminal";
  - limits: exact text only; `where` limits only the starting folder; UAC must be on (not
    "Never notify"); the AI tool must not run elevated; `shell` hosts can't tell Bash from
    PowerShell.
- **`SECURITY.md`:** a paragraph restating the guardrail threat model for grants, the
  installer exception, and the accepted check-then-read gap.

### 10.3 Manual release checks

Run the ten manual checks in design section 11 on a real Windows machine, and record the
results in the pull request. **These are release requirements.** Do them in a disposable
Windows user profile or VM when testing `--reset` and the broken-writer cases.

---

## 11. Risks and how to handle them

| # | Risk | What to do |
|---|---|---|
| R1 | `GetNamedSecurityInfoW` ctypes signatures are wrong on 64-bit, giving garbage or crashes. | Declare every `argtypes` and `restype`. Test against `System32\drivers\etc\hosts` first. |
| R2 | Elevated admins' new files are owned by the user, so integrity fails after a write. | Rule I8: always set the owner explicitly. Phase 6/7 manual checks cover it. |
| R3 | `JsonReaderWriterFactory` accepts some JSON that Python rejects, or the reverse. | A shared fixture will show it. **Stop and report.** The planned fallback is a small hand-written recursive-descent parser in the writer, following RFC 8259. Don't change Python's rules to match. **Confirmed on 2026-11-19, before the writer was started:** the reader accepts `NaN`, `Infinity`, trailing commas, empty input and two top-level values. A trailing comma leaves the node stream byte-for-byte identical to the same JSON without it, and two top-level values merge into one object, so no post-parse check can detect them. Awaiting the user's decision on the fallback. |
| R4 | `File.Replace` behaves unexpectedly, e.g. losing the DACL or failing with antivirus file locks. | The re-read logic (exit 50/51/52) reports the truth. Record what you saw in the PR. |
| R5 | Windows CI runners are elevated, so "must fail unelevated" tests can't run there. | Skip those when `is_elevated()` is true. They are part of the manual checklist. |
| R6 | The help line makes reasons longer for every deny/ask while enabled. | Accepted. It is only shown when exceptions are enabled. |
| R7 | A `ProgramData` path with an unusual ACL on some machine fails the ancestor check. | `aiallow check` names the exact parent folder and right. Document it in the README troubleshooting section. Don't loosen the rule. |

---

## 12. Order of work, summarized

1. **Phase 1:** config.
2. **Phase 2:** fixtures plus pure logic.
3. **Phase 3:** Windows integrity and identity.
4. **Phase 4:** hook integration, **plus** adding `exception_grants.py` to both installers and
   the installer-coverage test. (Grants can now be hand-planted in tests, end to end.)
5. **Phase 5:** writer.
6. **Phase 6:** setup.
7. **Phase 7:** `aiallow`.
8. **Phase 8:** install, docs and manual release checks.

Each phase is one pull request with its tests. **Each merged phase must install and run with
exceptions disabled.** Don't merge a phase that changes the existing test suite's
expectations, except for the `render_reason` additions in Phase 4, which must leave current
output unchanged when `extra_lines` is empty.

---

## 13. Plan review findings and where they are fixed

| Finding | Fix | Where |
|---|---|---|
| PLAN-001 Phase 4 breaks installs | Installers updated in the same phase as the import. Installer-coverage test, plus a run of the copied files. | 0.1, A17, 6.5, 10.1, 12 |
| PLAN-002 Case-insensitive keys in PowerShell | Ordinal `OrderedDictionary`, `$d['key']` access, ordinal schema-key sets. Fixtures for `name`/`Name`. | D17, 7.3 (1, 2), 2.2 |
| PLAN-003 Unbounded diff | LCS only up to 1,000,000 cells, otherwise show all lines removed and added. `validate-diff` tests. | D20, 7.4 |
| PLAN-004 Test touching real ProgramData | Removed. `Get-SetupPlan` / `-PlanOnly` decision tests. Real checks in the VM only. | A19, Phase 6 tests |
| PLAN-005 ACL parity | Both sides parse the raw binary descriptor. Shared hex ACL fixtures and a `validate-acl` action. Ancestors fail on NULL DACLs and unusual entry types. | I5, I9, 2.1, 4.1, 4.2, 7.3 (9) |
| PLAN-006 False-like config sections | Only absent or null mean defaults. `section=` passed. Drive-letter check. | 5.1 |
| PLAN-007 Undeclared design departures | Amendments listed (0.2a) and applied to the design doc. A non-Windows `cwd` gives an empty `cwd` plus a note, not `any`. `cwd` cleaned. Help lines make no "always valid" promise. | 0.2a, D4, 3.9 |
| PLAN-008 Custom store setup | Set up by hand. `aiallow setup` refuses a custom path. | A16, 9.2 |
| PLAN-009 `Set-StrictMode` and the regex check | Removed. AST-based check with self-tests. No `& $scriptblock`. | A18, 7.1, Phase 5 tests |
| Fixture determinism | Placeholders for temp folders and repos. Records compared without `id`/`ts`/`user_display`, which get their own checks. | 2.1 |
| Re-read returning different bytes | Exit 52 (outcome unknown), with the mutex held. | 7.3 (11) |
| Code points vs UTF-16 units | Code points on both sides, with boundary fixtures. | D18, 7.3 (2), 2.2 |
| SID validity | One regex plus numeric limits, shared. Constructor not used. | D19, 3.1, 7.3 (2) |
| Test paths and the cwd change | Absolute paths anchored to `REPO`. | 0.1, Phase 5 tests |
| `removeprefix` wording | Corrected. | 0.1 |
| PLAN-010 Diff test expected the wrong branch | 5,000 × 10 expects `lcs`. Exact-limit and just-over cases added. `[long]` product. | D20, Phase 5 tests |
| PLAN-011 Portable vs real-path fixtures | `request` cases are text-only with fixed Windows paths, on every OS. `conversion` cases are Windows-only with placeholders. The writer reports the two layers separately. | 2.1, 7.4, Phase 5 tests |
| PLAN-012 AST check vs imported helpers | The check also reads the writer's definitions for setup. Exactly one allowed import shape. Scope collision rules and test. `-LibraryOnly` return placement. | 7.4, Phase 5 tests, 8, Phase 6 tests |
| PLAN-013 Setup plan interface | `-Plan*` parameters, the `Get-SetupPlan` decision table, plan-only dispatched first, and a test proving it touches nothing. | 8, Phase 6 tests |

---

## 14. Implementation checkpoints

From the second plan review. These are checks for whoever reviews the code, not design changes.

- **Descriptor parsing:** containment inside the ACL and each ACE, not just the outer buffer
  (4.1). The nested-size fixtures (2.1) must report `malformed` on both sides.
- **PowerShell function results:** discard incidental method output with `[void]`. Arrays
  must come back as arrays for zero, one and many elements: return them with the unary comma
  (`return ,$list`), because PowerShell otherwise unrolls them. A writer test round-trips
  `[]`, `["a"]` and `["a","b"]` through the writer's own parser and serializer.
- **Descriptions:** output must not depend on the machine's time zone, language settings or
  account-name lookup, except in the parts the design requires to be local: the "Until" time
  is shown in local time (design 6.4) and the "For user" line shows the account name. Format
  with the invariant culture. Golden-file tests replace those two values with fixed markers
  before comparing, and check them separately: the local time must equal the record's UTC
  expiry converted with `ToLocalTime()`, and the account name must equal the record's
  `user_display`.
- **Library-only mode:** loading the writer must never run an action, and the writer's `-Now`
  stays ignored by write actions (7.1 rule 5).
- **Python and writer agreement:** keep the shared fixtures passing before considering the R3
  fallback parser. A disagreement is fixed in the code that is wrong, never by relaxing
  either side's rules.
- **Release evidence:** successful protected writes, permissions after replacement,
  elevation, mutex contention and reset are proven only by the disposable-VM checks (10.3).
  Unit and validate-only tests don't replace them.

---

## 15. Implementation notes (phases 1-8)

Where the build departed from or refined this plan, so a reviewer can check each one.

| Topic | What was done | Why |
|---|---|---|
| R3 / D16 | The writer uses a hand-written JSON parser (user-approved). | The .NET reader accepted inputs Python rejects. |
| D21-D24, I4a | Added during implementation (section 1). | Parity gaps found while writing the fixtures. |
| SID structure | A SID inside a security descriptor may have 0-15 sub-authorities (`S-1-5` is valid). Fixture `sid-zero-subauthorities` now expects `write-right`. D19's stricter rule still applies to user SIDs in grant files. | Windows and .NET's `RawSecurityDescriptor` accept 0; the first Python parser wrongly called it malformed. |
| Phase 4 tests | In new files `test_grant_review.py` and `test_grant_adapters.py`; the adapter round trip replaces the store check in a test-only wrapper script. | Keeps the existing tests untouched; a temp store can never pass the real check. |
| Result messages | `Show-Result` prints instead of showing a message box when stdout or stderr is redirected. | Automated tests would otherwise hang. It only changes how a result is shown; confirmations always use a dialog, and the UAC launch never redirects output. |
| Bulk fixtures | `tests/ps/writer-harness.ps1` loads the writer as a library and runs its validate functions for every fixture in one PowerShell process. The real `validate-*` entry points are tested separately. | One process per fixture took minutes. |
| Dialog callbacks | Event handlers call named functions directly; no `& $scriptblock` and no `GetNewClosure`. | Rule A18. |
| Extra writer action | `validate-roundtrip` (read-only) for the JSON array-shape checkpoint. | Section 14. |
| Generators | `tests/fixtures/grants/make_fixtures.py` regenerates the grant fixtures; description goldens are reviewed writer output. | Fixtures stay reproducible. |
| `aiallow` quoting | Values are quoted; parameter names stay bare; a value ending in `\` is refused. | A trailing backslash would escape the closing quote. |
| Approved scope (review CODE-003) | `add` converts the request once. The dialog shows that candidate, an expiry change only replaces its `expires` (same scope, ID and time), and the approved candidate is what gets written. The repo root is never looked up again. Test: `tests/ps/add-scope-probe.ps1`. | Re-converting after Approve could pick a different repo root than the one shown. |
| Setup result (review CODE-004) | `aiallow setup` returns the elevated step's code if it failed, otherwise the final check's code; "Setup complete." only when both pass. | A failing final check used to exit 0. |
| Not done | Manual release checks (design section 11, plan 10.3) and the `! aiallow` test in Claude Code. | They need a real UAC prompt and a disposable machine. |
