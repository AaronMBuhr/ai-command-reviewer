"""Regenerate tests/fixtures/grants (cases.json, requests/, files/). Run by hand.

Writes raw bytes, so the fixtures are byte-exact on every OS. It overwrites
files but never deletes them: when you rename or remove a case, delete
requests/ and files/ first. descriptions/*.txt are golden outputs of the
writer, not generated here; update them only after reviewing the new text.

Usage:  python tests/fixtures/grants/make_fixtures.py
"""
# ruff: noqa: E501  -- one fixture per line reads better than wrapped data.
import json
import sys
from pathlib import Path

if len(sys.argv) < 2:
    sys.argv.append(str(Path(__file__).resolve().parent))

ROOT = Path(sys.argv[1])
NOW = "2026-11-19T18:00:00Z"
USER = "S-1-5-21-1-2-3-1001"
OTHER = "S-1-5-21-1-2-3-1002"

cases = []


def dump(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def request(case_id, body, valid, code=None, field=None, raw=False):
    rel = f"requests/{case_id[4:]}.json"
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    data = body if isinstance(body, bytes) else (body if raw else dump(body)).encode("utf-8", "surrogatepass")
    path.write_bytes(data)
    entry = {"id": case_id, "kind": "request", "path": rel, "valid": valid,
             "now": NOW, "for_user": USER}
    if not valid:
        entry["code"] = code
        entry["field"] = field
    cases.append(entry)


def base(**changes):
    obj = {"v": 1, "name": "push-x", "commands": ["git push"], "tool": "Bash",
           "where": "dir", "cwd": "C:\\cc-fixture\\work", "hosts": None,
           "expires": "30m", "why": ""}
    for key, value in changes.items():
        if value is DROP:
            obj.pop(key, None)
        else:
            obj[key] = value
    return obj


DROP = object()

# ---- requests: valid
request("req-valid-minimal", base(where="any", cwd=DROP), True)
request("req-valid-full", base(hosts=["claude", "codex"], expires="2h",
                               why="The rebase rewrote history."), True)
request("req-valid-repo", base(where="repo", cwd="D:/src/proj"), True)
request("req-valid-any-null-cwd", base(where="any", cwd=None), True)
request("req-expires-never", base(expires="never"), True)
request("req-expires-iso-offset", base(expires="2026-11-20T10:00:00+02:00"), True)
request("req-expires-iso-z", base(expires="2026-11-20T10:00:00Z"), True)
request("req-command-emoji", base(commands=["echo \U0001F600"]), True)
request("req-command-tab-crlf", base(commands=["a\tb\r\nc"]), True)
request("req-command-8000", base(commands=["a" * 8000]), True)
request("req-command-8000-emoji", base(commands=["\U0001F600" * 8000]), True)
request("req-why-1000-emoji", base(why="\U0001F600" * 1000), True)
request("req-twenty-commands", base(commands=[f"echo {i}" for i in range(20)]), True)
request("req-tool-empty", base(tool=""), True)
request("req-tool-40", base(tool="t" * 40), True)
request("req-name-40", base(name="a" * 40), True)
request("req-all-hosts", base(hosts=["claude", "codex", "cursor", "windsurf", "devin",
                                     "antigravity"]), True)
request("req-key-order-free", b'{"why":"","expires":"30m","hosts":null,"cwd":"C:\\\\x",'
        b'"where":"dir","tool":"Bash","commands":["ls"],"name":"n","v":1}', True)

# ---- requests: invalid expiry
request("req-expires-iso-nozone", base(expires="2026-11-20T10:00:00"), False, "bad-value", "expires")
request("req-expires-past", base(expires="2026-11-19T17:00:00Z"), False, "expired", "expires")
request("req-expires-equal-now", base(expires=NOW), False, "expired", "expires")
request("req-expires-fraction", base(expires="2026-11-20T10:00:00.5Z"), False, "bad-value", "expires")
request("req-expires-month-13", base(expires="2026-13-20T10:00:00Z"), False, "bad-value", "expires")
request("req-expires-offset-24", base(expires="2026-11-20T10:00:00+24:00"), False, "bad-value", "expires")
request("req-expires-zero-duration", base(expires="0m"), False, "bad-value", "expires")
request("req-expires-long-duration", base(expires="10000m"), False, "bad-value", "expires")
request("req-expires-number", base(expires=30), False, "bad-type", "expires")
request("req-expires-null", base(expires=None), False, "bad-type", "expires")
request("req-expires-unicode-digit", base(expires="\u0663m"), False, "bad-value", "expires")

# ---- requests: commands
request("req-empty-commands", base(commands=[]), False, "bad-value", "commands")
request("req-commands-string", base(commands="git push"), False, "bad-type", "commands")
request("req-empty-command", base(commands=[""]), False, "bad-value", "commands")
request("req-whitespace-command", base(commands=["  \t"]), False, "bad-value", "commands")
request("req-x1c-command", base(commands=["\x1c\x1f"]), False, "bad-value", "commands")
request("req-nbsp-command", base(commands=["\u00a0\u3000"]), False, "bad-value", "commands")
request("req-duplicate-commands", base(commands=["ls", "ls"]), False, "bad-value", "commands")
request("req-21-commands", base(commands=[f"echo {i}" for i in range(21)]), False,
        "bad-value", "commands")
request("req-command-8001", base(commands=["a" * 8001]), False, "bad-value", "commands")
request("req-command-8001-emoji", base(commands=["\U0001F600" * 8001]), False,
        "bad-value", "commands")
request("req-command-nul", base(commands=["a\x00b"]), False, "bad-value", "commands")
request("req-command-lone-surrogate",
        b'{"v":1,"name":"push-x","commands":["a\\ud800b"],"tool":"Bash","where":"any",'
        b'"hosts":null,"expires":"30m","why":""}', False, "bad-value", "commands")
request("req-command-number", base(commands=["ls", 5]), False, "bad-type", "commands")
request("req-command-case-distinct", base(commands=["ls", "LS"]), True)

# ---- requests: cwd and where
request("req-cwd-with-any", base(where="any", cwd="C:\\x"), False, "bad-value", "cwd")
request("req-cwd-missing-dir", base(cwd=DROP), False, "missing-field", "cwd")
request("req-cwd-null-dir", base(cwd=None), False, "bad-type", "cwd")
request("req-cwd-relative", base(cwd="work"), False, "bad-value", "cwd")
request("req-cwd-unc", base(cwd="\\\\server\\share"), False, "bad-value", "cwd")
request("req-cwd-rooted", base(cwd="\\work"), False, "bad-value", "cwd")
request("req-cwd-posix", base(cwd="/e/Source"), False, "bad-value", "cwd")
request("req-cwd-dotdot", base(cwd="C:\\a\\..\\b"), False, "bad-value", "cwd")
request("req-cwd-dot", base(cwd="C:/a/./b"), False, "bad-value", "cwd")
request("req-cwd-empty", base(cwd=""), False, "bad-value", "cwd")
request("req-where-bad", base(where="folder"), False, "bad-value", "where")
request("req-where-case", base(where="Dir"), False, "bad-value", "where")

# ---- requests: hosts
request("req-hosts-empty", base(hosts=[]), False, "bad-value", "hosts")
request("req-hosts-unknown", base(hosts=["vim"]), False, "bad-value", "hosts")
request("req-hosts-dup", base(hosts=["codex", "codex"]), False, "bad-value", "hosts")
request("req-hosts-case", base(hosts=["Codex"]), False, "bad-value", "hosts")
request("req-hosts-string", base(hosts="codex"), False, "bad-type", "hosts")

# ---- requests: v
request("req-v-true", base(v=True), False, "bad-type", "v")
request("req-v-float", b'{"v":1.0,"name":"push-x","commands":["ls"],"tool":"Bash","where":"any",'
        b'"hosts":null,"expires":"30m","why":""}', False, "bad-type", "v")
request("req-v-exponent", b'{"v":1e0,"name":"push-x","commands":["ls"],"tool":"Bash",'
        b'"where":"any","hosts":null,"expires":"30m","why":""}', False, "bad-type", "v")
request("req-v-2", base(v=2), False, "bad-value", "v")
request("req-v-minus-zero", b'{"v":-0,"name":"push-x","commands":["ls"],"tool":"Bash",'
        b'"where":"any","hosts":null,"expires":"30m","why":""}', False, "bad-value", "v")
request("req-v-huge", ('{"v":1' + "0" * 120 + ',"name":"push-x","commands":["ls"],"tool":"Bash",'
                       '"where":"any","hosts":null,"expires":"30m","why":""}').encode(),
        False, "bad-value", "v")
request("req-v-string", base(v="1"), False, "bad-type", "v")

# ---- requests: keys
request("req-unknown-field", {**base(), "extra": 1}, False, "unknown-field", "extra")
request("req-missing-why", base(why=DROP), False, "missing-field", "why")
request("req-missing-v", base(v=DROP), False, "missing-field", "v")
request("req-duplicate-key", b'{"v":1,"name":"a","name":"b","commands":["ls"],"tool":"Bash",'
        b'"where":"any","hosts":null,"expires":"30m","why":""}', False, "duplicate-key", "name")
request("req-duplicate-key-escaped", b'{"v":1,"name":"a","na\\u006de":"b","commands":["ls"],'
        b'"tool":"Bash","where":"any","hosts":null,"expires":"30m","why":""}', False,
        "duplicate-key", "name")
request("req-name-then-upper-name", b'{"v":1,"name":"a","Name":"b","commands":["ls"],"tool":"Bash",'
        b'"where":"any","hosts":null,"expires":"30m","why":""}', False, "unknown-field", "Name")
request("req-upper-name-then-name", b'{"v":1,"Name":"b","name":"a","commands":["ls"],"tool":"Bash",'
        b'"where":"any","hosts":null,"expires":"30m","why":""}', False, "unknown-field", "Name")
request("req-v-and-upper-v", b'{"v":1,"V":1,"name":"a","commands":["ls"],"tool":"Bash",'
        b'"where":"any","hosts":null,"expires":"30m","why":""}', False, "unknown-field", "V")
request("req-upper-commands", b'{"v":1,"name":"a","Commands":["ls"],"tool":"Bash",'
        b'"where":"any","hosts":null,"expires":"30m","why":""}', False, "unknown-field", "Commands")
request("req-nested-duplicate-first", b'{"v":1,"v":{"a":1,"a":2},"name":"a","commands":["ls"],'
        b'"tool":"Bash","where":"any","hosts":null,"expires":"30m","why":""}', False,
        "duplicate-key", "a")

# ---- requests: name, tool, why
request("req-name-upper", base(name="Push"), False, "bad-value", "name")
request("req-name-41", base(name="a" * 41), False, "bad-value", "name")
request("req-name-trailing-newline", base(name="push\n"), False, "bad-value", "name")
request("req-name-leading-dash", base(name="-push"), False, "bad-value", "name")
request("req-name-number", base(name=5), False, "bad-type", "name")
request("req-tool-41", base(tool="t" * 41), False, "bad-value", "tool")
request("req-tool-null", base(tool=None), False, "bad-type", "tool")
request("req-why-1001", base(why="w" * 1001), False, "bad-value", "why")
request("req-why-1001-emoji", base(why="\U0001F600" * 1001), False, "bad-value", "why")


def escaped(obj):
    # ensure_ascii writes a lone surrogate as a \uXXXX escape (D24 fixtures).
    return json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("ascii")


request("req-why-lone-surrogate", escaped(base(why="x\udc00")), False, "bad-value", "why")
request("req-tool-lone-surrogate", escaped(base(tool="\ud800")), False, "bad-value", "tool")
request("req-cwd-lone-surrogate", escaped(base(cwd="C:\\\ud800")), False, "bad-value", "cwd")
request("req-why-surrogate-pair-escaped", escaped(base(why="\U0001F600")), True)

# ---- requests: JSON syntax and encoding
request("req-nan", b'{"v":NaN,"name":"a","commands":["ls"],"tool":"Bash","where":"any",'
        b'"hosts":null,"expires":"30m","why":""}', False, "json-syntax", None)
request("req-infinity", b'{"v":Infinity,"name":"a","commands":["ls"],"tool":"Bash",'
        b'"where":"any","hosts":null,"expires":"30m","why":""}', False, "json-syntax", None)
request("req-trailing-comma", b'{"v":1,"name":"a","commands":["ls"],"tool":"Bash",'
        b'"where":"any","hosts":null,"expires":"30m","why":"",}', False, "json-syntax", None)
request("req-duplicate-then-trailing-comma", b'{"v":1,"v":1,"name":"a","commands":["ls"],'
        b'"tool":"Bash","where":"any","hosts":null,"expires":"30m","why":"",}', False,
        "json-syntax", None)
request("req-single-quotes", b"{'v':1}", False, "json-syntax", None)
request("req-raw-tab-in-string", b'{"v":1,"name":"a","commands":["a\tb"],"tool":"Bash",'
        b'"where":"any","hosts":null,"expires":"30m","why":""}', False, "json-syntax", None)
request("req-top-array", b'[1,2]', False, "not-object", None)
request("req-top-string", b'"x"', False, "not-object", None)
request("req-empty-input", b'', False, "json-syntax", None)
request("req-two-values", b'{"v":1} {"v":1}', False, "json-syntax", None)
request("req-bom", b'\xef\xbb\xbf' + dump(base()).encode(), False, "bom", None)
request("req-invalid-utf8", b'{"v":1,"name":"\xff"}', False, "encoding", None)
request("req-deep-nesting", ('{"v":1,"name":"a","commands":["ls"],"tool":"Bash","where":"any",'
                             '"hosts":null,"expires":"30m","why":' + "[" * 65 + "]" * 65
                             + "}").encode(), False, "json-syntax", None)
request("req-depth-64", ('{"v":1,"name":"a","commands":["ls"],"tool":"Bash","where":"any",'
                         '"hosts":null,"expires":"30m","why":' + "[" * 63 + "]" * 63
                         + "}").encode(), False, "bad-type", "why")
request("req-leading-whitespace", (" \r\n\t" + dump(base()) + " \n").encode(), True)

# ---- files
grant_n = [0]


def grant(user=USER, name="push-x", **changes):
    grant_n[0] += 1
    obj = {"v": 1, "type": "grant", "id": f"g-20261119T170000Z-{grant_n[0]:08x}",
           "name": name, "ts": "2026-11-19T17:00:00Z", "user": user,
           "user_display": "PC\\user", "commands": ["git push"], "tool": "Bash",
           "where": "any", "path": None, "hosts": None, "expires": "2026-11-19T19:00:00Z",
           "why": ""}
    obj.update(changes)
    return obj


def revoke(user=USER, name="push-x", **changes):
    grant_n[0] += 1
    obj = {"v": 1, "type": "revoke", "id": f"r-20261119T171000Z-{grant_n[0]:08x}",
           "ts": "2026-11-19T17:10:00Z", "user": user, "name": name}
    obj.update(changes)
    return obj


def file_case(case_id, content, valid, code=None, field=None, line=None, active=None):
    rel = f"files/{case_id[5:]}.jsonl"
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, list):
        content = "".join(dump(o) + "\n" for o in content).encode("utf-8")
    path.write_bytes(content)
    entry = {"id": case_id, "kind": "file", "path": rel, "valid": valid, "now": NOW}
    if valid:
        entry["active"] = active or {}
    else:
        entry["code"] = code
        entry["field"] = field
        entry["line"] = line
    cases.append(entry)


g = grant()
file_case("file-empty", b"", True)
file_case("file-one-grant", [g], True, active={USER: [g["id"]]})
g1 = grant()
file_case("file-grant-then-revoke", [g1, revoke()], True)
ga, gb = grant(name="a"), grant(name="b")
file_case("file-revoke-other-name", [ga, gb, revoke(name="a")], True, active={USER: [gb["id"]]})
gc = grant(name="c")
gd = grant(name="d")
file_case("file-revoke-star-then-grant", [gc, revoke(name="*"), gd], True,
          active={USER: [gd["id"]]})
ge = grant()
file_case("file-revoke-other-user", [ge, revoke(user=OTHER)], True, active={USER: [ge["id"]]})
gf, gg = grant(), grant(user=OTHER)
file_case("file-two-users", [gf, gg], True, active={USER: [gf["id"]], OTHER: [gg["id"]]})
gh = grant(expires=None)
file_case("file-expires-null", [gh], True, active={USER: [gh["id"]]})
file_case("file-expired", [grant(expires="2026-11-19T18:00:00Z")], True)
gi = grant(where="repo", path="C:\\src\\proj", hosts=["claude"], commands=["a", "b"],
           why="\U0001F600 x\u2028y")
file_case("file-rich-grant", [gi], True, active={USER: [gi["id"]]})
gj = grant()
file_case("file-malformed-revoke-after-grant",
          [gj, {k: v for k, v in revoke().items() if k != "name"}], False,
          "missing-field", "name", 2)
gk = grant()
file_case("file-truncated-last-line", (dump(gk) + "\n" + dump(grant())[:40] + "\n").encode(),
          False, "json-syntax", None, 2)
file_case("file-missing-final-newline", dump(grant()).encode(), False, "no-final-newline")
file_case("file-blank-line", (dump(grant()) + "\n\n" + dump(grant()) + "\n").encode(), False,
          "blank-line", None, 2)
file_case("file-crlf", (dump(grant()) + "\r\n").encode(), False, "cr")
file_case("file-bom", b"\xef\xbb\xbf" + (dump(grant()) + "\n").encode(), False, "bom")
file_case("file-invalid-utf8", b'{"v":1,"type":"\xc3"}\n', False, "encoding")
dup = grant()
file_case("file-duplicate-grant-id", [dup, dup], False, "duplicate-id", "id", 2)
file_case("file-bad-sid-leading-zero", [grant(user="S-1-5-021-1")], False, "bad-value", "user", 1)
file_case("file-bad-sid-sub-too-big", [grant(user="S-1-5-21-4294967296")], False,
          "bad-value", "user", 1)
file_case("file-sid-sub-max", [grant(user="S-1-5-21-4294967295")], True,
          active={"S-1-5-21-4294967295": [f"g-20261119T170000Z-{grant_n[0]:08x}"]})
file_case("file-bad-sid-authority", [grant(user="S-1-281474976710656-1")], False,
          "bad-value", "user", 1)
file_case("file-sid-authority-max", [grant(user="S-1-281474976710655-1")], True,
          active={"S-1-281474976710655-1": [f"g-20261119T170000Z-{grant_n[0]:08x}"]})
file_case("file-bad-sid-16-subs", [grant(user="S-1-5" + "-1" * 16)], False, "bad-value",
          "user", 1)
file_case("file-sid-15-subs", [grant(user="S-1-5" + "-1" * 15)], True,
          active={"S-1-5" + "-1" * 15: [f"g-20261119T170000Z-{grant_n[0]:08x}"]})
file_case("file-missing-user-display", [{k: v for k, v in grant().items()
                                         if k != "user_display"}], False,
          "missing-field", "user_display", 1)
file_case("file-empty-user-display", [grant(user_display="")], False, "bad-value",
          "user_display", 1)
file_case("file-path-with-any", [grant(path="C:\\x")], False, "bad-value", "path", 1)
file_case("file-null-path-with-dir", [grant(where="dir")], False, "bad-value", "path", 1)
file_case("file-ts-without-z", [grant(ts="2026-11-19T17:00:00")], False, "bad-value", "ts", 1)
file_case("file-expires-offset", [grant(expires="2026-11-19T19:00:00+00:00")], False,
          "bad-value", "expires", 1)
file_case("file-type-unknown", [{**grant(), "type": "grnt"}], False, "bad-value", "type", 1)
file_case("file-type-missing", [{k: v for k, v in grant().items() if k != "type"}], False,
          "missing-field", "type", 1)
file_case("file-extra-field", [{**grant(), "note": "x"}], False, "unknown-field", "note", 1)
file_case("file-revoke-star", [grant(), revoke(name="*")], True)
file_case("file-revoke-bad-name", [revoke(name="**")], False, "bad-value", "name", 1)
file_case("file-grant-id-as-revoke", [{**revoke(), "id": "g-20261119T170000Z-00000000"}],
          False, "bad-value", "id", 1)
file_case("file-top-array", b"[]\n", False, "not-object", None, 1)
file_case("file-v-true", [grant(v=True)], False, "bad-type", "v", 1)
file_case("file-nan", (dump(grant())[:-1] + ',"x":NaN}\n').encode(), False, "json-syntax",
          None, 1)
file_case("file-user-display-lone-surrogate",
          (json.dumps(grant(user_display="PC\\\ud800"), ensure_ascii=True,
                      separators=(",", ":")) + "\n").encode("ascii"),
          False, "bad-value", "user_display", 1)
file_case("file-path-lone-surrogate",
          (json.dumps(grant(where="dir", path="C:\\\udfff"), ensure_ascii=True,
                      separators=(",", ":")) + "\n").encode("ascii"),
          False, "bad-value", "path", 1)
file_case("file-line-bom", (dump(grant()) + "\n\ufeff" + dump(grant()) + "\n").encode(), False,
          "json-syntax", None, 2)

# ---- conversions (writer only, Windows only; {TMP} and {TMP_REPO} are
# replaced with real temp folders by the test)


def conversion(case_id, body, record=None, code=None, field=None, description=False):
    rel = f"requests/{case_id}.json"
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(escaped(body))
    entry = {"id": case_id, "kind": "conversion", "path": rel, "valid": True,
             "now": NOW, "for_user": USER}
    if record is not None:
        entry["record"] = record
    else:
        entry["code"] = code
        entry["field"] = field
    if description:
        entry["description"] = f"descriptions/{case_id}.txt"
    cases.append(entry)


def expected(body, path, expires, **extra):
    record = {"v": 1, "type": "grant", "name": body["name"], "user": USER,
              "commands": body["commands"], "tool": body["tool"], "where": body["where"],
              "path": path, "hosts": body["hosts"], "expires": expires, "why": body["why"]}
    record.update(extra)
    return record


body = base(cwd="{TMP}", why="Needed for the build.")
conversion("conv-dir", body, expected(body, "{TMP}", "2026-11-19T18:30:00Z"), description=True)
body = base(where="repo", cwd="{TMP_REPO}\\sub", expires="2h", hosts=["claude", "codex"])
conversion("conv-repo-sub", body, expected(body, "{TMP_REPO}", "2026-11-19T20:00:00Z"),
           description=True)
body = base(where="any", cwd=DROP, expires="never", tool="shell",
            commands=["git push --force", " echo\tx ​"], hosts=["codex"])
conversion("conv-any-never", body, expected(body, None, None), description=True)
body = base(cwd="{TMP}", expires="2026-11-20T10:00:00+02:00")
conversion("conv-iso-offset", body, expected(body, "{TMP}", "2026-11-20T08:00:00Z"))
body = base(cwd="{TMP}", expires="1d", tool="")
conversion("conv-one-day-no-tool", body, expected(body, "{TMP}", "2026-11-20T18:00:00Z"),
           description=True)
conversion("conv-repo-without-git", base(where="repo", cwd="{TMP}"), code="bad-value",
           field="where")
conversion("conv-dir-missing", base(cwd="{TMP}\\missing"), code="bad-value", field="cwd")

(ROOT / "cases.json").write_bytes(
    (json.dumps(cases, indent=1, ensure_ascii=True) + "\n").encode("utf-8"))
print(len(cases), "cases")
