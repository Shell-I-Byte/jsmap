#!/usr/bin/env python3
"""Independent end-to-end, local-only CLI checks; each assert counts as a real probe."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
checks = 0
skipped = 0

def check(condition, label):
    global checks
    if not condition:
        raise AssertionError(f"PROBE FAIL: {label}")
    checks += 1
    print(f"PASS {checks:02}: {label}")

with tempfile.TemporaryDirectory(prefix="jsmap-independent-") as temp:
    tmp = pathlib.Path(temp)
    binary = tmp / ("jsmap.exe" if os.name == "nt" else "jsmap")
    subprocess.run(["go", "build", "-o", str(binary), "./cmd/jsmap"], cwd=ROOT, check=True)

    def invoke(*args):
        return subprocess.run([str(binary), *map(str, args)], cwd=ROOT, capture_output=True, timeout=20)

    path = tmp / "input"
    path.mkdir()
    a = path / "a.js"
    body = b"fetch('/api/v1?apikey=INVISIBLE#part'); axios.post('https://admin:TOPSECRET@example.test/login?token=DO-NOT-LEAK'); fetch('/partial/' + dynamic); // fetch('/comment')\n"
    a.write_bytes(body)
    (path / "not-a-js.txt").write_text("fetch('/not-included')", encoding="utf8")
    b = path / "b.mjs"
    b.write_text('axios.get("https://[::1]:443/a"); fetch("../relative");', encoding="utf8")
    (path / "c.cjs").write_text('fetch("/c");', encoding="utf8")

    proc = invoke("--root", path)
    check(proc.returncode == 0, "normal CLI success exitcode")
    check(proc.stderr == b"", "normal CLI has no stderr")
    report = json.loads(proc.stdout)
    check(report["schema_version"] == "jsmap.result/v1", "schema contract")
    check(report["scope"] == "local-files-only", "local-only scope")
    check(report["tool_version"] == "v0.1.0-rc12", "version stable")
    check(report["files_scanned"] == 3, "extension filtering")
    findings = report["findings"]
    check(len(findings) == 5, "positive, negative and dynamic filtering")
    check([x["path"] for x in findings] == ["a.js", "a.js", "b.mjs", "b.mjs", "c.cjs"], "deterministic path ordering")
    check(findings[0]["source_sha256"] == hashlib.sha256(body).hexdigest(), "source provenance digest")
    check(findings[0]["byte_offset"] == body.index(b"'/api/v1"), "UTF-8 byte-offset evidence")
    check(findings[0]["endpoint"] == "/api/v1", "query and fragment removed")
    check(findings[0]["query_redacted"] is True, "query redaction flag")
    check(findings[1]["userinfo_redacted"] is True, "userinfo redaction flag")
    check(findings[1]["endpoint"] == "https://example.test/login", "userinfo and query removal")
    check(b"INVISIBLE" not in proc.stdout and b"TOPSECRET" not in proc.stdout and b"DO-NOT-LEAK" not in proc.stdout, "no sensitive query/userinfo in stdout")
    check(all(x["confidence"] == "inferred" for x in findings), "no fabricated confirmation")
    check(b"/partial/" not in proc.stdout and b"/comment" not in proc.stdout, "omit dynamic and comments")
    check(invoke("--root", path).stdout == proc.stdout, "exact JSON replay determinism")
    check(b"/input/" not in proc.stdout and str(path).encode() not in proc.stdout, "no absolute source root in JSON")
    check(findings[2]["endpoint"] == "https://[::1]:443/a", "IPv6 URL")

    no_root = invoke()
    check(no_root.returncode == 2, "required root exitcode")
    check(no_root.stdout == b"", "invalid arguments do not emit partial JSON")
    control = invoke("--evil\nFORGED-LOG\x1b[31m")
    check(control.returncode == 2 and b"FORGED-LOG" not in control.stderr and b"\x1b" not in control.stderr, "CLI-log injection denied")
    invalid = invoke("--root", tmp / "missing\nFORGED")
    check(invalid.returncode == 3 and b"FORGED" not in invalid.stderr, "filesystem-error log injection denied")
    check(invoke("--version").stdout.strip() == b"v0.1.0-rc12", "version CLI")

    (path / "bad.js").write_bytes(b"\xff\xfe")
    invalid_utf8 = invoke("--root", path)
    check(invalid_utf8.returncode == 3 and not invalid_utf8.stdout, "invalid UTF-8 fail-closed")
    (path / "bad.js").unlink()
    (path / "bad.js").write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    oversized = invoke("--root", path)
    check(oversized.returncode == 3 and not oversized.stdout, "oversized file fail-closed")
    (path / "bad.js").unlink()

    src = tmp / "external.js"
    src.write_text("fetch('/external-not-authorized')", encoding="utf8")
    link = path / "skip.js"
    try:
        link.symlink_to(src)
    except OSError:
        skipped += 1
        print("SKIP: symlink controls unavailable on this platform")
    else:
        symlinked = invoke("--root", path)
        check(symlinked.returncode == 0, "symlink target is not an error")
        check(b"external-not-authorized" not in symlinked.stdout, "symlink escape ignored")
        check(json.loads(symlinked.stdout)["files_scanned"] == 3, "symlink excluded from scan count")
        link.unlink()
        rootlink = tmp / "rootlink"
        rootlink.symlink_to(path, target_is_directory=True)
        check(invoke("--root", rootlink).returncode == 3, "symlink root rejected")

    empty = tmp / "empty"
    empty.mkdir()
    blank = invoke("--root", empty)
    check(blank.returncode == 0 and json.loads(blank.stdout)["findings"] == [], "empty result stable []")

    # A regex literal must not invent a network endpoint. A real fetch still counts.
    regex_dir = tmp / "regex"
    regex_dir.mkdir()
    (regex_dir / "regex.js").write_text(r'''const re = /fetch("https:\x2f\x2fexample.test\x2fphantom")/;
const re2 = /[\/]axios.get("https:\x2f\x2fexample.test\x2ffake")/;
fetch('/real');''', encoding="utf8")
    regex_proc = invoke("--root", regex_dir)
    check(regex_proc.returncode == 0, "regex/control local scan succeeds")
    regex_findings = json.loads(regex_proc.stdout)["findings"]
    check(len(regex_findings) == 1 and regex_findings[0]["endpoint"] == "/real", "regex candidates never fabricated as endpoint evidence")
    for help_flag in ("-h", "-help", "--help"):
        h = invoke(help_flag)
        check(h.returncode == 0 and b"Usage: jsmap" in h.stdout and not h.stderr, "safe successful help " + help_flag)

    # Unicode ID_Start/ID_Continue characters are part of identifier names.
    # πfetch, ℘fetch and πaxios are distinct names from fetch and axios.
    unicode_dir = tmp / "unicode"
    unicode_dir.mkdir()
    unicode_source = "const πfetch = u=>u; πfetch('/bogus'); const ℘fetch = u=>u; ℘fetch('/bogus2'); const πaxios = {get:u=>u}; πaxios.get('/bogus3'); const π\u200cfetch = u=>u; π\u200cfetch('/bogus4'); fetch('/real'); axios.get('/real2');"
    (unicode_dir / "unicode.js").write_text(unicode_source, encoding="utf8")
    unicode_proc = invoke("--root", unicode_dir)
    check(unicode_proc.returncode == 0 and unicode_proc.stderr == b"", "Unicode identifiers scan normally")
    unicode_report = json.loads(unicode_proc.stdout)
    check([x["endpoint"] for x in unicode_report["findings"]] == ["/real", "/real2"], "Unicode-prefixed names cannot invent findings")
    first = unicode_report["findings"][0]
    check(first["byte_offset"] == unicode_source.encode("utf8").index(b"'/real'"), "UTF-8 byte offset preserved after Unicode identifiers")
    check(all(x["confidence"] == "inferred" for x in unicode_report["findings"]), "inference semantics unchanged")

    print(f"INDEPENDENT_CLI_PASS={checks} SKIPPED={skipped}")
