#!/usr/bin/env python3
"""Synthetic, offline, independent end-to-end JSMap control-head regression.

Run with an existing executable path. This test never reads other project trees.
"""
from __future__ import annotations
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

binary = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else None
if not binary or not binary.is_file():
    print("Usage: python3 tests/control_regex_cli_probes.py PATH_TO_JSMAP_BINARY", file=sys.stderr)
    sys.exit(2)

cases = {
 "if": "let yes=true; if (yes) /fetch(\"https:\\x2f\\x2fphantom.test\\x2fif\")/.test('x'); fetch('/real');",
 "nested_if": "let yes=true; if ((yes)) /axios.get(\"https:\\x2f\\x2fphantom.test\\x2fnested\")/.test('x'); fetch('/real');",
 "while": "while(false) /fetch(\"https:\\x2f\\x2fphantom.test\\x2fwhile\")/.test('x'); fetch('/real');",
 "for": "for(;false;) /fetch(\"https:\\x2f\\x2fphantom.test\\x2ffor\")/.test('x'); fetch('/real');",
 "with": "with ({yes:true}) /axios.post(\"https:\\x2f\\x2fphantom.test\\x2fwith\")/.test('x'); fetch('/real');",
 "else": "if(false) {} else /fetch(\"https:\\x2f\\x2fphantom.test\\x2felse\")/.test('x'); fetch('/real');",
 "do": "do /fetch(\"https:\\x2f\\x2fphantom.test\\x2fdo\")/.test('x'); while(false); fetch('/real');",
 "division": "let x=10; if(true) x = x / 2; fetch('/real');",
 "normal_regex": "const p=/fetch(\"https:\\x2f\\x2fphantom.test\\x2fnormal\")/; fetch('/real');",
 "normal_fetch": "if(true) fetch('/real');",
}
checks = 0
node_checks = 0

def check(v: bool, detail: str):
    global checks
    if not v:
        raise AssertionError(f"FAIL {detail}")
    checks += 1
    print(f"PASS {checks:02d}: {detail}")

with tempfile.TemporaryDirectory(prefix="jsmap-run117-") as t:
    base = pathlib.Path(t)
    for name, content in cases.items():
        folder = base / name
        folder.mkdir()
        source = folder / "source.js"
        source.write_text(content, encoding="utf-8")
        if shutil.which("node"):
            proc = subprocess.run(["node", "--check", str(source)], capture_output=True, timeout=15)
            check(proc.returncode == 0, name + " valid ECMAScript under Node.js")
            node_checks += 1
        result = subprocess.run([str(binary), "--root", str(folder)], capture_output=True, timeout=15)
        check(result.returncode == 0 and not result.stderr, name + " CLI success")
        doc = json.loads(result.stdout)
        check(doc["schema_version"] == "jsmap.result/v1" and doc["scope"] == "local-files-only", name + " schema and scope")
        check(doc["files_scanned"] == 1 and [f["endpoint"] for f in doc["findings"]] == ["/real"], name + " only real endpoint")
        finding = doc["findings"][0]
        check(finding["confidence"] == "inferred" and finding["source_sha256"] == hashlib.sha256(content.encode()).hexdigest(), name + " hash and inference")
        check(finding["byte_offset"] == content.encode().rindex(b"'/real'"), name + " byte provenance")
        rerun = subprocess.run([str(binary), "--root", str(folder)], capture_output=True, timeout=15)
        check(rerun.returncode == 0 and result.stdout == rerun.stdout, name + " deterministic replay")
        check(b"phantom.test" not in result.stdout, name + " no regex-only false finding")
    print(f"CONTROL_REGEX_ACCEPTANCE_PASS={checks} NODE_ORACLE_EXECUTED={node_checks}")
