#!/usr/bin/env python3
"""Independent local CLI proof that ECMAScript Annex B comments are not evidence."""
import json, os, pathlib, subprocess, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
checks = 0
with tempfile.TemporaryDirectory(prefix="jsmap-html-comments-") as scratch:
    work = pathlib.Path(scratch)
    binary = work / ("jsmap.exe" if os.name == "nt" else "jsmap")
    subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-o", str(binary), "./cmd/jsmap"], cwd=ROOT, check=True)
    cases = {
        "opening": "<!-- fetch('/fake-open');\nfetch('/real');\n",
        "opening-inline": "const a = 1; <!-- fetch('/fake-inline');\nfetch('/real');\n",
        "closing": "--> fetch('/fake-close');\nfetch('/real');\n",
        "closing-indented": "\t--> fetch('/fake-indented');\nfetch('/real');\n",
        "ordinary-line": "// fetch('/fake-control');\nfetch('/real');\n",
        "ordinary-tokens": "let a = 3; a-- > fetch('/real');\n",
    }
    for case, source in cases.items():
        folder = work / case
        folder.mkdir()
        (folder / "demo.cjs").write_text(source, encoding="utf8")
        proc = subprocess.run([str(binary), "--root", str(folder)], capture_output=True, timeout=10)
        if proc.returncode != 0 or proc.stderr:
            raise AssertionError(f"{case}: CLI failure code={proc.returncode}")
        findings = json.loads(proc.stdout)["findings"]
        if [finding["endpoint"] for finding in findings] != ["/real"]:
            raise AssertionError(f"{case}: false evidence {findings}")
        if findings[0]["confidence"] != "inferred":
            raise AssertionError("confirmation was fabricated")
        checks += 1
        print(f"PASS {case}: only /real (inferred)")
    print(f"HTML_COMMENT_CLI_PASS={checks}")
