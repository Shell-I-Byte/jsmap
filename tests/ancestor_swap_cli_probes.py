#!/usr/bin/env python3
"""Linux-only offline, synthetically race a child-directory against a symlink.

Usage: python3 tests/ancestor_swap_cli_probes.py <jsmap-binary> [attempts]
Never reaches network; the outside fixture exists only under a local temp dir.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import threading


AT_FDCWD = -100
RENAME_EXCHANGE = 2
SYSCALLS = {"x86_64": 316, "aarch64": 276}


def main() -> int:
    if len(sys.argv) not in (2, 3) or sys.platform != "linux" or platform.machine() not in SYSCALLS:
        print("ERROR: Linux x86_64/aarch64 and jsmap binary required", file=sys.stderr)
        return 2
    exe = str(Path(sys.argv[1]).resolve())
    rounds = int(sys.argv[2]) if len(sys.argv) == 3 else 180
    if rounds < 2 or rounds > 1500:
        print("ERROR: rounds must be 2..1500", file=sys.stderr)
        return 2
    libc = ctypes.CDLL(None, use_errno=True)
    syscall_no = SYSCALLS[platform.machine()]
    libc.syscall.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]

    def swap(a: Path, b: Path) -> None:
        ret = libc.syscall(syscall_no, AT_FDCWD, os.fsencode(a), AT_FDCWD, os.fsencode(b), RENAME_EXCHANGE)
        if ret:
            raise OSError(ctypes.get_errno(), "renameat2(RENAME_EXCHANGE)")

    with tempfile.TemporaryDirectory(prefix="jsmap-scoped-root-") as base:
        base_path = Path(base)
        root = base_path / "scan"
        external = base_path / "external"
        root.mkdir()
        external.mkdir()
        (root / "inner").mkdir()
        (root / "inner" / "a.js").write_text("fetch('/SAFE-IN-ROOT');\n", encoding="utf8")
        outside_text = "fetch('/OUTSIDE-ROOT-READ-IS-A-BUG');\n"
        (external / "a.js").write_text(outside_text, encoding="utf8")
        external_digest = hashlib.sha256(outside_text.encode()).hexdigest()
        (root / "toggle").symlink_to(external, target_is_directory=True)

        positive = subprocess.run([exe, "--root", str(root)], capture_output=True, timeout=3)
        if positive.returncode != 0:
            print("FAIL: positive valid input", positive.stderr.decode(errors="replace"))
            return 1
        positive_json = json.loads(positive.stdout)
        if [f["endpoint"] for f in positive_json["findings"]] != ["/SAFE-IN-ROOT"]:
            print("FAIL: positive or symlink negative control", positive_json)
            return 1

        root_symlink = base_path / "root-link"
        root_symlink.symlink_to(external, target_is_directory=True)
        denied = subprocess.run([exe, "--root", str(root_symlink)], capture_output=True, timeout=3)
        if denied.returncode != 3 or denied.stdout:
            print("FAIL: symlink root accepted")
            return 1

        stop = threading.Event()
        swaps = [0]
        errors: list[str] = []
        def flip() -> None:
            try:
                while not stop.is_set():
                    swap(root / "inner", root / "toggle")
                    swaps[0] += 1
            except BaseException as exc:
                errors.append(repr(exc))
        worker = threading.Thread(target=flip, daemon=True)
        worker.start()
        counts = {"rounds": rounds, "success": 0, "safe_failures": 0, "timeouts": 0, "outside_read_findings": 0, "inside_findings": 0}
        try:
            for _ in range(rounds):
                try:
                    proc = subprocess.run([exe, "--root", str(root)], capture_output=True, timeout=3)
                except subprocess.TimeoutExpired:
                    counts["timeouts"] += 1
                    continue
                if proc.returncode != 0:
                    if proc.returncode != 3 or proc.stdout:
                        print("FAIL: unsafe error status or partial JSON")
                        return 1
                    counts["safe_failures"] += 1
                    continue
                counts["success"] += 1
                report = json.loads(proc.stdout)
                for finding in report["findings"]:
                    if finding["source_sha256"] == external_digest or "OUTSIDE-ROOT" in finding["endpoint"]:
                        counts["outside_read_findings"] += 1
                    elif finding["endpoint"] == "/SAFE-IN-ROOT":
                        counts["inside_findings"] += 1
        finally:
            stop.set()
            worker.join(timeout=5)
        counts["swaps"] = swaps[0]
        counts["swapper_errors"] = errors
        counts["baseline"] = "PASS"
        counts["result"] = "PASS" if not errors and not counts["outside_read_findings"] and not counts["timeouts"] else "FAIL"
        print(json.dumps(counts, sort_keys=True))
        return 0 if counts["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
