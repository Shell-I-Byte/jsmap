#!/usr/bin/env python3
"""Run only offline synthetic JSMap block-terminator RegExp evidence probes."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

if len(sys.argv) != 2:
    sys.exit('usage: python3 tests/block_regex_cli_probes.py EXECUTABLE')
exe = pathlib.Path(sys.argv[1]).resolve()
if not exe.is_file():
    sys.exit('executable missing')

cases = {
    'if_block': '''if(true) {} /fetch("\\x2fphantom")/.test('x'); fetch('/real');''',
    'nested_if_block': '''if(true) {if(true){}} /axios.get("\\x2fphantom")/.test('x'); fetch('/real');''',
    'while_block': '''while(false) {} /fetch("\\x2fphantom")/.test('x'); fetch('/real');''',
    'for_block': '''for(;false;) {} /fetch("\\x2fphantom")/.test('x'); fetch('/real');''',
    'else_block': '''if(false) {} else {} /fetch("\\x2fphantom")/.test('x'); fetch('/real');''',
    'finally_block': '''try {} finally {} /fetch("\\x2fphantom")/.test('x'); fetch('/real');''',
    'object_division': '''const ratio = {value:10} / fetch('/real');''',
    'arrow_division': '''const ratio = (()=>{return 10}) / fetch('/real');''',
}
checks = 0
node_checks = 0

def check(value, desc):
    global checks
    if not value:
        raise AssertionError(desc)
    checks += 1

with tempfile.TemporaryDirectory(prefix='jsmap-block-regex-') as t:
    for name, code in cases.items():
        root = pathlib.Path(t) / name
        root.mkdir()
        src = root / 'source.js'
        src.write_text(code, encoding='utf-8')
        if shutil.which('node'):
            node = subprocess.run(['node', '--check', str(src)], capture_output=True, timeout=10)
            check(node.returncode == 0, f'{name} Node syntax: {node.stderr!r}')
            node_checks += 1
        proc = subprocess.run([str(exe), '--root', str(root)], capture_output=True, timeout=10)
        check(proc.returncode == 0 and not proc.stderr, f'{name} CLI: {proc.returncode} {proc.stderr}')
        report = json.loads(proc.stdout)
        check(report['schema_version'] == 'jsmap.result/v1' and report['files_scanned'] == 1, f'{name} contract')
        items = report['findings']
        check(len(items) == 1 and items[0]['endpoint'] == '/real', f'{name} no phantom: {items!r}')
        check(items[0]['confidence'] == 'inferred' and items[0]['source_sha256'] == hashlib.sha256(code.encode()).hexdigest(), f'{name} provenance')
        check(items[0]['byte_offset'] == code.encode().rindex(b"'/real'"), f'{name} byte offset')
        other = subprocess.run([str(exe), '--root', str(root)], capture_output=True, timeout=10)
        check(other.returncode == 0 and other.stdout == proc.stdout, f'{name} deterministic')
        check(b'phantom' not in proc.stdout, f'{name} redacted phantom')
print(f'BLOCK_REGEX_ACCEPTANCE_PASS={checks} NODE_ORACLE_EXECUTED={node_checks}')
