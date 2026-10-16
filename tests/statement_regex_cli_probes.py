#!/usr/bin/env python3
"""Offline Node v22 syntax-oracle and JSMap CLI false-evidence regression."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

if len(sys.argv) != 2:
    sys.exit("usage: python3 tests/statement_regex_cli_probes.py ABSOLUTE_EXECUTABLE")
exe = pathlib.Path(sys.argv[1]).resolve()
if not exe.is_file():
    sys.exit("executable missing")

cases = {
 "function_declaration": '''function f() {} /fetch("\\x2fphantom")/.test("x"); fetch('/real');''',
 "function_after_semicolon": '''const n=2; function f(x){return x;} /axios.get("\\x2fphantom")/.test("x"); fetch('/real');''',
 "async_function_declaration": '''async function f(){} /fetch("\\x2fphantom")/.test("x"); fetch('/real');''',
 "class_declaration": '''class Foo {} /fetch("\\x2fphantom")/.test("x"); fetch('/real');''',
 "switch_block": '''switch(1){case 1:break;} /fetch("\\x2fphantom")/.test("x"); fetch('/real');''',
 "catch_parameter_block": '''try {} catch(err) {} /fetch("\\x2fphantom")/.test("x"); fetch('/real');''',
 "function_expression_division": '''const ratio = function f() {return 10;} / fetch('/real');''',
 "class_expression_division": '''const ratio = class Foo {} / fetch('/real');''',
 "object_division": '''const ratio = ({x:1}) / fetch('/real');''',
 "arrow_division": '''const ratio = (()=>{return 10}) / fetch('/real');''',
}
count=0; nodecount=0
with tempfile.TemporaryDirectory(prefix="jsmap-statement-regex-") as td:
 for name, src in cases.items():
    root=pathlib.Path(td)/name
    root.mkdir()
    path=root/'input.js'
    path.write_text(src,encoding='utf8')
    if shutil.which('node'):
        n=subprocess.run(['node','--check',str(path)],capture_output=True,timeout=10)
        assert n.returncode==0,(name,n.stderr)
        nodecount+=1;count+=1
    r=subprocess.run([str(exe),'--root',str(root)],capture_output=True,timeout=10)
    assert r.returncode==0 and not r.stderr,(name,r.returncode,r.stderr);count+=1
    report=json.loads(r.stdout)
    assert report['schema_version']=='jsmap.result/v1' and report['files_scanned']==1,name;count+=1
    assert len(report['findings'])==1 and report['findings'][0]['endpoint']=='/real',(name,report['findings']);count+=1
    f=report['findings'][0]
    assert f['confidence']=='inferred' and f['source_sha256']==hashlib.sha256(src.encode()).hexdigest(),name;count+=1
    assert f['byte_offset']==src.encode().index(b"'/real'"),name;count+=1
    r2=subprocess.run([str(exe),'--root',str(root)],capture_output=True,timeout=10)
    assert r2.returncode==0 and r2.stdout==r.stdout,name;count+=1
    assert b'phantom' not in r.stdout,name;count+=1
print(f'STATEMENT_REGEX_ACCEPTANCE_PASS={count} NODE_SYNTAX_CASES={nodecount}')
