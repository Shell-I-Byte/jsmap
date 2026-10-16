#!/usr/bin/env python3
"""Offline JS property-callee negative controls for the release CLI."""
from __future__ import annotations
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

binary = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None
if not binary or not binary.is_file():
    raise SystemExit('usage: property_calls_cli_probes.py /absolute/path/to/jsmap')

source = '''const obj = { fetch(v){return v}, axios:{get(v){return v}} };
obj.fetch('/fake-obj');
obj.axios.get('/fake-axios');
const data = { window:{fetch(v){return v}, axios:{get(v){return v}}} };
data.window.fetch('/fake-nested');
data.window.axios.get('/fake-nested-axios');
obj?.fetch('/fake-optional');
window.fetch('/window-real');
globalThis.fetch('/global-real');
self.fetch('/self-real');
fetch('/bare-real');
window.axios.get('/window-axios');
axios.get('/axios-real');
'''
want=['/window-real','/global-real','/self-real','/bare-real','/window-axios','/axios-real']
checks=0
with tempfile.TemporaryDirectory(prefix='jsmap-property-negative-') as tmp:
    root=pathlib.Path(tmp)
    (root/'property.js').write_text(source,encoding='utf8')
    syntax=subprocess.run(['node','--check',str(root/'property.js')],capture_output=True,timeout=8)
    assert syntax.returncode==0,syntax.stderr.decode(errors='replace');checks+=1
    def invoke():return subprocess.run([str(binary),'--root',str(root)],capture_output=True,timeout=8)
    p=invoke();assert p.returncode==0 and p.stderr==b'',(p.returncode,p.stderr);checks+=1
    report=json.loads(p.stdout);assert report['schema_version']=='jsmap.result/v1';checks+=1
    actual=[f['endpoint'] for f in report['findings']]
    assert actual==want,('false or missing candidate',actual,want);checks+=1
    digest=hashlib.sha256(source.encode('utf8')).hexdigest()
    for item in report['findings']:
        assert item['source_sha256']==digest;checks+=1
        assert item['confidence']=='inferred' and item['call'] in ['fetch','axios.get'];checks+=1
        assert source.encode('utf8')[item['byte_offset']:].startswith(b"'");checks+=1
    assert invoke().stdout==p.stdout;checks+=1
    assert all(b'/fake-' not in p.stdout for _ in [0]);checks+=1
print(f'PROPERTY_CALLEE_CLI_PASS={checks}')
