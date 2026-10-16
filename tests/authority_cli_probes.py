#!/usr/bin/env python3
"""Independent offline black-box HTTP authority vs real JavaScript URL validity."""
import json, pathlib, subprocess, sys, tempfile, hashlib
exe = pathlib.Path(sys.argv[1]).resolve()
src = '''fetch("https://[example.test]/fake-dns?token=SECRET")
fetch("http://[127.0.0.1]/fake-ipv4")
fetch("https://[v1.fe80]/fake-future")
fetch("https://[::1%25eth0]/fake-zone")
fetch("//[example.test]/fake-relative")
fetch("https://[::1]:8443/real-v6?token=HIDDEN")
axios.get("https://example.test/real-dns")
fetch("/static/[example.test]/valid-path")
'''
with tempfile.TemporaryDirectory() as td:
    root=pathlib.Path(td); (root/'case.js').write_text(src, encoding='utf8')
    r=subprocess.run([str(exe),'--root',str(root)],capture_output=True,text=True,timeout=15)
    assert r.returncode==0 and r.stderr=='', (r.returncode,r.stderr)
    doc=json.loads(r.stdout)
    assert doc['schema_version']=='jsmap.result/v1' and doc['files_scanned']==1, doc
    got=[f['endpoint'] for f in doc['findings']]
    want=['https://[::1]:8443/real-v6','https://example.test/real-dns','/static/[example.test]/valid-path']
    assert got==want, ('false endpoint evidence',got,'wanted',want)
    digest=hashlib.sha256(src.encode()).hexdigest()
    for f in doc['findings']:
        assert f['source_sha256']==digest and f['confidence']=='inferred', f
        assert src.encode()[f['byte_offset']:f['byte_offset']+1]==b'"', f
    assert doc['findings'][0]['query_redacted']
    assert 'SECRET' not in r.stdout and 'HIDDEN' not in r.stdout and 'fake' not in r.stdout
    r2=subprocess.run([str(exe),'--root',str(root)],capture_output=True,text=True,timeout=15)
    assert r2.returncode==0 and r.stdout==r2.stdout, 'JSON nondeterministic'
    print('PASS JSMap invalid authority black-box negatives+positives+redaction+provenance+determinism')
