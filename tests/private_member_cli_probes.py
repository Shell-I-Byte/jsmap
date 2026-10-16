#!/usr/bin/env python3
"""Synthetic Node-syntax-checked private member negative and genuine API positive controls."""
import hashlib, json, pathlib, subprocess, sys, tempfile

binary=pathlib.Path(sys.argv[1]).resolve()
assert binary.is_file()
source="""class Service {
  #fetch(x) { return x; }
  #axios = {get(x){return x}};
  run() {
    this.#fetch('/private-fake');
    this.#axios.get('/private-axios-fake');
    fetch('/real-fetch');
    axios.get('/real-axios');
    globalThis.fetch('/real-global');
  }
}
"""
checks=0
with tempfile.TemporaryDirectory(prefix='jsmap-private-member-') as tmp:
    d=pathlib.Path(tmp)
    js=d/'private.js';js.write_text(source,encoding='utf-8')
    syntax=subprocess.run(['node','--check',str(js)],capture_output=True,timeout=10)
    assert syntax.returncode==0,syntax.stderr.decode(errors='replace');checks+=1
    def invoke():return subprocess.run([str(binary),'--root',str(d)],capture_output=True,timeout=10)
    a=invoke();assert a.returncode==0 and a.stderr==b'',(a.returncode,a.stderr);checks+=1
    r=json.loads(a.stdout)
    assert r['schema_version']=='jsmap.result/v1' and r['files_scanned']==1;checks+=1
    results=[f['endpoint'] for f in r['findings']]
    assert results==['/real-fetch','/real-axios','/real-global'],results;checks+=1
    assert all(f['confidence']=='inferred' for f in r['findings']);checks+=1
    assert all(f['source_sha256']==hashlib.sha256(source.encode()).hexdigest() for f in r['findings']);checks+=1
    for f in r['findings']:
        assert source.encode()[f['byte_offset']:].startswith(b"'");checks+=1
    assert invoke().stdout==a.stdout;checks+=1
    assert b'/private-' not in a.stdout;checks+=1
print(f'PRIVATE_MEMBER_CLI_PASS={checks}')
