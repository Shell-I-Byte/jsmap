#!/usr/bin/env python3
"""Locally swap synthetic regular js file and FIFO to falsify TOCTOU open; no network."""
import ctypes, json, os, pathlib, subprocess, sys, tempfile, threading, time
from collections import Counter
libc = ctypes.CDLL(None, use_errno=True)
AT_FDCWD=-100
RENAME_EXCHANGE=2

def main():
    binary = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv)>2 else 100
    timeout = float(sys.argv[3]) if len(sys.argv)>3 else 0.5
    results=Counter()
    with tempfile.TemporaryDirectory(prefix="jsmap-swap-fifo-") as tmp:
        root=pathlib.Path(tmp)
        regular=root/'a.js'
        other=root/'swap'  # file extension deliberately not scanned
        regular.write_text("fetch('/synthetic-safe')\n")
        os.mkfifo(other)
        stop=threading.Event()
        errors=[]
        def flip():
            while not stop.is_set():
                if libc.renameat2(AT_FDCWD,os.fsencode(regular),AT_FDCWD,os.fsencode(other),RENAME_EXCHANGE)!=0:
                    errors.append(ctypes.get_errno());stop.set();break
        worker=threading.Thread(target=flip,daemon=True)
        worker.start()
        for _ in range(count):
            try:
                r=subprocess.run([binary,'--root',str(root)],capture_output=True,timeout=timeout)
                if r.returncode==0:
                    try:
                        result=json.loads(r.stdout)
                        if (result.get('files_scanned')==1 and len(result.get('findings',[]))==1) or (result.get('files_scanned')==0 and result.get('findings')==[]):
                            results['PASS_NORMAL']+=1
                        else: results['FAIL_UNEXPECTED_JSON']+=1
                    except Exception: results['FAIL_MALFORMED_OUTPUT']+=1
                elif r.returncode==3 and not r.stdout and b'fetch(' not in r.stderr:
                    results['PASS_REJECT']+=1
                else: results['FAIL_UNEXPECTED_EXIT']+=1
            except subprocess.TimeoutExpired:
                results['HANG_TIMEOUT']+=1
            if errors: break
        stop.set();worker.join(timeout=2)
        print(json.dumps({'binary':binary,'attempts':sum(results.values()),'timeout_s':timeout,'result':dict(results),'swapper_errors':errors},sort_keys=True))
        if errors: return 2
        if results['HANG_TIMEOUT'] or any(x.startswith('FAIL') for x in results):return 1
        return 0
if __name__=='__main__': sys.exit(main())
