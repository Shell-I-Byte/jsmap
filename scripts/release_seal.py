#!/usr/bin/env python3
"""Reproduce the deterministic JSMap RC source ZIP from a sealed source tree.

Does not generate or modify source manifests: the checked-in manifest is a
release commitment; changes require a reviewed, new release candidate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSION_DIR = 'JSMap_v0.1.0-rc12_Run204'
MANIFEST = ROOT / 'SOURCE_MANIFEST_SHA256.json'

def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, help='Destination directory outside source tree')
    args = parser.parse_args()
    dest = pathlib.Path(args.out).resolve()
    if dest == ROOT or ROOT in dest.parents:
        parser.error('Output must be outside the source directory')
    report = json.loads(MANIFEST.read_text(encoding='utf8'))
    if report['format'] != 'jsmap.source-manifest/v1' or report['tree'] != VERSION_DIR:
        raise ValueError('Unexpected release manifest contract')
    files = report['files']
    listed = {r['path'] for r in files}
    actual = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*')
              if p.is_file() and '.git' not in p.relative_to(ROOT).parts
              and p.name != 'SOURCE_MANIFEST_SHA256.json'}
    if actual != listed:
        raise ValueError('Source tree does not match sealed manifest filenames')
    for r in files:
        rel = pathlib.PurePosixPath(r['path'])
        if rel.is_absolute() or '..' in rel.parts or len(rel.parts) == 0:
            raise ValueError('Unsafe release manifest path')
        target = ROOT.joinpath(*rel.parts)
        if not target.is_file() or target.is_symlink() or target.stat().st_size != r['size'] or digest(target) != r['sha256']:
            raise ValueError('Source hash mismatch: ' + str(rel))
    dest.mkdir(parents=True, exist_ok=True)
    zip_path = dest / (VERSION_DIR + '_source.zip')
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for rel_text in sorted([*listed, 'SOURCE_MANIFEST_SHA256.json']):
            contents = (ROOT / rel_text).read_bytes()
            info = zipfile.ZipInfo(VERSION_DIR + '/' + rel_text, date_time=(2026, 10, 15, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            z.writestr(info, contents, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    with zipfile.ZipFile(zip_path) as z:
        for r in files:
            if hashlib.sha256(z.read(VERSION_DIR + '/' + r['path'])).hexdigest() != r['sha256']:
                raise ValueError('ZIP source hash mismatch')
    print('PASS sealed source file count:', len(files))
    print('PASS deterministic ZIP:', zip_path)
    print('ZIP_SHA256:', digest(zip_path))
    return 0

if __name__ == '__main__':
    sys.exit(main())
