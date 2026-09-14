#!/usr/bin/env python3
"""Collect candidate Python 3.12 Strands wheels for local tests and ARM64 Runtime.

Runs pip download only. Does not access AWS APIs or alter installed packages.
Upload the resulting ZIP to the implementation conversation for offline tests.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct
import subprocess
import sys
import tempfile
from zipfile import ZipFile, ZIP_DEFLATED

REQUIREMENTS = ['strands-agents==1.51.0', 'boto3==1.43.89', 'botocore==1.43.89', 'rfc8785==0.1.4']
TARGETS = {'x86_64': 62, 'aarch64': 183}


def inspect_wheels(directory, architecture):
    wheels = sorted(Path(directory).glob('*.whl'))
    if not wheels:
        raise ValueError('No wheels downloaded for ' + architecture)
    records = []
    for wheel in wheels:
        with ZipFile(wheel) as archive:
            if archive.testzip() is not None:
                raise ValueError('Corrupt dependency wheel: ' + wheel.name)
            for item in archive.infolist():
                path = PurePosixPath(item.filename)
                if path.is_absolute() or '..' in path.parts or '\\' in item.filename:
                    raise ValueError('Unsafe wheel member')
                if item.filename.endswith('.so'):
                    raw = archive.read(item)
                    if len(raw) < 20 or raw[:4] != b'\x7fELF' or raw[4:6] != b'\x02\x01' or struct.unpack('<H', raw[18:20])[0] != TARGETS[architecture]:
                        raise ValueError('Wrong native architecture: ' + wheel.name)
        records.append({'file':wheel.name, 'size':wheel.stat().st_size, 'sha256':hashlib.sha256(wheel.read_bytes()).hexdigest()})
    if not any(r['file'].startswith('strands_agents-1.51.0-') for r in records):
        raise ValueError('Pinned Strands wheel is missing')
    return records


def collect(destination, run=subprocess.run):
    destination = Path(destination).expanduser().resolve()
    if destination.exists():
        raise ValueError('Output already exists. Keep it or choose a different --output path.')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='authority-delta-dependencies-') as work:
        work = Path(work)
        manifest = {'schema_version':'1.0', 'scope':'CANDIDATE_DEPENDENCIES_NOT_GATE_B_PROOF',
            'requirements':REQUIREMENTS, 'python_target':'3.12', 'wheels':{}}
        for arch in TARGETS:
            target = work / arch; target.mkdir()
            command = [sys.executable, '-m', 'pip', '--isolated', '--disable-pip-version-check', 'download',
                '--index-url', 'https://pypi.org/simple', '--only-binary=:all:', '--python-version','3.12',
                '--implementation','cp', '--abi','cp312', '--platform','manylinux2014_' + arch,
                '--platform','manylinux_2_28_' + arch, '--dest',str(target), '--timeout','20', '--retries','1', *REQUIREMENTS]
            print('Download and verify Python 3.12 dependencies: ' + arch, flush=True)
            result = run(command, capture_output=True, text=True, timeout=600)
            if result.returncode:
                raise RuntimeError('Dependency download failed for ' + arch + ':\n' + (result.stderr or result.stdout)[-5000:])
            manifest['wheels'][arch] = inspect_wheels(target, arch)
        (work / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        pending = destination.with_suffix('.pending.zip')
        try:
            with ZipFile(pending,'w',compression=ZIP_DEFLATED) as archive:
                for path in sorted(work.rglob('*')):
                    if path.is_file():archive.write(path, path.relative_to(work).as_posix())
            with ZipFile(pending) as archive:
                if archive.testzip() is not None:raise ValueError('Output ZIP failed integrity check')
            pending.replace(destination)
        finally:
            pending.unlink(missing_ok=True)
    print('DEPENDENCIES_READY (not Gate B PASS)',flush=True)
    print('Upload this file to the conversation: ' + str(destination),flush=True)
    print('SHA256: ' + hashlib.sha256(destination.read_bytes()).hexdigest(),flush=True)
    return destination


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default=str(Path.home() / 'Authority_Delta_Analysis_Dependencies.zip'))
    args=parser.parse_args()
    try:collect(args.output)
    except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as exc:
        print('ERROR: '+str(exc),file=sys.stderr);return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
