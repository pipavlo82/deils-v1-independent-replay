"""Verify exact public evidence inventory; offline, no writes."""
import hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
expected={}
for line in (ROOT/'SHA256SUMS').read_text(encoding='utf8').splitlines():
 digest,name=line.split('  ',1)
 if name in expected:raise RuntimeError('Duplicate manifest entry')
 path=(ROOT/name).resolve()
 if not path.is_relative_to(ROOT):raise RuntimeError('Unsafe manifest path')
 expected[name]=digest
actual={p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}
if actual!=set(expected)|{'SHA256SUMS'}:raise RuntimeError('Unlisted/missing file')
for name,digest in expected.items():
 if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest:raise RuntimeError('Digest mismatch: '+name)
print(f'{len(expected)}/{len(expected)} SHA-256 entries valid; exact inventory verified; no network requests')
