"""Reconstruct the exact locally tested candidate; this script never publishes it."""
from pathlib import Path
import hashlib
import lzma
import subprocess
import sys

FEATURE = '972bac1be241f2701d362b6a2e471423f66f8517'
MAIN = '1383bee124b11d09cee27f0226d51b4329c26fde'
INTEGRATED = 'dc35b64b2cd791cca84215890bfc6c9d5822587d'
TREE = 'd572ba9d26ee314a0a41e8e7744d87f6411fffb3'
CANDIDATE = '448cf1a3bfc45bb80343d66ef498258603fb4054'
COMPRESSED = 'bd266d0c41fa59c8c0a9b882e5fea1c1c8aba588002c922298506e70baaa3ee1'
PATCH = '4688e7e2f64d68dd2c6a2174e96330571ab1251ad62868241899c4db50b6c16e'
repo = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
here = Path(__file__).resolve().parent

def git(*args, check=True, data=None):
    result = subprocess.run(['git', *args], cwd=repo, input=data, capture_output=True, check=check)
    return result.stdout.decode().strip()

assert git('rev-parse', 'HEAD') == FEATURE
assert not git('status', '--porcelain')
subprocess.run(['git', '-c', 'user.name=Qualification', '-c', 'user.email=qualification@users.noreply.github.com',
                'merge', '--no-commit', '--no-ff', MAIN], cwd=repo, check=False)
conflicts = set(git('diff', '--name-only', '--diff-filter=U').splitlines())
assert conflicts == {'backend/tests/test_private_state_writes.py', 'scripts/verify_frontend_browser.py'}, conflicts
# These main versions preserve the feature code and add the reviewed symlink and browser regressions.
for path in sorted(conflicts):
    git('checkout', '--theirs', '--', path)
    git('add', '--', path)
assert git('write-tree') == INTEGRATED
compressed = b''.join((here / f'recovery-patch.part{i}').read_bytes() for i in range(5))
assert hashlib.sha256(compressed).hexdigest() == COMPRESSED
patch = lzma.decompress(compressed)
assert len(patch) == 134598 and hashlib.sha256(patch).hexdigest() == PATCH
git('apply', '--check', '--index', '-', data=patch)
git('apply', '--index', '--whitespace=error', '-', data=patch)
assert git('write-tree') == TREE
raw = (here / 'candidate-commit.txt').read_bytes()
assert git('hash-object', '-t', 'commit', '-w', '--stdin', data=raw) == CANDIDATE
# This is an isolated checkout; its staged tree has just been matched exactly.
git('reset', '--hard', CANDIDATE)
assert not git('status', '--porcelain')
out.mkdir(parents=True, exist_ok=False)
git('bundle', 'create', str(out / 'candidate.bundle'), 'HEAD')
git('bundle', 'verify', str(out / 'candidate.bundle'))
(out / 'candidate-sha.txt').write_text(CANDIDATE + '\n', encoding='utf-8')
print('Exact candidate and source tree reconstructed:', CANDIDATE, TREE)
