"""Reconstruct the reviewed candidate plus the bounded browser/documentation correction."""
from pathlib import Path
import hashlib
import subprocess
import sys
import tempfile

repo = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
here = Path(__file__).resolve().parent
CANDIDATE = 'a564a9cf1a909ec6c89f78ee0d3ff54b30cdf288'
TREE = '7ae76f5a8e784e0de2b7b853f7a2b14d23a4bedc'

def git(*args, data=None):
    return subprocess.run(['git', *args], cwd=repo, input=data, capture_output=True, check=True).stdout.decode().strip()

with tempfile.TemporaryDirectory(prefix='qwr-base-candidate-') as temp:
    subprocess.run([sys.executable, str(here / 'prepare_candidate.py'), str(repo), str(Path(temp) / 'base')], check=True)
assert git('rev-parse', 'HEAD') == '448cf1a3bfc45bb80343d66ef498258603fb4054'
patch = (here / 'followup.patch').read_bytes()
assert hashlib.sha256(patch).hexdigest() == 'd79ed6e0bb36b19fc9e0177175cd2a4d8757cc42a67a06ae8c38dd3a0a23ef25'
git('apply', '--check', '--index', '-', data=patch)
git('apply', '--index', '--whitespace=error', '-', data=patch)
assert git('write-tree') == TREE
raw = (here / 'followup-commit.txt').read_bytes()
assert git('hash-object', '-t', 'commit', '-w', '--stdin', data=raw) == CANDIDATE
# Isolated staging tree already matched exactly; materialize that tested commit.
git('reset', '--hard', CANDIDATE)
assert not git('status', '--porcelain')
out.mkdir(parents=True, exist_ok=False)
git('bundle', 'create', str(out / 'candidate.bundle'), 'HEAD')
git('bundle', 'verify', str(out / 'candidate.bundle'))
(out / 'candidate-sha.txt').write_text(CANDIDATE + '\n', encoding='utf-8')
print('Exact follow-up candidate reconstructed:', CANDIDATE, TREE)
