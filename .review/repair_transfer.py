"""Restore the independently verified local Git bundle after text transfer damage.

This is transport-only. Both the input and repaired output are SHA-256 pinned;
no candidate source, test, or expected candidate revision is changed.
"""
import base64
import hashlib
from pathlib import Path

path = Path(__file__).with_name("response-candidate.bundle")
original = path.read_bytes()
expected = "5a666af7b2efffa84bd89223eccd4feb5a64cef812b8ebf49b6fd6705b76f53c"
actual = hashlib.sha256(original).hexdigest()
if actual != expected:
    if actual != "5bf8d2e165a3c5a708ec400085716ba995d7ec41d554044ad1d3eada967b8b9f":
        raise SystemExit("Unexpected source-transport bytes; refusing repair")
    text = base64.b64encode(original).decode("ascii")
    edits = [(618,619,""),(620,620,"o"),(3780,3781,"1"),(5548,5548,"/"),
             (5549,5550,""),(5678,5678,"1"),(11462,11463,""),(11482,11483,""),
             (11487,11488,""),(11541,11542,""),(11685,11687,""),(14755,14756,"9"),
             (14866,14867,"0"),(15284,15284,"X")]
    for start, end, replacement in reversed(edits):
        text = text[:start] + replacement + text[end:]
    repaired = base64.b64decode(text, validate=True)
    if hashlib.sha256(repaired).hexdigest() != expected:
        raise SystemExit("Repaired transport does not match the verified candidate bundle")
    path.write_bytes(repaired)
print("Source transport verified:", expected)
