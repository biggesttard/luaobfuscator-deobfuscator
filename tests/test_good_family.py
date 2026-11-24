"""Optional check against a real Chaotic Good script.

The repository does not ship the sample (it is user supplied); the test runs whenever
``sample/sample.lua`` is present in the checkout.
"""

import os

import pytest

from deobf import deobf, OUT_HDR

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(ROOT, 'sample', 'sample.lua')

pytestmark = pytest.mark.skipif(not os.path.isfile(SAMPLE),
                                reason='sample/sample.lua not present')


def test_real_chaotic_good_script():
    with open(SAMPLE, encoding='utf-8', errors='replace') as fh:
        source = fh.read()

    result = deobf(source)

    assert result['detection']['family'] == 'luaobfuscator-chaotic-good'
    assert result['detection']['version'] == '0.10.9'
    assert result['lua'].startswith(OUT_HDR)
    assert 'math.ldexp' not in result['lua']
    assert len(result['lua'].splitlines()) > 400
    # the XOR bootstrap is reconstructed into plain Lua
    assert 'function(v42,v43)' in result['lua']
