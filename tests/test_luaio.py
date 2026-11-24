import pytest

from deobf import luaio as io


def test_rejects_plain_lua():
    result = io.det('print("hello")\n')
    assert result['matched'] is False
    assert result['family'] is None


def test_detects_synthetic_sample(sample_source):
    result = io.det(sample_source)
    assert result['matched'] is True
    assert result['family'] == 'luaobfuscator-chaotic-evil'


def test_find_lol_prefers_decrypted_payload(sample_source):
    lol = io.find_lol(sample_source)
    assert lol['found'] is True
    assert lol['plain'] is False
    assert lol['preview'].startswith('LOL!')


def test_fold_const_matches_reference(golden):
    cases = [
        'local a = (1 + 2) * 3',
        'x = 2^10 .. "s"',
        "if (1 == 1) then v1 = 'a' end",
        '#"abcdef"',
    ]
    assert [io.fold_const(c) for c in cases] == golden['io']['foldConst']


def test_xtr_bc_matches_reference(sample_source, golden):
    bc = io.xtr_bc(sample_source)
    assert bc['sentinel'] == 79  # 'O'
    assert bc['bytesRead'] > 0
    assert bc['bytesRead'] <= bc['bytesTotal']
    assert bc['xorCalls'] >= 1
    assert isinstance(bc['root'], io.Proto)


def test_dec_lol_requires_magic():
    with pytest.raises(ValueError):
        io.dec_lol(b'NOT!1234')


def test_unflat_passthrough():
    src = 'local v1 = 1\nprint(v1)\n'
    res = io.unflat_cff(src)
    assert res['replaced'] == 0
    assert isinstance(res['source'], str)
