import pytest

from deobf import deobf, DeobfError, OUT_HDR


def test_pipeline_matches_reference(sample_source, sample_golden):
    result = deobf(sample_source)

    assert result['detection']['family'] == sample_golden['detection']['family']
    assert result['lua'] == sample_golden['lua']
    assert result['disasm'] == sample_golden['disasm']

    vm_info = result['vm']
    want = sample_golden['vm']
    assert vm_info['opcodeCount'] == want['opcodeCount']
    assert vm_info['closureLocalOp'] == want['closureLocalOp']
    assert vm_info['usedMap'] == want['usedMap']
    assert vm_info['nameToOpcodes'] == want['nameToOpcodes']


def test_output_carries_header(sample_source):
    result = deobf(sample_source)
    assert result['lua'].startswith(OUT_HDR)


def test_rejects_unrelated_input():
    with pytest.raises(DeobfError) as exc:
        deobf('print("hello")')
    assert str(exc.value).startswith('det:')
    assert exc.value.detection['matched'] is False


def test_force_option_passes_detection():
    with pytest.raises(Exception):
        deobf('print("hello")', {'force': True})


def test_log_callback_reports_stages(sample_source):
    import io as _io

    stream = _io.StringIO()
    deobf(sample_source, {'log': True, 'log_stream': stream})
    log = stream.getvalue()
    for stage in ('[det]', '[cff]', '[bc]', '[str]', '[vm]', '[recon]'):
        assert stage in log
