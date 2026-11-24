from helpers import mk_proto, opcode_map
from deobf import luaout as out


def test_disassembly_matches_reference(spec, golden):
    proto = mk_proto(spec['root'])
    assert out.disasm_pr(proto, opcode_map(spec), spec['closureLocalOp']) == golden['disasm']


def test_lift_matches_reference(spec, golden):
    proto = mk_proto(spec['root'])
    assert out.lift_prog(proto, opcode_map(spec), spec['closureLocalOp']) == golden['lifted']


def test_reconstruction_matches_reference(spec, golden):
    proto = mk_proto(spec['root'])
    assert out.recon_prog(proto, opcode_map(spec), spec['closureLocalOp']) == golden['reconstructed']


def test_cfg_stats_match_reference(spec, golden):
    proto = mk_proto(spec['root'])
    assert out.sum_cfg(proto, opcode_map(spec), spec['closureLocalOp']) == golden['cfg']


def test_clean_cfg_keeps_empty_list():
    assert out.clean_cfg([]) == []


def test_step_emits_no_output_for_jmp():
    ops = [{'index': 1, 'name': 'FORLOOP', 'A': 0, 'B': 3, 'C': None, 'mode': 0}]
    res = out.step(ops[0], ops, 0, {}, set(), 0, [], {}, [])
    assert res['lines'] == []
