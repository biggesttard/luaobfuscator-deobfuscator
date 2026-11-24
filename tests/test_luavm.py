from deobf import luavm as vm


def test_dispatch_discovery_matches_reference(spec, golden):
    result = vm.an_vm(spec['vmSource'])
    want = golden['anVm']

    dispatch = result['dispatch']
    assert dispatch is not None
    assert {k: dispatch[k] for k in ('instVar', 'codeVar', 'pcVar', 'opVar',
                                     'fetchIndex', 'start', 'end')} == want['dispatch']

    assert result['ctx'] == want['ctx']
    assert result['closureLocalOp'] == want['closureLocalOp']
    assert result['opcodeCount'] == want['opcodeCount']
    assert {str(k): v for k, v in result['opcodeMap'].items()} == want['opcodeMap']
    assert result['nameToOpcodes'] == want['nameToOpcodes']


def test_classifies_common_handlers(spec):
    result = vm.an_vm(spec['vmSource'])
    names = [v['name'] for v in result['opcodeMap'].values()]
    assert 'CONCAT' in names
    assert 'NEWTABLE' in names


def test_missing_dispatch_is_reported():
    result = vm.an_vm('print("nothing here")')
    assert result['dispatch'] is None
    assert result['opcodeCount'] == 0
    assert result['opcodeMap'] == {}


def test_guess_op_for_skipped_instruction():
    from deobf.luaio import Instr

    assert vm.guess_op(Instr(skipped=True)) == 'UNKNOWN'
