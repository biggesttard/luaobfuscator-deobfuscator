"""The deobfuscation pipeline: detect, decrypt, analyse and rebuild."""

from __future__ import annotations

from . import luaio as io
from . import luavm as vm
from . import luaout as out

OUT_HDR = '-- oh my days deobfuscated this obfuscator with this special deobfuscator so insane\n\n'

ANSI = {
    'reset': '\x1b[0m',
    'green': '\x1b[32m',
    'red': '\x1b[31m',
    'yellow': '\x1b[33m',
    'cyan': '\x1b[36m',
}


class DeobfError(Exception):
    """Raised when detection or reconstruction fails."""

    def __init__(self, message, detection=None):
        super().__init__(message)
        self.detection = detection


def with_hdr(code):
    text = str(code or '')
    if text.startswith('\ufeff'):
        text = text[1:]
    return OUT_HDR + text


def mk_log(enabled, stream=None):
    def log(step, status, extra=''):
        if not enabled:
            return
        col = ANSI['red']
        tag = 'fail'
        if status is True or status == 'ok':
            col = ANSI['green']
            tag = 'ok'
        elif status == 'partial' or status == 'warn':
            col = ANSI['yellow']
            tag = 'warn'
        tail = (' ' + extra) if extra else ''
        line = col + '[' + step + '] ' + tag + tail + ANSI['reset'] + '\n'
        if stream is not None:
            stream.write(line)
            if hasattr(stream, 'flush'):
                stream.flush()

    return log


def walkp(root, fn):
    if fn(root):
        return True
    for child in root.prototypes:
        if child and walkp(child, fn):
            return True
    return False


def collect_opcodes(root):
    used = set()

    def visit(p):
        for ins in p.instructions:
            if ins and not ins.skipped:
                used.add(ins.opcode)
        return False

    walkp(root, visit)
    return used


def guess_from_ins(root, op):
    state = {'guess': 'UNKNOWN'}

    def visit(p):
        for ins in p.instructions:
            if ins and not ins.skipped and ins.opcode == op:
                state['guess'] = vm.guess_op(ins)
                return True
        return False

    walkp(root, visit)
    return state['guess']


def deobf(source, options=None):
    """Deobfuscate a LuaObfuscator script and return the full result dict."""
    options = options or {}
    log = mk_log(bool(options.get('log')), options.get('log_stream'))
    src = str(source)
    detection = io.det(src)

    if not detection['matched'] and not options.get('force'):
        log('det', False, detection.get('reason') or 'reject')
        raise DeobfError('det:' + str(detection.get('reason') or 'reject'), detection)

    family = detection['family']
    if family == 'luaobfuscator-chaotic-good':
        fam = 'good'
    elif family == 'luaobfuscator-chaotic-evil':
        fam = 'evil'
    elif family == 'luaobfuscator-v1':
        fam = 'v1'
    else:
        fam = family or '?'
    log('det', True, fam)

    if family == 'luaobfuscator-chaotic-good':
        try:
            good = io.deobf_gd(src)
            log('xor', True)
            wrapper_cff = good.get('wrapperCff') or {}
            log('cff', True if wrapper_cff.get('remaining', 0) <= 1 else 'partial')
        except Exception:
            log('xor', False)
            raise
        if 'math.ldexp' in good['lua']:
            log('recon', False, 'ldexp')
            raise DeobfError('good:ldexp', detection)
        log('recon', True)
        out_str = with_hdr(good['lua'])
        return {
            'detection': detection,
            'protections': [],
            'wrapperCff': good.get('wrapperCff'),
            'bytecode': None,
            'vm': None,
            'strings': good.get('strings'),
            'cfg': None,
            'lifted': out_str,
            'reconstructed': out_str,
            'lua': out_str,
            'disasm': '',
            'rewrittenSource': good['lua'],
        }

    is_v1 = family == 'luaobfuscator-v1'

    wrapper_cff = io.unflat_cff(src)
    flat_src = wrapper_cff['source']
    log(
        'cff',
        (True if wrapper_cff['remaining'] <= 1 else 'partial') if wrapper_cff['replaced'] > 0 else 'warn',
        'rep=' + str(wrapper_cff['replaced']) + ' rem=' + str(wrapper_cff['remaining']),
    )

    try:
        bytecode = io.xtr_bc(src)
        log('bc', True, str(bytecode['bytesRead']) + '/' + str(bytecode['bytesTotal']))
    except Exception:
        log('bc', False)
        raise

    if is_v1:
        strings = {
            'outer': [],
            'vm': [],
            'rewrittenSource': flat_src,
            'outerReplaced': 0,
            'summary': {'outerCount': 0, 'vmCount': 0, 'outerReplaced': 0},
        }
        if bytecode['root']:
            strings['vm'] = io.dec_all_str(flat_src, bytecode['root'])['vm']
            strings['summary']['vmCount'] = len(strings['vm'])
    else:
        strings = io.dec_all_str(flat_src, bytecode['root'])

    summary = strings.get('summary') or {}
    log('str', True, 'outer=' + str(summary.get('outerCount', 0)) + ' vm=' + str(summary.get('vmCount', 0)))

    rewritten_source = flat_src
    wrapper_after = {'replaced': 0, 'statesTotal': 0, 'remaining': wrapper_cff['remaining']}
    if strings.get('rewrittenSource') and strings['rewrittenSource'] != flat_src:
        rewritten_source = strings['rewrittenSource']
        wrapper_after = io.unflat_cff(rewritten_source)
        rewritten_source = wrapper_after['source']

    protections = io.inv_prot(src, {
        'wrapperCff': {
            'replaced': wrapper_cff['replaced'] + (wrapper_after.get('replaced') or 0),
            'remaining': (wrapper_after['remaining'] if wrapper_after.get('remaining') is not None
                          else wrapper_cff['remaining']),
        },
    })

    try:
        vm_result = vm.an_vm(rewritten_source)
        used = collect_opcodes(bytecode['root'])
        mapped = 0
        for op in used:
            if vm_result['opcodeMap'].get(op):
                mapped += 1
        if mapped < max(3, -(-len(used) * 35 // 100)):
            vm_flat = vm.an_vm(flat_src)
            mapped_flat = 0
            for op in used:
                if vm_flat['opcodeMap'].get(op):
                    mapped_flat += 1
            if mapped_flat > mapped:
                vm_result = vm_flat

        vm.ref_op_map(bytecode['root'], vm_result['opcodeMap'])

        for op in used:
            entry = vm_result['opcodeMap'].get(op)
            if not entry or entry.get('name') == 'UNKNOWN':
                g = guess_from_ins(bytecode['root'], op)
                if not entry:
                    vm_result['opcodeMap'][op] = {'name': g, 'body': ''}
                else:
                    entry['name'] = g
        log('vm', True, 'ops=' + str(vm_result['opcodeCount']) + ' used=' + str(len(used)))
    except Exception:
        log('vm', False)
        raise

    used = collect_opcodes(bytecode['root'])
    try:
        reconstructed = out.recon_prog(bytecode['root'], vm_result['opcodeMap'], vm_result['closureLocalOp'])
        lifted = out.lift_prog(bytecode['root'], vm_result['opcodeMap'], vm_result['closureLocalOp'])
        disasm = out.disasm_pr(bytecode['root'], vm_result['opcodeMap'], vm_result['closureLocalOp'])
        cfg = out.sum_cfg(bytecode['root'], vm_result['opcodeMap'], vm_result['closureLocalOp'])
        log('recon', True)
    except Exception:
        log('recon', False)
        raise

    out_str = with_hdr(reconstructed)
    return {
        'detection': detection,
        'protections': protections,
        'wrapperCff': {
            'replaced': wrapper_cff['replaced'] + (wrapper_after.get('replaced') or 0),
            'statesTotal': (wrapper_cff.get('statesTotal') or 0) + (wrapper_after.get('statesTotal') or 0),
            'remaining': (wrapper_after['remaining'] if wrapper_after.get('remaining') is not None
                          else wrapper_cff['remaining']),
        },
        'bytecode': {
            'bytesRead': bytecode['bytesRead'],
            'bytesTotal': bytecode['bytesTotal'],
            'sentinel': bytecode['sentinel'],
            'xorCalls': bytecode['xorCalls'],
            'root': bytecode['root'],
        },
        'vm': {
            'opcodeCount': vm_result['opcodeCount'],
            'closureLocalOp': vm_result['closureLocalOp'],
            'usedOpcodes': sorted(used),
            'usedMap': {str(op): ((vm_result['opcodeMap'].get(op) or {}).get('name') or 'UNKNOWN')
                        for op in sorted(used)},
            'nameToOpcodes': vm_result['nameToOpcodes'],
            'opcodeMap': vm_result['opcodeMap'],
        },
        'strings': {
            'outer': strings.get('outer'),
            'vm': strings.get('vm'),
            'summary': strings.get('summary'),
            'maps': [
                {
                    'path': m.get('path'),
                    'index': m.get('index'),
                    'key': m.get('key'),
                    'decrypted': m.get('decrypted'),
                    'score': m.get('score'),
                    'singleByte': bool(m.get('singleByte')),
                }
                for m in (strings.get('vm') or [])
            ],
            'rewrittenSource': rewritten_source if options.get('includeRewrittenSource') else None,
        },
        'cfg': cfg,
        'lifted': lifted,
        'reconstructed': out_str,
        'lua': out_str,
        'disasm': disasm,
        'rewrittenSource': rewritten_source,
    }
