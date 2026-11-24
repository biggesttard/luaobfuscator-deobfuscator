"""Bytecode annotation, structure recovery, lifting and disassembly."""

from __future__ import annotations

import json

from .luaio import char, fmt_num, is_num
from .luavm import (
    pref_nm, shp_guess, guess_op, is_g_name, is_bin_k,
)


# ---------------------------------------------------------------------------
# generic helpers
# ---------------------------------------------------------------------------


def _instr(proto, i):
    if not proto or i is None:
        return None
    arr = proto.instructions
    if isinstance(i, int) and 0 <= i < len(arr):
        return arr[i]
    return None


def _n_instr(proto):
    return len(proto.instructions) if proto else 1


def _proto_at(proto, i):
    if not proto or not isinstance(i, int):
        return None
    arr = proto.prototypes
    if 0 <= i < len(arr):
        return arr[i]
    return None


def _const_at(proto, i):
    if not proto or not isinstance(i, int):
        return None
    arr = proto.constants
    if 0 <= i < len(arr):
        return arr[i]
    return None


def js_str(v):
    if v is None:
        return 'null'
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, (int, float)):
        return fmt_num(v)
    return str(v)


def js_json(v):
    return json.dumps(v, separators=(',', ':'), ensure_ascii=False)


def reg(n):
    return 'r' + js_str(n)


def ind(n):
    return '  ' * n


def esc_str(s):
    return json.dumps(str(s), ensure_ascii=False)


def fmt_k(v):
    if isinstance(v, str):
        return esc_str(v)
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, (int, float)):
        return fmt_num(v)
    if v is None:
        return 'nil'
    return esc_str(js_str(v))


def lit(v):
    if isinstance(v, str):
        return fmt_k(v)
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, (int, float)):
        return fmt_num(v)
    if v is None:
        return 'nil'
    return fmt_k(v)


def is_id(s):
    if not isinstance(s, str) or not s:
        return False
    c0 = ord(s[0])
    if not ((65 <= c0 <= 90) or (97 <= c0 <= 122) or c0 == 95):
        return False
    for ch in s[1:]:
        c = ord(ch)
        if not ((65 <= c <= 90) or (97 <= c <= 122) or (48 <= c <= 57) or c == 95):
            return False
    return True


def g_name(key):
    if is_id(key):
        return key
    return '_ENV[' + fmt_k(key) + ']'


def field(base, key, is_k):
    if (isinstance(key, str) or is_k) and is_id(key):
        return base + '.' + key
    if isinstance(key, str) or is_k:
        return base + '[' + fmt_k(key) + ']'
    if is_num(key) and is_k:
        return base + '[' + js_str(key) + ']'
    if is_num(key):
        return base + '[' + reg(key) + ']'
    return base + '[' + fmt_k(key) + ']'


def is_noise(e):
    if e is None:
        return True
    t = e if isinstance(e, str) else js_str(e)
    if not t or t == 'nil' or t == 'null' or t == '0':
        return True
    if t.startswith('nil[') or t.startswith('nil.') or t.startswith('null[') or t.startswith('null.'):
        return True
    if t.startswith('0['):
        return True
    if t.startswith('{}('):
        return True
    return False


def cmp_sym(n):
    if n == 'EQ':
        return '=='
    if n == 'LT':
        return '<'
    if n == 'LE':
        return '<='
    return None


def ind_of(line):
    i = 0
    while char(line, i) == ' ':
        i += 1
    return line[:i]


def lead_ws(s):
    i = 0
    while i < len(s) and s[i] in (' ', '\t'):
        i += 1
    return s[:i]


def col_ws(src):
    out = []
    space = False
    for ch in src:
        if ch in (' ', '\t', '\n', '\r'):
            if not space and out:
                out.append(' ')
                space = True
        else:
            out.append(ch)
            space = False
    return ''.join(out)


# ---------------------------------------------------------------------------
# instruction list cleanup
# ---------------------------------------------------------------------------

_SUB_OPS = {
    'CALL', 'TAILCALL', 'GETGLOBAL', 'SETGLOBAL', 'LOADK', 'SELF',
    'CLOSURE', 'SETTABLE', 'GETTABLE', 'ADD', 'SUB', 'MUL', 'DIV',
    'CONCAT', 'RETURN', 'NEWTABLE', 'SETLIST', 'LOADBOOL', 'TEST',
    'EQ', 'LT', 'LE', 'FORPREP', 'FORLOOP',
}


def is_sub(op):
    if not op or op.get('name') == 'UNKNOWN' or op.get('name') == 'CLOSE':
        return False
    return op.get('name') in _SUB_OPS


def jmps_before(ops, i):
    for j in range(i):
        if ops[j].get('name') != 'JMP':
            return False
    return True


def res_jmp(ops, by_pc, b):
    guard = 0
    ti = by_pc.get(b)
    while ti is not None and guard < 12:
        guard += 1
        op = ops[ti]
        if op.get('name') == 'JMP' and is_num(op.get('B')) and op.get('B') != b:
            b = op['B']
            ti = by_pc.get(b)
            continue
        break
    return {'ti': ti, 'b': b}


def strip_red_jmp(ops):
    out = []
    for i, op in enumerate(ops):
        if op.get('name') != 'JMP' or not is_num(op.get('B')):
            out.append(op)
            continue
        if i + 1 < len(ops) and ops[i + 1].get('index') == op['B']:
            continue
        if out and out[-1].get('name') == 'JMP' and out[-1].get('B') == op['B']:
            continue
        out.append(op)
    return out


def strip_fwd_jmp(ops):
    by_pc = {}
    for i, op in enumerate(ops):
        by_pc[op.get('index')] = i

    nop = set()
    for i, op in enumerate(ops):
        if op.get('name') != 'JMP' or not is_num(op.get('B')):
            continue
        resolved = res_jmp(ops, by_pc, op['B'])
        ti = resolved['ti']
        if ti is None or ti <= i:
            continue

        subst = 0
        for j in range(i + 1, ti):
            if is_sub(ops[j]):
                subst += 1
        if subst < 2:
            continue

        epi_subst = 0
        for j in range(ti, min(ti + 6, len(ops))):
            if is_sub(ops[j]) and ops[j].get('name') != 'RETURN':
                epi_subst += 1

        if jmps_before(ops, i) and subst >= 2:
            nop.add(i)
            continue

        if subst >= 2 and epi_subst <= 1:
            nop.add(i)

    if not nop:
        return ops
    return [op for i, op in enumerate(ops) if i not in nop]


def strip_mut_jmp(ops):
    by_pc = {}
    for i, op in enumerate(ops):
        by_pc[op.get('index')] = i
    nop = set()
    for i, a in enumerate(ops):
        if a.get('name') != 'JMP' or not is_num(a.get('B')):
            continue
        ti = by_pc.get(a['B'])
        if ti is None:
            continue
        b = ops[ti]
        if b.get('name') == 'JMP' and b.get('B') == a.get('index'):
            nop.add(i)
            nop.add(ti)
    if not nop:
        return ops
    return [op for i, op in enumerate(ops) if i not in nop]


def strip_bog_ret(ops):
    nop = set()
    for i, op in enumerate(ops):
        if op.get('name') != 'RETURN' and op.get('name') != 'TAILCALL':
            continue
        if i + 2 >= len(ops):
            continue
        if op.get('name') == 'TAILCALL':
            continue

        if is_num(op.get('B')) and op['B'] >= 2:
            keep = False
            for j in range(i + 1, min(i + 5, len(ops))):
                n = ops[j]
                if n.get('name') == 'EQ' and is_num(n.get('A')) and n['A'] <= 4 and n.get('isKC'):
                    keep = True
                    break
                if n.get('name') == 'LOADK' and n.get('B') == 0 and is_num(n.get('A')) and n['A'] <= 4:
                    keep = True
                    break
            if keep:
                continue
        subst = 0
        for j in range(i + 1, len(ops)):
            if is_sub(ops[j]):
                subst += 1
        if subst >= 3:
            nop.add(i)
    if not nop:
        return ops
    return [op for i, op in enumerate(ops) if i not in nop]


def remap_jmp(ops):
    if not ops:
        return ops
    present = {o.get('index') for o in ops}
    sorted_ix = sorted(present)

    def resolve(b):
        if b in present:
            return b
        for ix in sorted_ix:
            if ix >= b:
                return ix
        return sorted_ix[-1]

    changed = False
    out = []
    for op in ops:
        if op.get('name') not in ('JMP', 'EQ', 'LT', 'LE', 'TEST', 'TESTSET', 'FORLOOP', 'FORPREP'):
            out.append(op)
            continue
        if not is_num(op.get('B')):
            out.append(op)
            continue
        nb = resolve(op['B'])
        if nb == op['B']:
            out.append(op)
            continue
        changed = True
        copy = dict(op)
        copy['B'] = nb
        out.append(copy)
    return out if changed else ops


def strip_nil(ops):
    nop = set()
    for i, op in enumerate(ops):
        if op.get('name') != 'LOADNIL':
            continue
        a = op.get('A')
        to = op['B'] if is_num(op.get('B')) else a
        for j in range(i + 1, min(i + 4, len(ops))):
            n = ops[j]
            if not n:
                break
            if n.get('name') == 'GETTABLE' and n.get('B') == a:
                nop.add(i)
                nop.add(j)
                if j + 1 < len(ops) and ops[j + 1].get('name') == 'CALL' and ops[j + 1].get('A') == n.get('A'):
                    nop.add(j + 1)
                break
            if n.get('name') == 'CALL' and n.get('A') == a:
                nop.add(i)
                nop.add(j)
                break
            if n.get('name') == 'LOADNIL':
                continue
            if n.get('name') in ('MOVE', 'JMP'):
                continue
            break

        if i == 0 and is_num(to) and is_num(a) and to >= a + 2:
            nop.add(i)
    if not nop:
        return ops
    return [op for i, op in enumerate(ops) if i not in nop]


def strip_back(ops):
    nop = set()
    for i, op in enumerate(ops):
        if op.get('name') not in ('EQ', 'LT', 'LE'):
            continue
        if is_num(op.get('A')) and op['A'] > 32:
            nop.add(i)
    if not nop:
        return ops
    return [op for i, op in enumerate(ops) if i not in nop]


def lin_st_cff(ops):
    if not ops or len(ops) < 10:
        return ops

    state_reg = None
    for i in range(min(6, len(ops))):
        op = ops[i]
        if op.get('name') == 'LOADK' and op.get('B') == 0 and is_num(op.get('A')):
            state_reg = op['A']
            break
    if state_reg is None:
        return ops

    by_pc = {}
    for i, op in enumerate(ops):
        by_pc[op.get('index')] = i

    eq_states = []
    for i, op in enumerate(ops):
        if (op.get('name') == 'EQ' and op.get('A') == state_reg and op.get('isKC')
                and is_num(op.get('C')) and is_num(op.get('B'))):
            eq_states.append({'i': i, 'state': op['C'], 'target': op['B']})
    if len(eq_states) < 2:
        return ops

    blocks = {}
    for eq in eq_states:
        start = eq['i'] + 1
        if start < len(ops) and ops[start].get('name') == 'JMP':
            start += 1
        end = len(ops)
        for j in range(start, len(ops)):
            op = ops[j]
            if op.get('name') == 'EQ' and op.get('A') == state_reg and op.get('isKC'):
                end = j
                break
            if (op.get('name') == 'LOADK' and op.get('A') == state_reg
                    and is_num(op.get('B')) and op['B'] != eq['state']):
                end = j
                break
        if end > start:
            blocks[eq['state']] = ops[start:end]

    if len(blocks) < 2:
        return ops

    out = []
    for s in sorted(blocks.keys()):
        block = list(blocks[s])
        while block:
            last = block[-1]
            if last.get('name') == 'JMP':
                block.pop()
                continue
            if last.get('name') == 'LOADK' and last.get('A') == state_reg:
                block.pop()
                continue
            break
        out.extend(block)

    last_orig = ops[-1]
    if last_orig and last_orig.get('name') == 'RETURN' and (not out or out[-1].get('name') != 'RETURN'):
        has_ret = any(o.get('name') == 'RETURN' for o in out)
        if not has_ret:
            out.append(last_orig)
    return out if len(out) >= 3 else ops


def clean_cfg(ops):
    cur = list(ops)
    for _ in range(4):
        n = len(cur)
        cur = strip_fwd_jmp(cur)
        cur = strip_red_jmp(cur)
        cur = strip_mut_jmp(cur)
        cur = strip_bog_ret(cur)
        cur = strip_nil(cur)
        cur = strip_back(cur)
        cur = remap_jmp(cur)
        if len(cur) == n:
            break
    cur = remap_jmp(cur)
    cur = lin_st_cff(cur)
    return remap_jmp(cur)


def jmp_stats(ops):
    jmps = sum(1 for op in ops if op.get('name') == 'JMP')
    cleaned = clean_cfg(ops)
    return {'jmps': jmps, 'removed': len(ops) - len(cleaned), 'before': len(ops), 'after': len(cleaned)}


# ---------------------------------------------------------------------------
# annotation
# ---------------------------------------------------------------------------


def ann_pr(proto, opcode_map, closure_local_op):
    out = []
    i = 1
    n = _n_instr(proto)
    while i < n:
        ins = _instr(proto, i)
        if not ins or ins.skipped:
            i += 1
            continue
        ins._index = i
        info = opcode_map.get(ins.opcode) or {'name': 'UNKNOWN'}
        name = info.get('name')
        if name == 'GETGLOBAL_OR_UPVAL':
            name = 'GETGLOBAL'
        if name == 'UNKNOWN':
            name = guess_op(ins)
        name = pref_nm(name, ins, proto, closure_local_op, opcode_map)

        if name == 'CALL' and is_num(ins.B) and ins.B >= 1 and ins.C == 1:
            saw_table = False
            loads = 0
            for j in range(i - 1, max(1, i - 12) - 1, -1):
                p = _instr(proto, j)
                if not p or p.skipped:
                    continue
                pn = pref_nm((opcode_map.get(p.opcode) or {}).get('name') or 'UNKNOWN',
                             p, proto, closure_local_op, opcode_map)
                if pn == 'NEWTABLE' and p.A == ins.A:
                    saw_table = True
                    break
                if pn in ('LOADK', 'MOVE', 'LOADBOOL'):
                    if is_num(p.A) and p.A > ins.A and p.A <= ins.A + ins.B:
                        loads += 1
                    continue
                break
            if saw_table and loads >= 1:
                name = 'SETLIST'

        if name == 'SETLIST' and is_num(ins.B) and is_num(ins.A) and ins.B > ins.A + 8:
            name = 'CALL'

        if name == 'SELF' and is_num(ins.C) and ins.C > 0 and is_num(ins.B):
            proto_idx = ins.B
            if _proto_at(proto, proto_idx):
                looks_up = True
                for u in range(int(ins.C)):
                    nxt = _instr(proto, i + 1 + u)
                    if not nxt or nxt.skipped:
                        looks_up = False
                        break
                    nn = (opcode_map.get(nxt.opcode) or {}).get('name')
                    if closure_local_op is not None and nxt.opcode == closure_local_op:
                        continue
                    if nn in ('MOVE', 'GETUPVAL'):
                        continue
                    if nxt.mode == 0 and not nxt.isKB and not nxt.isKC:
                        continue
                    looks_up = False
                    break
                if looks_up:
                    name = 'CLOSURE'

        if ((name == 'TAILCALL' or name == 'RETURN') and ins.B == 0
                and (ins.C == 0 or ins.C is None) and i + 3 < _n_instr(proto)):
            map_name = (opcode_map.get(ins.opcode) or {}).get('name') or 'UNKNOWN'
            if map_name == 'RETURN' or map_name == 'TAILCALL':
                pass
            else:
                shape = shp_guess(ins, proto, closure_local_op, opcode_map)
                if not shape or shape['conf'] < 60 or shape['name'] == 'UNKNOWN':
                    name = map_name if map_name != 'UNKNOWN' else 'MOVE'

        if name == 'CLOSURE':
            nups = ins.C if is_num(ins.C) else 0
            pidx = ins.B if is_num(ins.B) else -1
            if nups < 0 or nups > 32 or not _proto_at(proto, pidx):
                name = 'UNKNOWN'
            else:
                upvals = []
                for u in range(int(nups)):
                    nxt = _instr(proto, i + 1 + u)
                    if not nxt or nxt.skipped:
                        continue
                    if closure_local_op is not None:
                        is_local = nxt.opcode == closure_local_op
                    else:
                        is_local = (opcode_map.get(nxt.opcode) or {}).get('name') == 'MOVE'
                    upvals.append({'isLocal': bool(is_local), 'idx': nxt.B})
                out.append({
                    'index': i, 'opcode': ins.opcode, 'name': name,
                    'A': ins.A, 'B': ins.B, 'C': ins.C,
                    'isKA': ins.isKA, 'isKB': ins.isKB, 'isKC': ins.isKC,
                    'mode': ins.mode, 'upvals': upvals, 'skip': nups,
                })
                i += 1 + int(nups)
                continue

        out.append({
            'index': i, 'opcode': ins.opcode, 'name': name,
            'A': ins.A, 'B': ins.B, 'C': ins.C,
            'isKA': ins.isKA, 'isKB': ins.isKB, 'isKC': ins.isKC,
            'mode': ins.mode,
        })
        i += 1
    return out


# ---------------------------------------------------------------------------
# lifting / disassembly
# ---------------------------------------------------------------------------


def idx_or_k(v, is_k):
    if isinstance(v, str) or is_k:
        return fmt_k(v)
    if is_num(v):
        return reg(v)
    return fmt_k(v)


def lift_ins(ins, proto_name):
    A, B, C = ins['A'], ins['B'], ins['C']
    ra = reg(A) if is_num(A) else fmt_k(A)
    name = ins['name']

    if name == 'MOVE':
        return ra + ' = ' + reg(B)
    if name == 'LOADK':
        return ra + ' = ' + fmt_k(B)
    if name == 'LOADBOOL':
        return ra + ' = ' + ('true' if B else 'false')
    if name == 'LOADNIL':
        parts = []
        to = B if is_num(B) else A
        for i in range(int(A), int(to) + 1):
            parts.append(reg(i) + ' = nil')
        return '; '.join(parts)
    if name == 'GETUPVAL':
        return ra + ' = upval_' + js_str(B)
    if name == 'GETGLOBAL':
        return ra + ' = _ENV[' + fmt_k(B) + ']'
    if name == 'GETTABLE':
        return ra + ' = ' + reg(B) + '[' + idx_or_k(C, ins['isKC']) + ']'
    if name == 'SETGLOBAL':
        return '_ENV[' + fmt_k(B) + '] = ' + ra
    if name == 'SETUPVAL':
        return 'upval_' + js_str(B) + ' = ' + ra
    if name == 'SETTABLE':
        return reg(A) + '[' + idx_or_k(B, ins['isKB']) + '] = ' + idx_or_k(C, ins['isKC'])
    if name == 'NEWTABLE':
        return ra + ' = {}'
    if name == 'SELF':
        return reg(A + 1) + ' = ' + reg(B) + '; ' + ra + ' = ' + reg(B) + '[' + idx_or_k(C, ins['isKC']) + ']'
    if name == 'ADD':
        return ra + ' = ' + reg(B) + ' + ' + reg(C)
    if name == 'SUB':
        return ra + ' = ' + reg(B) + ' - ' + reg(C)
    if name == 'MUL':
        return ra + ' = ' + reg(B) + ' * ' + reg(C)
    if name == 'DIV':
        return ra + ' = ' + reg(B) + ' / ' + reg(C)
    if name == 'MOD':
        return ra + ' = ' + reg(B) + ' % ' + reg(C)
    if name == 'POW':
        return ra + ' = ' + reg(B) + ' ^ ' + reg(C)
    if name == 'UNM':
        return ra + ' = -' + reg(B)
    if name == 'NOT':
        return ra + ' = not ' + reg(B)
    if name == 'LEN':
        return ra + ' = #' + reg(B)
    if name == 'CONCAT':
        return ra + ' = ' + reg(B) + ' .. ' + reg(C)
    if name == 'JMP':
        return 'goto lbl_' + js_str(B)
    if name == 'EQ':
        return 'if ' + ra + ' == ' + fmt_k(C) + ' then else goto lbl_' + js_str(B) + ' end'
    if name == 'LT':
        return 'if ' + ra + ' < ' + fmt_k(C) + ' then else goto lbl_' + js_str(B) + ' end'
    if name == 'LE':
        return 'if ' + ra + ' <= ' + fmt_k(C) + ' then else goto lbl_' + js_str(B) + ' end'
    if name == 'TEST':
        return 'if ' + ra + ' then else goto lbl_' + js_str(B) + ' end'
    if name == 'CALL':
        if B is None or B == 0:
            return ra + ' = ' + ra + '(' + reg(A + 1) + ', ...)'
        if B == 1:
            return ra + ' = ' + ra + '()'
        if is_num(B) and B >= 2:
            args = [reg(i) for i in range(int(A) + 1, int(A + B))]
            return ra + ' = ' + ra + '(' + ', '.join(args) + ')'
        return ra + ' = ' + ra + '()'
    if name == 'TAILCALL':
        if B == 1:
            return 'return ' + ra + '()'
        if is_num(B) and B >= 2:
            args = [reg(i) for i in range(int(A) + 1, int(A + B))]
            return 'return ' + ra + '(' + ', '.join(args) + ')'
        return 'return ' + ra + '()'
    if name == 'RETURN':
        if B == 1 or B == 0:
            return 'return'
        if is_num(B) and B > 1:
            vals = [reg(i) for i in range(int(A), int(A + B) - 1)]
            return 'return ' + ', '.join(vals)
        return 'return ' + ra
    if name == 'CLOSURE':
        return ra + ' = ' + proto_name + '_f' + js_str(B)
    if name == 'SETLIST':
        return 'do end'
    if name == 'VARARG':
        return ra + ' = ...'
    if name == 'CLOSE':
        return 'do end'
    return 'do end'


def lift_pr(proto, opcode_map, closure_local_op, proto_name='main', ind_=0):
    sp = '  ' * ind_
    lines = []
    annotated = ann_pr(proto, opcode_map, closure_local_op)
    params = [reg(p) for p in range(int(proto.params or 0))]

    lines.append(sp + 'function ' + proto_name + '(' + ', '.join(params) + ')')

    for pi, child in enumerate(proto.prototypes):
        if not child:
            continue
        lines.append(lift_pr(child, opcode_map, closure_local_op, proto_name + '_f' + str(pi), ind_ + 1))

    labels = set()
    for ins in annotated:
        if ins['name'] in ('JMP', 'EQ', 'LT', 'LE', 'TEST') and is_num(ins.get('B')):
            labels.add(ins['B'])

    for ins in annotated:
        if ins['index'] in labels:
            lines.append(sp + '  ::lbl_' + str(ins['index']) + '::')
        lines.append(sp + '  ' + lift_ins(ins, proto_name))

    lines.append(sp + 'end')
    return '\n'.join(lines)


def lift_prog(root, opcode_map, closure_local_op):
    return '\n'.join([
        lift_pr(root, opcode_map, closure_local_op, 'main', 0),
        '',
        'return main()',
    ])


def disasm_pr(proto, opcode_map, closure_local_op, name='main', ind_=0):
    sp = '  ' * ind_
    lines = []
    lines.append(sp + '.proto ' + name + ' params=' + js_str(proto.params))
    consts = []
    for i, c in enumerate(proto.constants):
        if i:
            consts.append(str(i) + '=' + fmt_k(c))
    lines.append(sp + '.constants ' + ', '.join(consts))
    annotated = ann_pr(proto, opcode_map, closure_local_op)
    for ins in annotated:
        label = ins['name']
        line = (sp + '[' + str(ins['index']).rjust(3) + '] ' + label.ljust(10)
                + ' A=' + js_json(ins['A']) + ' B=' + js_json(ins['B']) + ' C=' + js_json(ins['C']))
        if 'upvals' in ins:
            line += ' upvals=' + js_json(ins['upvals'])
        lines.append(line)
    for i, child in enumerate(proto.prototypes):
        if not child:
            continue
        lines.append(disasm_pr(child, opcode_map, closure_local_op, name + '_f' + str(i), ind_ + 1))
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# line level helpers
# ---------------------------------------------------------------------------


def jmp_tgts(ops):
    t = set()
    for op in ops:
        if op.get('name') in ('JMP', 'EQ', 'LT', 'LE', 'TEST', 'TESTSET', 'FORLOOP', 'FORPREP'):
            if is_num(op.get('B')):
                t.add(op['B'])
    return t


def by_idx(ops):
    m = {}
    for i, op in enumerate(ops):
        m[op.get('index')] = i
    return m


def an_pr_use(proto, ops):
    loadk_str = loadk_num = get_g = get_f = get_u = calls = 0
    set_g = set_t = new_t = clos = loops = rets = 0

    for op in ops or []:
        if not op:
            continue
        name = op.get('name')
        if not name:
            continue
        if name == 'LOADK':
            if isinstance(op.get('B'), str) and len(op['B']) > 0:
                loadk_str += 1
            elif is_num(op.get('B')):
                loadk_num += 1
        elif name == 'GETGLOBAL':
            get_g += 1
        elif name in ('GETTABLE', 'SELF'):
            get_f += 1
        elif name == 'GETUPVAL':
            get_u += 1
        elif name in ('CALL', 'TAILCALL'):
            calls += 1
        elif name == 'SETGLOBAL':
            set_g += 1
        elif name == 'SETTABLE':
            set_t += 1
        elif name == 'NEWTABLE':
            new_t += 1
        elif name == 'CLOSURE':
            clos += 1
        elif name in ('FORPREP', 'FORLOOP', 'TFORLOOP'):
            loops += 1
        elif name == 'RETURN':
            rets += 1

    interesting = (
        loadk_str > 0
        or set_g > 0
        or set_t > 0
        or (new_t > 0 and (set_t > 0 or loops > 0))
        or (calls > 0 and loadk_str + set_g + set_t + new_t > 0)
        or (clos > 0 and calls > 0)
    )

    xor_stub = (
        loadk_str == 0
        and set_g == 0
        and set_t == 0
        and get_u >= 1
        and (get_g + get_f) >= 2
        and (loops > 0 or calls > 0)
    )

    score = (loadk_str * 12 + set_g * 15 + set_t * 8 + new_t * 3 + clos * 4
             + (10 if (calls > 0 and loadk_str > 0) else 0)
             + (-40 if xor_stub else 0)
             + (5 if interesting else 0))

    return {
        'loadkStr': loadk_str, 'loadkNum': loadk_num, 'getG': get_g, 'getF': get_f,
        'getU': get_u, 'calls': calls, 'setG': set_g, 'setT': set_t, 'newT': new_t,
        'clos': clos, 'loops': loops, 'rets': rets,
        'interesting': interesting, 'xorStub': xor_stub, 'score': score,
    }


def parse_asg(t):
    if char(t, 0) != 'r':
        return None
    i = 1
    if i >= len(t) or t[i] < '0' or t[i] > '9':
        return None
    while i < len(t) and '0' <= t[i] <= '9':
        i += 1
    if t[i:i + 3] != ' = ':
        return None
    return {'lhs': t[:i], 'rhs': t[i + 3:]}


def col_regs(text, into):
    i = 0
    while i < len(text):
        if text[i] != 'r':
            i += 1
            continue
        if i > 0:
            p = text[i - 1]
            if ('a' <= p <= 'z') or ('A' <= p <= 'Z') or ('0' <= p <= '9') or p == '_':
                i += 1
                continue
        j = i + 1
        if j >= len(text) or text[j] < '0' or text[j] > '9':
            i += 1
            continue
        while j < len(text) and '0' <= text[j] <= '9':
            j += 1
        n = char(text, j)
        if n and (('a' <= n <= 'z') or ('A' <= n <= 'Z') or n == '_'):
            i = j
            continue
        into.add(text[i:j])
        i = j


def rhs_call(rhs):
    i = 0
    while i < len(rhs):
        c = rhs[i]
        if c in ('"', "'"):
            q = c
            i += 1
            while i < len(rhs) and rhs[i] != q:
                if rhs[i] == '\\':
                    i += 1
                i += 1
            i += 1
            continue
        if c == '(':
            return True
        i += 1
    return False


def lab_exists(lines, lab):
    needle = '::' + lab + '::'
    for line in lines:
        if line.strip() == needle:
            return True
    return False


def drop_empty_if(lines):
    out = []
    i = 0
    while i < len(lines):
        t = lines[i].strip()
        if t.startswith('if ') and t.endswith(' then'):
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines) and lines[j].strip() == 'end' and ind_of(lines[j]) == ind_of(lines[i]):
                i = j + 1
                continue
        out.append(lines[i])
        i += 1
    return out


def fin_lines(lines):
    used = set()
    keep = [False] * len(lines)
    demote = [False] * len(lines)

    for i in range(len(lines) - 1, -1, -1):
        t = lines[i].strip()
        if not t:
            keep[i] = False
            continue
        if t.startswith('--'):
            keep[i] = True
            continue
        if t.startswith('::') and t.endswith('::'):
            keep[i] = ('#' + t[2:-2]) in used
            continue
        if t.startswith('goto '):
            lab = t[5:]
            if not lab_exists(lines, lab):
                keep[i] = False
                continue
            keep[i] = True
            used.add('#' + lab)
            continue
        asg = parse_asg(t)
        if asg:
            live = asg['lhs'] in used
            call = rhs_call(asg['rhs'])
            keep_bind = asg['rhs'].startswith('{') or is_id(asg['rhs'])
            if live or keep_bind:
                keep[i] = True
                used.discard(asg['lhs'])
                col_regs(asg['rhs'], used)
            elif call:
                keep[i] = True
                demote[i] = True
                col_regs(asg['rhs'], used)
            else:
                keep[i] = False
            continue
        keep[i] = True
        col_regs(t, used)

    out = []
    for i, line in enumerate(lines):
        if not keep[i]:
            continue
        if demote[i]:
            asg = parse_asg(line.strip())
            if asg:
                out.append(ind_of(line) + asg['rhs'])
                continue
        out.append(line)
    return drop_empty_if(out)


# ---------------------------------------------------------------------------
# structured recovery
# ---------------------------------------------------------------------------


def tidy(lines):
    text = '\n'.join(lines)
    out = []
    dead = False
    i = 0
    while i < len(lines):
        line = lines[i]
        t = line.strip()
        if not t:
            i += 1
            continue
        if t.startswith('::') and t.endswith('::'):
            dead = False
            lab = t[2:-2]
            if ('goto ' + lab) not in text:
                i += 1
                continue
            out.append(line)
            i += 1
            continue
        if dead:
            i += 1
            continue
        if t == 'return' and out and out[-1].strip().startswith('return'):
            i += 1
            continue
        if t.startswith('goto L'):
            lab = t[5:]
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines) and lines[j].strip() == '::' + lab + '::':
                i += 1
                continue
            out.append(line)
            dead = True
            i += 1
            continue
        if t == 'return' or t.startswith('return '):
            out.append(line)
            dead = True
            i += 1
            continue
        out.append(line)
        i += 1
    return out


def match_asg(line):
    i = 0
    while char(line, i) == ' ':
        i += 1
    if char(line, i) != 'r':
        return None
    j = i + 1
    while j < len(line) and '0' <= line[j] <= '9':
        j += 1
    left = line[i:j]
    if line[j:j + 3] != ' = ':
        return None
    return {'ind': line[:i], 'left': left, 'right': line[j + 3:]}


def fold_ln(lines):
    out = []
    i = 0
    while i < len(lines):
        a = match_asg(lines[i])
        b = match_asg(lines[i + 1]) if i + 1 < len(lines) else None
        if a and b and a['left'] == b['left']:
            if b['right'].startswith(a['left'] + '.') or b['right'].startswith(a['left'] + '['):
                out.append(a['ind'] + a['left'] + ' = ' + a['right'] + b['right'][len(a['left']):])
                i += 2
                continue
        out.append(lines[i])
        i += 1
    return out


def get_safe(regs, r):
    return regs.get(r) or reg(r)


def rk(v, is_k, regs):
    if is_k or isinstance(v, str) or isinstance(v, bool):
        return lit(v)
    if v is None:
        return 'nil'
    if is_num(v):
        return regs.get(v) or reg(v)
    return lit(v)


def call_args(op, regs, defined):
    A, B, C = op.get('A'), op.get('B'), op.get('C')

    if (is_num(B) and B >= A + 1 and B <= A + 8
            and (C == 0 or C is None or C == 1 or C == 2)):
        out = []
        for r in range(int(A) + 1, int(B) + 1):
            e = regs.get(r) or reg(r)
            if defined and e == reg(r) and r not in defined:
                continue
            if e == 'nil':
                continue
            out.append(e)
        return out

    if B is None or B == 0:
        if defined and (A + 1) in defined:
            e = regs.get(A + 1) or reg(A + 1)
            if e != 'nil':
                return [e]
        for r in range(int(A) + 2, int(A) + 9):
            if not defined or r not in defined:
                continue
            e = regs.get(r) or reg(r)
            if e != 'nil':
                return [e]
        return []
    if B == 1:
        return []
    if is_num(B) and B >= 2:
        out = []
        for r in range(int(A) + 1, int(A + B)):
            e = regs.get(r) or reg(r)
            if defined and e == reg(r) and r not in defined:
                continue
            out.append(e)
        while out and out[-1] == 'nil':
            out.pop()
        while out and out[0] == 'nil':
            out.pop(0)
        return out
    return []


def cmpl(op, regs):
    if op.get('isKA') and is_num(op.get('A')):
        return lit(op['A'])
    return regs.get(op.get('A')) or reg(op.get('A'))


def cmpr(op, regs):
    if op.get('name') == 'TEST':
        return None
    if op.get('isKA') and is_num(op.get('C')) and not op.get('isKC'):
        return regs.get(op['C']) or reg(op['C'])
    return rk(op.get('C'), op.get('isKC'), regs)


def try_num_for(ops, i, idx, targets, regs, defined, depth, upvals, child_names, closure_binds):
    op = ops[i]
    if op.get('name') != 'FORPREP' or not is_num(op.get('B')):
        return None
    loop_i = idx.get(op['B'])
    if loop_i is None or loop_i <= i:
        return None
    loop_op = ops[loop_i]
    if not loop_op or loop_op.get('name') != 'FORLOOP':
        return None

    A = op.get('A')
    init = regs.get(A) or reg(A)
    limit = regs.get(A + 1) or reg(A + 1)
    step = regs.get(A + 2) or reg(A + 2)
    var_r = A + 3
    sp = ind(depth)

    body_regs = dict(regs)
    body_def = set(defined)
    body_regs[var_r] = reg(var_r)
    body_def.add(var_r)
    body_def.add(A)
    body_def.add(A + 1)
    body_def.add(A + 2)

    ne = matcnns(ops, i + 1, loop_i, var_r, body_regs)
    if ne:
        body_lines = [ind(depth + 1) + ne]
    else:
        body_lines = emit_sl(ops, i + 1, loop_i, body_regs, body_def, depth + 1,
                             upvals, child_names, closure_binds, targets)
        neat = rec_ne_store(body_lines, var_r)
        if neat:
            body_lines = neat

    step_lit = parse_stat(step)
    if step_lit == 1 or step == '1':
        header = sp + 'for ' + reg(var_r) + ' = ' + init + ', ' + limit + ' do'
    else:
        header = sp + 'for ' + reg(var_r) + ' = ' + init + ', ' + limit + ', ' + step + ' do'

    for k, v in body_regs.items():
        regs[k] = v
    for k in body_def:
        defined.add(k)

    return {'lines': [header] + body_lines + [sp + 'end'], 'next': loop_i + 1}


def matcnns(ops, start, to, var_r, regs):
    for i in range(start, to - 2):
        eq = ops[i]
        if not eq or eq.get('name') != 'EQ' or not eq.get('isKA'):
            continue
        left = cmpl(eq, regs)
        right = cmpr(eq, regs)
        if js_str(left) != '1' and left != 1:
            continue
        if right != reg(var_r):
            continue

        fb = None
        tb = None
        st = None
        for j in range(i + 1, to):
            o = ops[j]
            if not o:
                continue
            if o.get('name') == 'JMP':
                continue
            if o.get('name') == 'LOADBOOL' and o.get('B') == 0 and fb is None:
                fb = o
                continue
            if o.get('name') == 'LOADBOOL' and o.get('B') == 1 and fb and tb is None:
                tb = o
                continue
            if o.get('name') == 'SETTABLE' and fb and tb and o.get('B') == var_r and o.get('C') == fb.get('A'):
                st = o
                break
            if o.get('name') == 'SETTABLE' and fb and tb and o.get('B') == var_r:
                st = o
                break
            if o.get('name') not in ('LOADBOOL', 'EQ', 'JMP') and st is None and tb:
                break
        if st:
            base = regs.get(st.get('A')) or reg(st.get('A'))
            return base + '[' + reg(var_r) + '] = (1 ~= ' + reg(var_r) + ')'
    return None


def is_fals_asg(a):
    if not a or len(a) < 10:
        return None
    if not a.startswith('r') or not a.endswith(' = false'):
        return None
    i = 1
    while i < len(a) and '0' <= a[i] <= '9':
        i += 1
    if i == 1 or a[i:] != ' = false':
        return None
    return a[1:i]


def is_true_asg(a, n):
    return a == 'r' + js_str(n) + ' = true'


def is_store_fr(a, n, vr):
    needle = '[' + vr + '] = r' + js_str(n)
    k = a.find(needle)
    if k <= 0:
        return None
    left = a[:k]
    if not left.startswith('r'):
        return None
    i = 1
    while i < len(left) and '0' <= left[i] <= '9':
        i += 1
    if i != len(left):
        return None
    return left


def rec_ne_store(lines, var_r):
    if not lines:
        return None
    vr = reg(var_r)
    out = []
    i = 0
    changed = False
    while i < len(lines):
        a = lines[i].strip() if lines[i] else None
        b = lines[i + 1].strip() if i + 1 < len(lines) and lines[i + 1] else None
        c = lines[i + 2].strip() if i + 2 < len(lines) and lines[i + 2] else None
        n = is_fals_asg(a)
        ok_t = bool(n) and bool(b) and is_true_asg(b, n)
        left = is_store_fr(c, n, vr) if (ok_t and c) else None
        if n and ok_t and left:
            out.append(lead_ws(lines[i + 2]) + left + '[' + vr + '] = (1 ~= ' + vr + ')')
            i += 3
            changed = True
            continue
        if a and a.startswith('if 1 == ') and 'then else goto' in a:
            i += 1
            changed = True
            continue
        out.append(lines[i])
        i += 1
    return out if changed else None


def try_gen_for(ops, i, idx, targets, regs, defined, depth, upvals, child_names, closure_binds):
    op = ops[i]
    if not (op.get('name') == 'CALL' or (op.get('name') == 'TFORLOOP' and op.get('mode') != 3)):
        return None
    jmp = ops[i + 1] if i + 1 < len(ops) else None
    if not jmp or jmp.get('name') != 'JMP' or not is_num(jmp.get('B')):
        return None

    A = op.get('A')

    tfor_i = None
    for j in range(i + 2, len(ops)):
        n = ops[j]
        if n.get('name') == 'TFORLOOP' and (n.get('mode') == 3 or is_num(n.get('B'))) and n.get('A') == A:
            tfor_i = j
            if n.get('mode') == 3:
                break
    if tfor_i is None:
        return None
    tfor = ops[tfor_i]
    nvars = min(tfor['C'], 4) if (is_num(tfor.get('C')) and tfor['C'] > 0) else 2
    nvars = int(nvars)

    body_start = i + 2
    body_end = tfor_i

    body_regs = dict(regs)
    body_def = set(defined)

    gen = body_regs.get(A) or reg(A)
    state = body_regs.get(A + 1) or reg(A + 1)
    for v in range(nvars):
        body_def.add(A + 3 + v)
        body_regs[A + 3 + v] = reg(A + 3 + v)

    body_lines = emit_sl(ops, body_start, body_end, body_regs, body_def, depth + 1,
                         upvals, child_names, closure_binds, targets)

    sp = ind(depth)
    vars_ = [reg(A + 3 + v) for v in range(nvars)]

    iter_expr = None
    call_fn = regs.get(A)
    if isinstance(call_fn, str) and 'pairs' in call_fn:
        iter_expr = call_fn if '(' in call_fn else call_fn + '(' + (regs.get(A + 1) or reg(A + 1)) + ')'
    elif call_fn == 'pairs' or regs.get(A) == 'pairs':
        iter_expr = 'pairs(' + (regs.get(A + 1) or state) + ')'
    else:
        prev = regs.get(A)
        if isinstance(prev, str) and prev.startswith('pairs('):
            iter_expr = prev

    if not iter_expr:
        iter_expr = get_safe(regs, A) + '(' + get_safe(regs, A + 1) + ')'

    fn_before = regs.get(A)
    arg_before = regs.get(A + 1)
    if fn_before == 'pairs' and arg_before:
        iter_expr = 'pairs(' + arg_before + ')'
    elif isinstance(fn_before, str) and fn_before.startswith('pairs('):
        iter_expr = fn_before

    for k, v in body_regs.items():
        regs[k] = v
    for k in body_def:
        defined.add(k)

    next_i = tfor_i + 1
    if next_i < len(ops) and ops[next_i].get('name') == 'JMP' and is_num(ops[next_i].get('B')):
        back = idx.get(ops[next_i]['B'])
        if back is not None and i <= back <= tfor_i:
            next_i += 1

    return {'lines': [sp + 'for ' + ', '.join(vars_) + ' in ' + iter_expr + ' do'] + body_lines + [sp + 'end'],
            'next': next_i}


def thentii(ops, else_i):
    t = ops[else_i] if 0 <= else_i < len(ops) else None
    if not t:
        return False
    if t.get('name') in ('JMP', 'RETURN', 'EQ', 'LT', 'LE', 'TEST'):
        return False
    if t.get('name') in ('FORLOOP', 'FORPREP'):
        return False
    n = ops[else_i + 1] if else_i + 1 < len(ops) else None
    if not n:
        return False
    if t.get('name') == 'TFORLOOP':
        return False
    if n.get('name') in ('TFORLOOP', 'FORLOOP'):
        return True
    if t.get('name') == 'CALL' and n.get('name') in ('TFORLOOP', 'JMP'):
        return True
    if t.get('name') == 'SETTABLE' and n.get('name') in ('FORLOOP', 'JMP'):
        return True
    return False


def iste(ops, else_i):
    if else_i is None or else_i >= len(ops):
        return False
    a = ops[else_i]
    b = ops[else_i + 1] if else_i + 1 < len(ops) else None
    if not a:
        return False
    if a.get('name') == 'GETTABLE' and b and b.get('name') == 'RETURN':
        return else_i + 2 >= len(ops)
    if a.get('name') == 'RETURN' and else_i + 1 >= len(ops):
        return True
    return False


def try_if(ops, i, idx, targets, regs, defined, depth, upvals, child_names, closure_binds):
    op = ops[i]
    if op.get('name') not in ('EQ', 'LT', 'LE', 'TEST') or not is_num(op.get('B')):
        return None
    else_i = idx.get(op['B'])
    if else_i is None or else_i <= i:
        return None

    inclusive_then = thentii(ops, else_i)

    then_end = else_i + 1 if inclusive_then else else_i
    join_pc = None
    else_anchor = else_i + 1 if inclusive_then else else_i
    before_else = ops[else_anchor - 1] if else_anchor - 1 >= 0 else None
    if (not inclusive_then and before_else and before_else.get('name') == 'JMP'
            and is_num(before_else.get('B')) and before_else['B'] > op['B']):
        join_pc = before_else['B']
        then_end = else_i - 1

    sp = ind(depth)
    left = cmpl(op, regs)
    right = cmpr(op, regs)

    if op.get('name') == 'EQ' and left == right:
        then_lines = emit_sl(ops, i + 1, then_end, dict(regs), set(defined), depth,
                             upvals, child_names, closure_binds, targets)
        next_i = idx.get(join_pc) if join_pc is not None else else_anchor
        if next_i is None:
            return None
        if join_pc is None and iste(ops, else_anchor):
            next_i = len(ops)
        if not then_lines and iste(ops, else_anchor):
            else_lines = emit_sl(ops, else_anchor, len(ops), dict(regs), set(defined), depth,
                                 upvals, child_names, closure_binds, targets)
            return {'lines': else_lines, 'next': len(ops)}
        return {'lines': then_lines, 'next': next_i}

    if op.get('name') != 'TEST':
        hit = eval_cmp(op['name'], left, right)
        if hit is True:
            then_regs = dict(regs)
            then_def = set(defined)
            then_lines = emit_sl(ops, i + 1, then_end, then_regs, then_def, depth,
                                 upvals, child_names, closure_binds, targets)
            for k, v in then_regs.items():
                regs[k] = v
            for k in then_def:
                defined.add(k)
            next_i = idx.get(join_pc) if join_pc is not None else else_anchor
            if next_i is None:
                next_i = else_anchor
            return {'lines': then_lines, 'next': next_i}
        if hit is False:
            next_i = idx.get(join_pc) if join_pc is not None else else_anchor
            if next_i is None:
                return None
            if join_pc is not None and not iste(ops, else_anchor):
                else_regs = dict(regs)
                else_def = set(defined)
                else_lines = emit_sl(ops, else_anchor, next_i, else_regs, else_def, depth,
                                     upvals, child_names, closure_binds, targets)
                for k, v in else_regs.items():
                    regs[k] = v
                return {'lines': else_lines, 'next': next_i}
            return {'lines': [], 'next': next_i}

    cond = left if op.get('name') == 'TEST' else (js_str(left) + ' ' + cmp_sym(op['name']) + ' ' + js_str(right))

    then_regs = dict(regs)
    then_def = set(defined)
    then_lines = emit_sl(ops, i + 1, then_end, then_regs, then_def, depth + 1,
                         upvals, child_names, closure_binds, targets)

    if inclusive_then:
        return {'lines': [sp + 'if ' + cond + ' then'] + then_lines + [sp + 'end'], 'next': else_anchor}

    if join_pc is not None:
        join_i = idx.get(join_pc)
        if join_i is None:
            return None
        if iste(ops, else_i):
            flat = emit_sl(ops, i + 1, then_end, dict(regs), set(defined), depth,
                           upvals, child_names, closure_binds, targets)
            return {'lines': flat, 'next': join_i}
        else_regs = dict(regs)
        else_def = set(defined)
        else_lines = emit_sl(ops, else_i, join_i, else_regs, else_def, depth + 1,
                             upvals, child_names, closure_binds, targets)
        lines = [sp + 'if ' + cond + ' then'] + then_lines
        if else_lines:
            lines.append(sp + 'else')
            lines.extend(else_lines)
        lines.append(sp + 'end')
        return {'lines': lines, 'next': join_i}

    if then_end > i + 1:
        if iste(ops, else_i):
            flat = emit_sl(ops, i + 1, then_end, dict(regs), set(defined), depth,
                           upvals, child_names, closure_binds, targets)
            return {'lines': flat, 'next': len(ops)}
        return {'lines': [sp + 'if ' + cond + ' then'] + then_lines + [sp + 'end'], 'next': else_i}

    if not then_lines or then_end == i + 1:
        else_regs = dict(regs)
        else_def = set(defined)
        else_lines = emit_sl(ops, else_i, len(ops), else_regs, else_def, depth,
                             upvals, child_names, closure_binds, targets)
        if iste(ops, else_i):
            return {'lines': else_lines, 'next': len(ops)}
        return {'lines': [], 'next': else_i}
    return None


def emit_sl(ops, start, to, regs, defined, depth, upvals, child_names, closure_binds, targets):
    lines = []
    idx = by_idx(ops)
    i = start
    while i < to:
        op = ops[i]
        if op.get('index') in targets:
            lines.append(ind(depth) + '::L' + js_str(op['index']) + '::')

        as_for = try_num_for(ops, i, idx, targets, regs, defined, depth, upvals, child_names, closure_binds)
        if as_for and as_for['next'] > i:
            loop_at_boundary = as_for['next'] == to + 1 and to < len(ops) and ops[to].get('name') == 'FORLOOP'
            if as_for['next'] <= to or loop_at_boundary:
                lines.extend(as_for['lines'])
                i = to if loop_at_boundary else as_for['next']
                continue

        as_gfor = try_gen_for(ops, i, idx, targets, regs, defined, depth, upvals, child_names, closure_binds)
        if as_gfor and as_gfor['next'] > i and as_gfor['next'] <= to:
            lines.extend(as_gfor['lines'])
            i = as_gfor['next']
            continue

        structured = try_if(ops, i, idx, targets, regs, defined, depth, upvals, child_names, closure_binds)
        if structured and structured['next'] > i and structured['next'] <= to:
            lines.extend(structured['lines'])
            i = structured['next']
            continue
        if op.get('name') in ('JMP', 'FORLOOP', 'FORPREP'):
            i += 1
            continue
        em = step(op, ops, i, regs, defined, depth, upvals, child_names, closure_binds)
        if em['lines']:
            lines.extend(em['lines'])
        i += 1 + (em.get('skip') or 0)
    return lines


def step(op, ops, i, regs, defined, depth, upvals, child_names, closure_binds):
    sp = ind(depth)
    A = op.get('A')
    B = op.get('B')
    C = op.get('C')
    lines = []

    def get(r):
        return regs.get(r) or reg(r)

    def setv(r, e, mark=True):
        regs[r] = e
        if mark is not False:
            defined.add(r)

    name = op.get('name')

    if name == 'MOVE':
        setv(A, get(B))
        return {'lines': lines, 'skip': 0}
    if name in ('LOADK', 'LOADBOOL'):
        if isinstance(B, str):
            if is_bin_k(B):
                return {'lines': lines, 'skip': 0}
        if B is None:
            return {'lines': lines, 'skip': 0}
        if name == 'LOADK' and isinstance(B, str) and is_id(B):
            if is_g_name(B):
                for j in range(i + 1, min(i + 8, len(ops))):
                    n = ops[j]
                    if not n:
                        break
                    if n.get('name') == 'CALL' and n.get('A') == A:
                        setv(A, g_name(B))
                        return {'lines': lines, 'skip': 0}
                    if n.get('name') in ('LOADK', 'LOADBOOL', 'GETGLOBAL', 'MOVE', 'CLOSURE', 'GETTABLE', 'SELF'):
                        continue
                    break
        setv(A, lit(B))
        return {'lines': lines, 'skip': 0}
    if name == 'LOADNIL':
        to = B if is_num(B) else A
        for r in range(int(A), int(to) + 1):
            setv(r, 'nil')
        return {'lines': lines, 'skip': 0}
    if name == 'GETUPVAL':
        setv(A, upvals[B] if isinstance(B, int) and 0 <= B < len(upvals) and upvals[B] else 'up' + js_str(B))
        return {'lines': lines, 'skip': 0}
    if name == 'GETGLOBAL':
        if isinstance(B, str) and not is_g_name(B):
            as_fn = False
            for j in range(i + 1, min(i + 5, len(ops))):
                n = ops[j]
                if not n:
                    break
                if n.get('name') == 'CALL' and n.get('A') == A:
                    as_fn = True
                    break
                if n.get('name') in ('LOADK', 'LOADBOOL', 'MOVE', 'GETUPVAL'):
                    continue
                break
            setv(A, g_name(B) if as_fn else lit(B))
        else:
            setv(A, g_name(B))
        return {'lines': lines, 'skip': 0}
    if name == 'GETTABLE':
        base = get(B)
        if is_noise(base) or base == 'nil' or base == 'null':
            return {'lines': lines, 'skip': 0}
        expr = field(base, C, op.get('isKC'))
        if is_noise(expr):
            return {'lines': lines, 'skip': 0}
        nxt = ops[i + 1] if i + 1 < len(ops) else None
        if nxt and nxt.get('name') == 'RETURN' and is_num(nxt.get('B')) and nxt['B'] <= 1:
            lines.append(sp + 'return ' + expr)
            return {'lines': lines, 'skip': 1}
        if nxt and nxt.get('name') == 'RETURN' and nxt.get('B') == 2 and nxt.get('A') == A:
            lines.append(sp + 'return ' + expr)
            return {'lines': lines, 'skip': 1}
        setv(A, expr)
        return {'lines': lines, 'skip': 0}
    if name == 'SETGLOBAL':
        lines.append(sp + g_name(B) + ' = ' + get(A))
        return {'lines': lines, 'skip': 0}
    if name == 'SETUPVAL':
        lines.append(sp + (upvals[B] if isinstance(B, int) and 0 <= B < len(upvals) and upvals[B] else 'up' + js_str(B)) + ' = ' + get(A))
        return {'lines': lines, 'skip': 0}
    if name == 'SETTABLE':
        base = get(A)
        if base == '{}':
            lines.append(sp + reg(A) + ' = {}')
            base = reg(A)
            setv(A, base)
        lines.append(sp + field(base, B, op.get('isKB')) + ' = ' + rk(C, op.get('isKC'), regs))
        return {'lines': lines, 'skip': 0}
    if name == 'NEWTABLE':
        lines.append(sp + reg(A) + ' = {}')
        setv(A, reg(A))
        return {'lines': lines, 'skip': 0}
    if name == 'SELF':
        j = i + 1
        while j < len(ops) and j <= i + 8:
            n = ops[j]
            if n.get('name') == 'CALL' and n.get('A') == A:
                break
            if (n.get('name') in ('LOADK', 'LOADBOOL', 'MOVE', 'GETGLOBAL', 'GETTABLE', 'GETUPVAL')
                    and n.get('A') != A):
                step(n, ops, j, regs, defined, depth, upvals, child_names, closure_binds)
                j += 1
                continue
            break
        if j < len(ops) and ops[j].get('name') == 'CALL' and ops[j].get('A') == A:
            setv(A + 1, get(B))
            args = call_args(ops[j], regs, defined)[1:]
            if is_id(C):
                expr = get(B) + ':' + C + '(' + ', '.join(args) + ')'
            else:
                expr = field(get(B), C, True) + '(' + ', '.join([get(B)] + args) + ')'
            lines.append(sp + reg(A) + ' = ' + expr)
            setv(A, reg(A))
            return {'lines': lines, 'skip': j - i}
        setv(A + 1, get(B))
        setv(A, field(get(B), C, op.get('isKC')))
        return {'lines': lines, 'skip': 0}
    if name in ('ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'POW'):
        sym = {'ADD': '+', 'SUB': '-', 'MUL': '*', 'DIV': '/', 'MOD': '%', 'POW': '^'}[name]
        setv(A, '(' + js_str(rk(B, op.get('isKB'), regs)) + ' ' + sym + ' ' + js_str(rk(C, op.get('isKC'), regs)) + ')')
        return {'lines': lines, 'skip': 0}
    if name == 'UNM':
        setv(A, '(-' + js_str(rk(B, op.get('isKB'), regs)) + ')')
        return {'lines': lines, 'skip': 0}
    if name == 'NOT':
        setv(A, '(not ' + js_str(rk(B, op.get('isKB'), regs)) + ')')
        return {'lines': lines, 'skip': 0}
    if name == 'LEN':
        setv(A, '(#' + js_str(rk(B, op.get('isKB'), regs)) + ')')
        return {'lines': lines, 'skip': 0}
    if name == 'CONCAT':
        if is_num(B) and is_num(C) and C > B:
            parts = [get(r) for r in range(int(B), int(C) + 1)]
            setv(A, '(' + ' .. '.join(parts) + ')')
        else:
            setv(A, '(' + get(B) + ' .. ' + get(C) + ')')
        return {'lines': lines, 'skip': 0}
    if name == 'JMP':
        if is_num(B):
            lines.append(sp + 'goto L' + js_str(B))
        return {'lines': lines, 'skip': 0}
    if name in ('EQ', 'LT', 'LE'):
        sym = cmp_sym(name)
        if is_num(B):
            left = cmpl(op, regs)
            right = cmpr(op, regs)
            if name == 'EQ' and left == right:
                skip = 1 if (i + 1 < len(ops) and ops[i + 1].get('name') == 'JMP') else 0
                return {'lines': lines, 'skip': skip}
            if is_noise(left) or is_noise(right) or left == 'nil' or right == 'nil':
                return {'lines': lines, 'skip': 0}
            if is_num(A) and A > 32 and not op.get('isKA'):
                return {'lines': lines, 'skip': 0}
            hit = eval_cmp(name, left, right)
            if hit is True:
                skip = 0
                if i + 1 < len(ops) and ops[i + 1].get('name') == 'JMP' and ops[i + 1].get('B') == B:
                    skip = 1
                return {'lines': lines, 'skip': skip}
            if hit is False:
                lines.append(sp + 'goto L' + js_str(B))
                return {'lines': lines, 'skip': 0}
            lines.append(sp + 'if ' + js_str(left) + ' ' + sym + ' ' + js_str(right) + ' then else goto L' + js_str(B) + ' end')
        return {'lines': lines, 'skip': 0}
    if name == 'TEST':
        if is_num(B):
            left = get(A)
            if is_noise(left) or left == 'nil':
                return {'lines': lines, 'skip': 0}
            lines.append(sp + 'if ' + js_str(left) + ' then else goto L' + js_str(B) + ' end')
        return {'lines': lines, 'skip': 0}
    if name == 'TESTSET':
        if not is_num(B):
            return {'lines': lines, 'skip': 0}
        jmp = B
        val = get(C if (is_num(C) and C <= 255 and not op.get('isKC')) else A)
        if is_noise(val) or val == 'nil':
            return {'lines': lines, 'skip': 0}
        lines.append(sp + 'if ' + js_str(val) + ' then')
        lines.append(sp + '  ' + reg(A) + ' = ' + js_str(val))
        lines.append(sp + 'else goto L' + js_str(jmp) + ' end')
        setv(A, reg(A))
        return {'lines': lines, 'skip': 0}
    if name == 'CALL':
        fn = get(A)
        if A not in defined and fn == reg(A):
            return {'lines': lines, 'skip': 0}
        if is_noise(fn) or fn == 'nil' or fn == 'null' or fn == '0':
            return {'lines': lines, 'skip': 0}
        if ((isinstance(fn, str) and (fn.startswith('"') or fn.startswith("'")))
                or fn == 'true' or fn == 'false'):
            return {'lines': lines, 'skip': 0}
        args = call_args(op, regs, defined)
        if len(args) >= 1:
            a0 = args[0]
            if isinstance(a0, str) and (a0.startswith('"') or a0.startswith("'")):
                looks_up = fn == 'dec'
                if not looks_up and isinstance(fn, str) and len(fn) >= 3 and fn[0] == 'u' and fn[1] == 'p':
                    looks_up = True
                    for k in range(2, len(fn)):
                        if fn[k] < '0' or fn[k] > '9':
                            looks_up = False
                            break
                nxt = ops[i + 1] if i + 1 < len(ops) else None
                feeds_print = bool(nxt and nxt.get('name') == 'CALL' and nxt.get('B') == 0 and nxt.get('A') != A)
                if looks_up or feeds_print:
                    setv(A, a0)
                    return {'lines': lines, 'skip': 0}
        filtered = []
        for i2, a in enumerate(args):
            if i2 == 0:
                filtered.append(a)
                continue
            if not isinstance(a, str):
                filtered.append(a)
                continue
            if not (a.startswith('"') or a.startswith("'")):
                filtered.append(a)
                continue
            inner = a[1:-1]
            bad = 0
            for ch in inner:
                c = ord(ch)
                if c < 32 or c >= 127:
                    bad += 1
            if not (len(inner) >= 2 and bad / len(inner) >= 0.3):
                filtered.append(a)
        expr = js_str(fn) + '(' + ', '.join(js_str(a) for a in filtered) + ')'
        if C == 1:
            lines.append(sp + expr)
            return {'lines': lines, 'skip': 0}
        lines.append(sp + reg(A) + ' = ' + expr)
        setv(A, reg(A))
        return {'lines': lines, 'skip': 0}
    if name == 'TFORLOOP':
        if op.get('mode') == 3 and is_num(B):
            return {'lines': lines, 'skip': 0}
        fn = get(A)
        args = call_args({'A': A, 'B': B if (is_num(B) and B <= 32) else 2, 'C': C}, regs, defined)
        if fn and fn != reg(A) and not is_noise(fn):
            nret = min(C, 4) if (is_num(C) and C > 1) else 3
            lines.append(sp + reg(A) + ' = ' + js_str(fn) + '(' + ', '.join(args) + ')')
            setv(A, reg(A))
            for r in range(1, int(nret)):
                setv(A + r, reg(A + r))
                defined.add(A + r)
        return {'lines': lines, 'skip': 0}
    if name == 'TAILCALL':
        args = call_args(op, regs, defined)
        lines.append(sp + 'return ' + get(A) + '(' + ', '.join(args) + ')')
        return {'lines': lines, 'skip': 0}
    if name == 'RETURN':
        if B == 1 or B == 0:
            lines.append(sp + 'return')
        elif is_num(B) and B > 1:
            vals = [get(r) for r in range(int(A), int(A + B) - 1)]
            lines.append(sp + 'return ' + ', '.join(vals))
        else:
            lines.append(sp + 'return ' + get(A))
        return {'lines': lines, 'skip': 0}
    if name == 'CLOSURE':
        nm = child_names.get(B) or 'f' + js_str(B)
        ups = []
        upv = op.get('upvals') or []
        for u, uv in enumerate(upv):
            ups.append(get(uv['idx']) if uv['isLocal'] else (upvals[uv['idx']] if isinstance(uv['idx'], int) and 0 <= uv['idx'] < len(upvals) and upvals[uv['idx']] else 'up' + js_str(uv['idx'])))
        closure_binds.append({'idx': B, 'ups': ups})

        fname = nm
        nxt = ops[i + 1] if i + 1 < len(ops) else None
        if (nxt and nxt.get('name') == 'SETGLOBAL' and nxt.get('A') == A
                and isinstance(nxt.get('B'), str) and is_id(nxt['B'])):
            fname = nxt['B']
            child_names[B] = fname
            setv(A, fname)
            return {'lines': lines, 'skip': 1}
        setv(A, nm)
        return {'lines': lines, 'skip': 0}
    if name == 'SETLIST':
        n = B if (is_num(B) and B > 0) else 32
        parts = []
        for r in range(int(A) + 1, int(A) + int(n) + 1):
            if r not in regs and r not in defined:
                break
            parts.append(get(r))
        if parts:
            expr = '{ ' + ', '.join(parts) + ' }'
            lines.append(sp + reg(A) + ' = ' + expr)
            setv(A, expr)
        else:
            cur = get(A)
            setv(A, '{}' if cur == '{}' else cur)
        return {'lines': lines, 'skip': 0}
    if name in ('FORPREP', 'FORLOOP'):
        return {'lines': lines, 'skip': 0}
    if name == 'VARARG':
        setv(A, '...')
        return {'lines': lines, 'skip': 0}
    return {'lines': lines, 'skip': 0}


# ---------------------------------------------------------------------------
# numeric evaluation helpers
# ---------------------------------------------------------------------------


def parse_num(t):
    if not t:
        return None
    i = 0
    neg = False
    if char(t, i) == '-':
        neg = True
        i += 1
    if i >= len(t) or t[i] < '0' or t[i] > '9':
        return None
    j = i
    while j < len(t) and '0' <= t[j] <= '9':
        j += 1
    if char(t, j) == '.':
        j += 1
        if j >= len(t) or t[j] < '0' or t[j] > '9':
            return None
        while j < len(t) and '0' <= t[j] <= '9':
            j += 1
    if j != len(t):
        return None
    n = float(t[i:]) if '.' in t[i:] else int(t[i:])
    return -n if neg else n


def parse_bin(t, op):
    s = t.strip()
    if char(s, 0) == '(' and char(s, len(s) - 1) == ')':
        s = s[1:-1].strip()
    for i in range(1, len(s)):
        if s[i] == op[0] and (len(op) == 1 or s[i:i + len(op)] == op):
            left = parse_num(s[:i].strip())
            right = parse_num(s[i + len(op):].strip())
            if left is not None and right is not None:
                return left + right if op == '+' else left - right
    return None


def parse_stat(expr):
    if is_num(expr):
        return expr
    if not isinstance(expr, str):
        return None
    t = expr.strip()
    n = parse_num(t)
    if n is not None:
        return n
    if t == 'true':
        return True
    if t == 'false':
        return False
    add = parse_bin(t, '+')
    if add is not None:
        return add
    sub = parse_bin(t, '-')
    if sub is not None:
        return sub
    return None


def _eq(a, b):
    """JS ``===`` semantics for numbers/booleans/strings."""
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if is_num(a) and is_num(b):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    if a is None or b is None:
        return a is None and b is None
    return type(a) is type(b) and a == b


def eval_cmp(name, left, right):
    a = parse_stat(left)
    b = parse_stat(right)
    if a is None or b is None:
        return None
    if isinstance(a, bool) or isinstance(b, bool):
        pass
    if name == 'EQ':
        return _eq(a, b)
    if name == 'LT':
        return a < b
    if name == 'LE':
        return a <= b
    return None


# ---------------------------------------------------------------------------
# program reconstruction
# ---------------------------------------------------------------------------


def is_pln_line(s):
    if not s:
        return False
    c0 = ord(s[0])
    if not ((65 <= c0 <= 90) or (97 <= c0 <= 122) or c0 == 95):
        return False
    for ch in s[1:]:
        c = ord(ch)
        if not ((65 <= c <= 90) or (97 <= c <= 122) or (48 <= c <= 57) or c == 95):
            return False
    return True


def fn_nm_of(src):
    i = src.find('function ')
    if i < 0:
        return None
    j = i + 9
    if src.startswith('local function ', i):
        j = i + 15
    k = j
    while k < len(src) and src[k] != '(':
        k += 1
    name = src[j:k].strip()
    return name or None


def is_empty_fn(src):
    flat = col_ws(src).strip()
    if 'while true do' not in flat:
        return False
    if 'while true do end' in flat:
        return True
    if 'while true do {} end' in flat:
        return True
    if 'while true do table.insert({}) end' in flat:
        return True
    a = flat.find('while true do')
    if a < 0:
        return False
    b = flat.rfind('end')
    if b <= a:
        return False
    body = flat[a + 13:b].strip()
    return not body or body == '{}' or body == 'table.insert({})'


def def_ups(proto, opcode_map, closure_local_op):
    ops = ann_pr(proto, opcode_map, closure_local_op)
    mx = -1
    for op in ops:
        if op.get('name') in ('GETUPVAL', 'SETUPVAL') and is_num(op.get('B')) and op['B'] > mx:
            mx = op['B']
    return ['up' + str(i) for i in range(int(mx) + 1)]


def recon_pr(proto, opcode_map, closure_local_op, fname, upvals, depth):
    ops = ann_pr(proto, opcode_map, closure_local_op)
    ops = clean_cfg(ops)
    targets = jmp_tgts(ops)
    idx = by_idx(ops)
    regs = {}
    defined = set()
    for p in range(int(proto.params or 0)):
        regs[p] = reg(p)
        defined.add(p)

    child_names = {}
    for i, child in enumerate(proto.prototypes):
        if child:
            child_names[i] = fname + '_f' + str(i)

    closure_binds = []
    lines = []
    sp = ind(depth)
    bsp = ind(depth + 1)

    i = 0
    while i < len(ops):
        op = ops[i]

        if op.get('index') in targets:
            lines.append(bsp + '::L' + js_str(op['index']) + '::')

        as_for = try_num_for(ops, i, idx, targets, regs, defined, depth + 1,
                             upvals, child_names, closure_binds)
        if as_for:
            lines.extend(as_for['lines'])
            i = as_for['next']
            continue

        as_gfor = try_gen_for(ops, i, idx, targets, regs, defined, depth + 1,
                              upvals, child_names, closure_binds)
        if as_gfor:
            lines.extend(as_gfor['lines'])
            i = as_gfor['next']
            continue

        structured = try_if(ops, i, idx, targets, regs, defined, depth + 1,
                            upvals, child_names, closure_binds)
        if structured:
            lines.extend(structured['lines'])
            i = structured['next']
            continue

        em = step(op, ops, i, regs, defined, depth + 1, upvals, child_names, closure_binds)
        if em['lines']:
            lines.extend(em['lines'])
        i += 1 + (em.get('skip') or 0)

    body = fin_lines(tidy(fold_ln(lines)))
    body_text = '\n'.join(body)
    nested = []
    for pi, child in enumerate(proto.prototypes):
        if not child:
            continue
        cname = child_names[pi]
        child_ops = clean_cfg(ann_pr(child, opcode_map, closure_local_op))
        child_usage = an_pr_use(child, child_ops)
        if child_usage['xorStub'] and not child_usage['interesting']:
            continue
        bound = any(b['idx'] == pi for b in closure_binds)
        if cname not in body_text and not bound:
            continue
        matches = [b for b in closure_binds if b['idx'] == pi]
        bind = matches[-1] if matches else None
        ups = bind['ups'] if bind else def_ups(child, opcode_map, closure_local_op)
        src = recon_pr(child, opcode_map, closure_local_op, cname, ups, depth + 1)
        if is_empty_fn(src):
            continue
        nested.append(src)

    kept_names = set()
    for n in nested:
        k = fn_nm_of(n)
        if k:
            kept_names.add(k)

    body2 = []
    for l in body:
        t = l.strip()
        if char(t, 0) != 'r':
            body2.append(l)
            continue
        spn = t.find(' = ')
        if spn < 0:
            body2.append(l)
            continue
        rhs = t[spn + 3:]
        if is_pln_line(rhs) and rhs.startswith(fname) and rhs not in kept_names:
            continue
        body2.append(l)

    params = [reg(p) for p in range(int(proto.params or 0))]

    early = []
    late = []
    for l in body2:
        t = l.strip()
        plain = None
        if char(t, 0) == 'r':
            j = 1
            while j < len(t) and '0' <= t[j] <= '9':
                j += 1
            if t[j:j + 3] == ' = ':
                plain = t[j + 3:]
        if plain is not None and '(' not in plain and is_pln_line(plain):
            early.append(l)
        elif plain is not None and '(' not in plain and plain.startswith('{'):
            early.append(l)
        else:
            late.append(l)

    out = [sp + 'local function ' + fname + '(' + ', '.join(params) + ')'] + early + nested + late + [sp + 'end']
    return '\n'.join(out)


def isatr(proto):
    names = {c for c in (proto.constants or []) if isinstance(c, str)}
    return {'string', 'match', 'pcall', 'tonumber'} <= names


def islcp(proto):
    names = {c for c in (proto.constants or []) if isinstance(c, str)}
    return ':%d+:' in names and '%d+' in names


def findpp(root):
    if not root or not isatr(root):
        return None
    mid = next((p for p in (root.prototypes or []) if p and islcp(p)), None)
    if not mid:
        return None
    payload = next((p for p in (mid.prototypes or []) if p), None)
    return payload or None


def isep(proto):
    if not proto:
        return True
    consts = (proto.constants or [])[1:]
    useful = [c for c in consts if isinstance(c, str) and len(c) > 1]
    if useful:
        return False
    ops = [i for i in (proto.instructions or []) if i and not i.skipped]
    return len(ops) <= 8


def recon_prog(root, opcode_map, closure_local_op):
    payload = findpp(root)
    if payload:
        if isep(payload):
            return '\n'.join([
                'local function main()',
                'end',
                '',
                'return main()',
                '',
            ])
        body = recon_pr(payload, opcode_map, closure_local_op, 'main', [], 0)
        return '\n'.join([body, '', 'return main()', ''])

    leaf = findil(root, opcode_map, closure_local_op)
    if leaf and leaf is not root:
        body = recon_pr(leaf, opcode_map, closure_local_op, 'main', [], 0)
        return '\n'.join([body, '', 'return main()', ''])

    return '\n'.join([recon_pr(root, opcode_map, closure_local_op, 'main', [], 0), '', 'return main()', ''])


def findil(root, opcode_map, closure_local_op):
    best = {'p': None}
    best_score = {'v': 0}

    def score(p):
        ops = clean_cfg(ann_pr(p, opcode_map, closure_local_op))
        return an_pr_use(p, ops)['score']

    def walk(p):
        sc = score(p)
        kids = [k for k in (p.prototypes or []) if k]
        if sc > best_score['v'] and (not kids or sc >= 20):
            best_score['v'] = sc
            best['p'] = p
        for k in kids:
            walk(k)

    walk(root)
    if not best['p'] or best['p'] is root or best_score['v'] < 15:
        return None
    root_score = score(root)
    if root_score >= best_score['v']:
        return None
    root_usage = an_pr_use(root, clean_cfg(ann_pr(root, opcode_map, closure_local_op)))
    if not root_usage['xorStub'] and root_score >= 8:
        return None
    return best['p']


def sum_cfg(root, opcode_map, closure_local_op):
    total = {'jmps': 0, 'removed': 0}

    def walk(p):
        ops = ann_pr(p, opcode_map, closure_local_op)
        st = jmp_stats(ops)
        total['jmps'] += st['jmps']
        total['removed'] += st['removed']
        for c in p.prototypes:
            if c:
                walk(c)

    walk(root)
    return total
