"""Virtual machine analysis: dispatch tree discovery and opcode naming."""

from __future__ import annotations

from .luaio import (
    char, sub, is_num, fold_const, find_blk_end, eval_ok, sk_str, next_kw,
    sk_ws, rd_id, rd_num, is_dig, is_ws, wd_at, find_wd, str_ws, col_ws,
)

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def _instr(proto, i):
    """JS-style ``proto.instructions[i]`` (``None`` when out of range)."""
    if not proto or i is None:
        return None
    arr = proto.instructions
    if isinstance(i, int) and 0 <= i < len(arr):
        return arr[i]
    return None


def _n_instr(proto):
    return len(proto.instructions) if proto else 1


def _truthy(v):
    if v is None or v is False:
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v != 0 and v == v
    if isinstance(v, str):
        return v != ''
    return True


def rd_var(s, i):
    if char(s, i) != 'v' or not is_dig(char(s, i + 1)):
        return None
    j = i + 1
    while j < len(s) and is_dig(s[j]):
        j += 1
    return {'name': s[i:j], 'end': j}


def strip_n(body):
    src = fold_const(str(body) if body is not None else '')
    out = []
    i = 0
    n = len(src)
    while i < n:
        if wd_at(src, i, 'local'):
            j = sk_ws(src, i + 5)
            ident = rd_id(src, j)
            if ident and ident['name'][0] == 'v' and is_dig(ident['name'][1] if len(ident['name']) > 1 else ''):
                j = sk_ws(src, ident['end'])
                if char(src, j) == '=':
                    j = sk_ws(src, j + 1)
                    if is_dig(char(src, j)):
                        while j < n and is_dig(src[j]):
                            j += 1
                        if char(src, j) == ';':
                            j += 1
                        i = j
                        continue
                elif char(src, j) == ';' or is_ws(char(src, j)) or j >= n:
                    if char(src, j) == ';':
                        j += 1
                    i = j
                    continue

        if src[i:i + 13] == 'while true do':
            i += 13
            continue

        if wd_at(src, i, 'if'):
            j = sk_ws(src, i + 2)
            if char(src, j) == '(':
                left = rd_var(src, sk_ws(src, j + 1))
                if left:
                    j = sk_ws(src, left['end'])
                    if char(src, j) == '=' and char(src, j + 1) == '=':
                        j = sk_ws(src, j + 2)
                        if is_dig(char(src, j)):
                            while j < n and is_dig(src[j]):
                                j += 1
                            j = sk_ws(src, j)
                            if char(src, j) == ')':
                                j = sk_ws(src, j + 1)
                                if wd_at(src, j, 'then'):
                                    i = j + 4
                                    continue

        if wd_at(src, i, 'break'):
            j = i + 5
            if char(src, j) == ';':
                j += 1
            j = sk_ws(src, j)
            if wd_at(src, j, 'end'):
                i = j + 3
                continue

        if wd_at(src, i, 'end'):
            i += 3
            continue

        out.append(src[i])
        i += 1
    return col_ws(''.join(out))


def cmpct(body):
    return str_ws(strip_n(body))


def has(s, part):
    return s is not None and part in s


def lk_clos_call(c):
    start = 0
    while start < len(c):
        mark = c.find('[2]]=v', start)
        if mark < 0:
            return False
        v = rd_var(c, mark + 5)
        if not v or char(c, v['end']) != '(':
            start = mark + 6
            continue
        a = rd_var(c, v['end'] + 1)
        if not a:
            start = mark + 6
            continue
        if char(c, a['end']) == '[':
            return True
        if char(c, a['end']) == ',':
            b = rd_var(c, a['end'] + 1)
            if b and char(c, b['end']) == ',':
                d = rd_var(c, b['end'] + 1)
                if d and char(c, d['end']) == ')':
                    return True
        start = mark + 6
    return False


def is_set_l(raw, text, c):
    if not (has(text, 'for ') or has(c, 'for')):
        return False
    if has(c, '[2]]=v') or has(raw, 'setmetatable'):
        return False
    if (has(c, ',v') or has2_v_asg(c)) and has(c, ']('):
        return False
    if has(raw, 'insert(') or has(raw, 'v15(') or has(raw, 'v6('):
        return True
    if has(c, ']=v') and (has(c, '+1') or has(c, '-1') or has(c, '+v') or has_plus_v(c)):
        return True
    if has(c, ']=v') and has(c, '+') and has(c, '[2]'):
        return True
    return False


def is_self(c):
    i = 0
    while i < len(c):
        v = rd_var(c, i)
        if not v or char(c, v['end']) != '[':
            i += 1
            continue
        j = v['end'] + 1
        if char(c, j) == '#':
            i = v['end']
            continue
        inner = rd_var(c, j)
        if inner and c[inner['end']:inner['end'] + 4] == '+1]=':
            return True
        plus = c.find('+1]=', j)
        if j < plus < j + 20 and char(c, plus - 1) != '#':
            if '#' not in c[j:plus]:
                return True
        i = v['end']
    return False


def is_jmp(c):
    a = rd_var(c, 0)
    if not a or char(c, a['end']) != '=':
        return False
    b = rd_var(c, a['end'] + 1)
    if not b:
        return False
    tail = c[b['end']:]
    return tail == '[3]' or tail == '[3];'


def is_test(text, c):
    if not has(text, 'if') or not has(text, 'else') or not has(text, 'then'):
        return False
    for i, ch in enumerate(c):
        if ch in ('<', '>', '~'):
            return False
        if ch == '=' and char(c, i + 1) == '=':
            return False
    return has(c, '[2]]')


def match_asg_idx(c):
    a = rd_var(c, 0)
    if not a or char(c, a['end']) != '[':
        return None
    b = rd_var(c, a['end'] + 1)
    if not b or c[b['end']:b['end'] + 4] != '[2]]':
        return None
    i = b['end'] + 4
    if char(c, i) != '=':
        return None
    i += 1
    d = rd_var(c, i)
    if not d or char(c, d['end']) != '[':
        return None
    e = rd_var(c, d['end'] + 1)
    if not e:
        return None
    rest = c[e['end']:]
    if rest in ('[3]', '[3];', '[3]]', '[3]];'):
        return {'left': a['name'], 'right': d['name']}
    return None


def is_load_k(c):
    a = rd_var(c, 0)
    if not a or char(c, a['end']) != '[':
        return False
    b = rd_var(c, a['end'] + 1)
    if not b or c[b['end']:b['end'] + 4] != '[2]]':
        return False
    i = b['end'] + 4
    if char(c, i) != '=':
        return False
    d = rd_var(c, i + 1)
    if not d:
        return False
    rest = c[d['end']:]
    return rest == '[3]' or rest == '[3];'


def is_set_t(c):
    if not has(c, ']['):
        return False
    eq = c.find(']=')
    if eq < 0:
        return False
    closes = 0
    for i in range(eq + 1):
        if c[i] == ']':
            closes += 1
    return closes >= 2


def is_call(c, text):
    if has(c, ']('):
        return True
    if has(text, 'for ') and has(c, '('):
        for i in range(len(c) - 2):
            a = rd_var(c, i)
            if not a or char(c, a['end']) != ',':
                continue
            b = rd_var(c, a['end'] + 1)
            if b and char(c, b['end']) == '=':
                return True
    return False


def bin_op(c, op):
    return (']' + op + 'v') in c


def has2_v_asg(c):
    i = 0
    while i < len(c):
        if c[i] != 'v':
            i += 1
            continue
        a = rd_var(c, i)
        if not a or char(c, a['end']) != ',':
            i += 1
            continue
        b = rd_var(c, a['end'] + 1)
        if b and char(c, b['end']) == '=':
            return True
        i = a['end']
    return False


def has_plus_v(c):
    i = 0
    while i < len(c):
        if c[i] == '+' and char(c, i + 1) == 'v':
            v = rd_var(c, i + 1)
            if v and char(c, v['end']) == ']':
                return True
        i += 1
    return False


def has_abc_add(c):
    i = 0
    while i < len(c):
        a = rd_id(c, i)
        if not a:
            i += 1
            continue
        if char(c, a['end']) != '=':
            i = a['end']
            continue
        b = rd_id(c, a['end'] + 1)
        if not b or char(c, b['end']) != '+':
            i = a['end']
            continue
        d = rd_id(c, b['end'] + 1)
        if d:
            return True
        i = a['end']
    return False


def has_for_add(c):
    if has(c, ']+v') or has(c, ']+='):
        return True
    if has_abc_add(c) and has(c, '+2'):
        return True
    return False


def is_for_l(c, text):
    if not has(text, 'if'):
        return False
    if not has(c, '+2') or not has(c, '+1') or not has(c, '+3'):
        return False
    if not has(c, '>0') and not has(c, '<0'):
        return False
    if not has(c, '[3]') and not has(c, '[3];'):
        return False
    if not has_for_add(c):
        return False
    return True


def is_for_p(c, text):
    if not has(c, '+2'):
        return False
    if has(c, ']-v') or has(c, ']-='):
        if not has(c, '[3]') and not has(text, 'if'):
            return False
        return has(c, '[2]]') or has(c, '[2];') or has(c, '[2]=')
    if not has(text, 'if'):
        return False
    if not has(c, '+1') or not has(c, '+3'):
        return False
    if not has(c, '>0') and not has(c, '<0'):
        return False
    if not has(c, '[3]') and not has(c, '[3];'):
        return False
    if has_for_add(c):
        return False
    return True


def is_set_g(c):
    eq = c.find(']=')
    if eq < 0:
        return False
    left = c[:eq + 1]
    if '[3]' not in left:
        return False
    if '][' in left:
        return False
    right = c[eq + 2:]
    v = rd_var(right, 0)
    if not v or char(right, v['end']) != '[':
        return False
    idx = right[v['end']:]
    return idx.startswith('[') and '[2]' in idx


def is_set_u(c):
    eq = c.find(']=')
    if eq < 0:
        return False
    left = c[:eq + 1]
    if '[3]' not in left:
        return False
    right = c[eq + 2:]
    v = rd_var(right, 0)
    if not v or char(right, v['end']) != '[':
        return False
    if '[2]' not in right[v['end']:]:
        return False
    return '][1]' in left or '][2]' in left


def is_tset(text, c):
    if not has(text, 'if') or not has(text, 'else'):
        return False
    if not has(c, '[2]]=') or not has(c, '[3]'):
        return False
    if has(c, '<') or has(c, '>') or has(c, '=='):
        return False
    return has(c, '[2]]=v')


def is_unm(c):
    return has(c, ']=-v') or has(c, ']=-(') or has(c, '[2]]=-')


def is_varg(c):
    return has(c, '...')


def cls_h(body):
    raw = fold_const(str(body) if body is not None else '')
    text = strip_n(raw)
    c = cmpct(raw)

    if has(text, 'do return'):
        if not has(text, '('):
            return 'RETURN'
        ri = c.find('returnv')
        if ri >= 0:
            after = c[ri + 6:]
            v = rd_var(after, 0)
            if v and char(after, v['end']) == '[':
                return 'TAILCALL'
            if v and char(after, v['end']) == '(' and rd_var(after, v['end'] + 1):
                return 'RETURN'
        return 'TAILCALL'

    if has(raw, 'setmetatable'):
        return 'CLOSURE'
    if lk_clos_call(c):
        return 'CLOSURE'
    if is_set_l(raw, text, c):
        return 'SETLIST'

    if has(c, '..'):
        return 'CONCAT'

    if has(text, 'for') and has(c, '](') and has(c, 'if') and has(c, ',v'):
        return 'TFORLOOP'

    if is_self(c):
        return 'SELF'
    if is_varg(c):
        return 'VARARG'
    if is_unm(c):
        return 'UNM'

    if has(c, '=nil') and has(text, 'for'):
        return 'LOADNIL'
    if has(c, '={}') and len(c) < 80 and not has(text, 'for') and not has(text, 'while'):
        return 'NEWTABLE'
    if is_jmp(c):
        return 'JMP'

    if is_for_l(c, text):
        return 'FORLOOP'
    if is_for_p(c, text):
        return 'FORPREP'

    if (has(text, 'if') and has(c, '[2]') and has(c, '[4]') and has(c, '[3]')
            and (has(c, '+1') or has(text, 'else'))):
        if has(c, ']==') or has(c, ']==v') or (has(c, '==') and not has(c, '<') and not has(c, '>')):
            return 'EQ'
        if has(c, '<=') or has(c, '>='):
            return 'LE'
        if has(c, '<') or has(c, '>'):
            return 'LT'
    if has(text, 'if') and has(c, '+1') and has(c, '[3]'):
        if has(c, '==') or has(c, '~='):
            return 'EQ'
        if has(c, '<=') or has(c, '>='):
            return 'LE'
        if has(c, '<') or has(c, '>'):
            return 'LT'
    if has(c, '[v') and has(c, '[2]]') and has(c, '=v') and (has(c, '+1') or has(c, '[3]')):
        if has(text, 'if') and (has(c, '==') or has(c, '~=')):
            return 'EQ'
        if has(text, 'if') and (has(c, '<=') or has(c, '>=')):
            return 'LE'
        if has(text, 'if') and (has(c, '<') or has(c, '>')):
            return 'LT'
    if has(c, '==v') and has(c, '[4]') and has(c, '+1'):
        return 'EQ'

    if is_tset(text, c):
        return 'TESTSET'
    if is_test(text, c):
        return 'TEST'

    if has(c, '~=0') and has(c, '[2]]=') and has(c, '[3]') and not has(c, ']('):
        return 'LOADBOOL'

    if has(c, '[2]]=') and has(c, '[3]][') and has(c, '[4]]'):
        return 'GETTABLE'
    if has(c, '=v') and has(c, '[3]][') and has(c, '[4]]'):
        return 'GETTABLE'
    if has(c, '[2]]=') and has(c, '[3]][') and has(c, '[4]'):
        return 'GETTABLE'

    if is_set_t(c):
        return 'SETTABLE'
    if is_set_u(c):
        return 'SETUPVAL'
    if is_set_g(c):
        return 'SETGLOBAL'

    mv = match_asg_idx(c)
    if mv:
        return 'MOVE' if mv['left'] == mv['right'] else 'GETGLOBAL_OR_UPVAL'

    if is_load_k(c):
        return 'LOADK'
    if is_call(c, text):
        return 'CALL'

    if bin_op(c, '+'):
        return 'ADD'
    if bin_op(c, '-'):
        return 'SUB'
    if bin_op(c, '*'):
        return 'MUL'
    if bin_op(c, '/'):
        return 'DIV'
    if bin_op(c, '%'):
        return 'MOD'
    if bin_op(c, '^'):
        return 'POW'
    if has(c, '=#v') or has(c, '=#('):
        return 'LEN'
    if has(text, 'not '):
        return 'NOT'
    if has(c, '={}') and not has(c, '](') and not has(text, 'setmetatable'):
        return 'NEWTABLE'

    return 'UNKNOWN'


def ref_op_nm(name, body, ctx=None):
    ctx = ctx or {}
    if name != 'GETGLOBAL_OR_UPVAL':
        return name
    c = cmpct(body)
    if ctx.get('upValVar') and ('=' + ctx['upValVar'] + '[') in c:
        return 'GETUPVAL'
    if ctx.get('envVar') and ('=' + ctx['envVar'] + '[') in c:
        return 'GETGLOBAL'
    eq = c.find(']=')
    if eq >= 0:
        v = rd_var(c, eq + 2)
        if v and char(c, v['end']) == '[':
            if v['name'] == ctx.get('upValVar'):
                return 'GETUPVAL'
            if v['name'] == ctx.get('envVar'):
                return 'GETGLOBAL'
    return 'GETGLOBAL'


def is_id_str(s):
    if not isinstance(s, str) or not s or len(s) > 64:
        return False
    c0 = ord(s[0])
    if not ((65 <= c0 <= 90) or (97 <= c0 <= 122) or c0 == 95):
        return False
    for ch in s[1:]:
        c = ord(ch)
        if not ((65 <= c <= 90) or (97 <= c <= 122) or (48 <= c <= 57) or c == 95):
            return False
    return True


def is_bin_k(s):
    if not isinstance(s, str) or len(s) < 2:
        return False
    bad = 0
    for ch in s:
        c = ord(ch)
        if c < 9 or (13 < c < 32) or c >= 127:
            bad += 1
    return bad / len(s) >= 0.3


def is_g_name(s):
    if not isinstance(s, str) or not s:
        return False
    if is_bin_k(s):
        return False
    return is_id_str(s)


def has_call_soon(ins, proto):
    if not proto or ins._index is None:
        return False
    start = ins._index
    for i in range(start + 1, min(start + 8, _n_instr(proto))):
        n = _instr(proto, i)
        if not n or n.skipped:
            continue
        if (n.mode == 0 or n.mode is None) and n.A == ins.A and not n.isKB and not n.isKC:
            if is_num(n.B) or n.B is None:
                return True
        if n.mode == 2:
            return False
    return False


def feeds_global_use(ins, proto):
    if not proto or ins._index is None:
        return False
    if has_call_soon(ins, proto):
        return True
    start = ins._index
    for i in range(start + 1, min(start + 8, _n_instr(proto))):
        n = _instr(proto, i)
        if not n or n.skipped:
            continue
        if n.mode == 2:
            return False
        if (n.mode == 0 or n.mode is None) and n.isKC and is_num(n.B) and n.B == ins.A:
            return True
        if n.A == ins.A and n.mode == 1 and n.isKB:
            continue
        if is_num(n.A) and n.A == ins.A:
            continue
        break
    return False


def lk_arg_mv(ins, proto):
    if not proto or ins._index is None:
        return False
    for i in range(ins._index + 1, min(ins._index + 4, _n_instr(proto))):
        n = _instr(proto, i)
        if not n or n.skipped:
            continue
        if n.mode == 2:
            return False
        if (n.mode == 0 or n.mode is None) and not n.isKB and not n.isKC and is_num(n.B):
            if n.A == ins.A - 1 and n.B == 2:
                return True
            if n.A == ins.A and n.B >= 2:
                return False
        break
    for i in range(ins._index - 1, max(1, ins._index - 4) - 1, -1):
        n = _instr(proto, i)
        if not n or n.skipped:
            continue
        if n.mode == 1 and n.isKB and n.A == ins.A - 1:
            return True
        break
    return False


def lk_call(ins, proto):
    if not proto or ins._index is None:
        return False
    b_num = ins.B if is_num(ins.B) else -1

    for i in range(ins._index - 1, max(1, ins._index - 8) - 1, -1):
        n = _instr(proto, i)
        if not n or n.skipped:
            continue
        if n.A != ins.A:
            if n.mode == 1 and n.isKB:
                continue
            if n.mode == 0 and not n.isKB and not n.isKC:
                continue
            if n.mode == 2:
                return False
            continue
        if n.mode == 0 and n.isKC:
            return True
        if n.mode == 1 and n.isKB:
            return True
        if n.mode == 3:
            return True
        break

    if b_num >= 2:
        arg_loads = 0
        for i in range(ins._index - 1, max(1, ins._index - 8) - 1, -1):
            n = _instr(proto, i)
            if not n or n.skipped:
                continue
            if n.mode == 2:
                break
            if is_num(n.A) and n.A > ins.A and n.A <= ins.A + min(b_num, 8) - 1:
                if n.mode == 1 and n.isKB:
                    arg_loads += 1
                if n.mode == 0 and n.isKC:
                    arg_loads += 1
            if n.A == ins.A and n.mode == 1 and n.isKB:
                return True
        if arg_loads >= 1:
            return True
    return False


def lk_up_follow(ins, proto, closure_local_op, opcode_map):
    if not proto or not is_num(ins.B) or not is_num(ins.C):
        return False
    if ins.C <= 0 or ins.C > 32:
        return False
    if not _proto_at(proto, ins.B):
        return False
    for u in range(int(ins.C)):
        next_i = ins._index + 1 + u
        nxt = _instr(proto, next_i)
        if not nxt or nxt.skipped:
            return False
        if closure_local_op is not None and nxt.opcode == closure_local_op:
            continue
        entry = (opcode_map or {}).get(nxt.opcode)
        n = (entry or {}).get('name') or ''
        if n == 'MOVE' or n == 'GETUPVAL':
            continue
        if nxt.mode == 0 and not nxt.isKB and not nxt.isKC and is_num(nxt.B):
            continue
        return False
    return True


def _proto_at(proto, idx):
    if not proto or not isinstance(idx, int):
        return None
    arr = proto.prototypes
    if 0 <= idx < len(arr):
        return arr[idx]
    return None


def shp_guess(ins, proto, closure_local_op, opcode_map):
    if not ins or ins.skipped:
        return None

    A, B, C, mode, is_kb, is_kc = ins.A, ins.B, ins.C, ins.mode, ins.isKB, ins.isKC
    b_str = isinstance(B, str)
    b_num = is_num(B)
    c_num = is_num(C)
    c_str = isinstance(C, str)
    c_nil = C is None

    if mode == 2 and b_num:
        return {'name': 'JMP', 'conf': 95}

    if mode == 3 and b_num and c_num is not None:
        if _proto_at(proto, B) and C >= 0 and C <= 255 and not is_kc and not is_kb:
            return {'name': 'CLOSURE', 'conf': 90}
        if is_kc or is_kb:
            return {'name': 'EQ', 'conf': 55}
        if proto and ins._index is not None:
            nxt = _instr(proto, ins._index + 1)
            if nxt and not nxt.skipped and nxt.mode == 2 and is_num(nxt.B):
                return {'name': 'EQ', 'conf': 75}
        if B > 0 and proto and B < _n_instr(proto) and C == 0:
            return {'name': 'JMP', 'conf': 55}
        return {'name': 'EQ', 'conf': 50}

    if mode == 1 and is_kb and c_nil:
        if b_str:
            if is_bin_k(B):
                return {'name': 'LOADK', 'conf': 95}
            if is_id_str(B) and feeds_global_use(ins, proto):
                return {'name': 'GETGLOBAL', 'conf': 90}
            return {'name': 'LOADK', 'conf': 88}
        if isinstance(B, bool):
            return {'name': 'LOADBOOL', 'conf': 90}
        if b_num:
            return {'name': 'LOADK', 'conf': 85}
        if B is None:
            return {'name': 'LOADNIL', 'conf': 70}

    if mode == 0 and not is_kb and not is_kc and b_num and (C == 0 or c_nil) and B >= A and B <= A + 32:
        if lk_call(ins, proto):
            return {'name': 'CALL', 'conf': 80}
        if B == A:
            return {'name': 'LOADNIL', 'conf': 70}
        if B - A <= 8:
            return {'name': 'LOADNIL', 'conf': 55}

    if mode == 0 and is_kb and is_kc:
        return {'name': 'SETTABLE', 'conf': 92}

    if mode == 0 and is_kc and not is_kb and b_num:
        if A == B and c_str and is_id_str(C) and has_call_soon(ins, proto):
            return {'name': 'SELF', 'conf': 88}
        return {'name': 'GETTABLE', 'conf': 90}

    if mode == 0 and is_kb and not is_kc and (b_num or isinstance(B, str) or isinstance(B, bool)) and c_num:
        return {'name': 'ADD', 'conf': 45}

    if b_num and c_num and lk_up_follow(ins, proto, closure_local_op, opcode_map):
        return {'name': 'CLOSURE', 'conf': 80}

    if mode == 0 and not is_kb and not is_kc and b_num:
        if B == 0 and c_num and C >= 1 and C <= 32:
            return {'name': 'CALL', 'conf': 72}
        if B == 0 and (C == 0 or c_nil):
            return {'name': 'MOVE', 'conf': 25}
        if B == 0 and C == 1:
            return {'name': 'CALL', 'conf': 50}
        if B == 1 and (C == 0 or c_nil or C == 1):
            if lk_arg_mv(ins, proto):
                return {'name': 'MOVE', 'conf': 70}
            return {'name': 'CALL', 'conf': 48}
        if 2 <= B <= 32:
            if lk_call(ins, proto):
                return {'name': 'CALL', 'conf': 75}
            if c_nil or C == 0 or (c_num and 1 <= C <= 32):
                return {'name': 'CALL', 'conf': 55}
        if B <= 255 and (c_nil or C == 0):
            return {'name': 'MOVE', 'conf': 50}

    return None


def is_cmp_op(n):
    return n in ('EQ', 'LT', 'LE', 'TEST')


def is_strong_map(n):
    return n in ('FORLOOP', 'FORPREP', 'SETTABLE', 'NEWTABLE', 'CONCAT',
                 'SETGLOBAL', 'CLOSURE', 'SETUPVAL', 'GETUPVAL')


def is_weak_map(n):
    return n in ('UNKNOWN', 'CALL', 'SETLIST', 'SELF', 'TAILCALL', 'EQ', 'LT',
                 'LE', 'TEST', 'RETURN', 'MOVE')


def is_mode_bound(n):
    return n in ('CLOSURE', 'JMP', 'GETGLOBAL', 'LOADK', 'GETTABLE', 'SETTABLE', 'SELF')


def pref_nm(map_name, ins, proto, closure_local_op, opcode_map):
    shape = shp_guess(ins, proto, closure_local_op, opcode_map)
    name = map_name or 'UNKNOWN'

    if shape and shape['conf'] >= 70 and shape['name'] != 'UNKNOWN':
        protect = (is_strong_map(map_name)
                   and shape['name'] != map_name
                   and not (map_name == 'SETTABLE' and shape['name'] == 'GETTABLE'))
        ret_mis = map_name == 'RETURN' and shape['name'] in (
            'LOADK', 'LOADNIL', 'GETGLOBAL', 'JMP', 'MOVE', 'CALL')
        if ret_mis:
            name = shape['name']
        elif protect:
            name = map_name
        elif not (shape['name'] == 'CALL' and map_name in ('CONCAT', 'SETGLOBAL', 'TFORLOOP')):
            name = shape['name']
    elif shape and shape['name'] != 'UNKNOWN' and name == 'UNKNOWN':
        name = shape['name']
    elif (shape and shape['name'] != 'UNKNOWN' and shape['conf'] >= 55
          and is_weak_map(name) and is_mode_bound(shape['name'])):
        name = shape['name']

    if map_name == 'CONCAT':
        name = 'CONCAT'
    if map_name == 'SETGLOBAL' and ins.mode == 1:
        name = 'SETGLOBAL'
    if map_name == 'SETTABLE':
        name = 'SETTABLE'
    if map_name == 'GETTABLE':
        name = 'GETTABLE'
    if map_name in ('FORLOOP', 'FORPREP'):
        name = map_name

    if (map_name == 'RETURN' and ins.mode == 0 and is_num(ins.B)
            and ins.B >= 2 and not ins.isKB and not ins.isKC):
        name = 'RETURN'
    if (map_name == 'MOVE' and ins.mode == 0 and not ins.isKB and not ins.isKC
            and is_num(ins.B) and ins.B <= 255):
        if not (shape and shape['name'] == 'CALL' and shape['conf'] >= 85 and lk_call(ins, proto)):
            name = 'MOVE'
    if map_name == 'TFORLOOP':
        name = 'TFORLOOP'
    if map_name in ('LT', 'LE', 'EQ'):
        if ins.mode == 3 or is_cmp_op(map_name):
            name = map_name

    if (name == 'TFORLOOP' and ins.mode == 0 and is_num(ins.B) and is_num(ins.A)
            and ins.B >= 1
            and (ins.C == 0 or ins.C == 1 or ins.C is None
                 or (is_num(ins.C) and 2 <= ins.C <= 16))):
        if ins.B <= ins.A + 8 or (shape and shape['name'] == 'CALL'):
            name = 'CALL'

    if map_name == 'TFORLOOP' and ins.mode == 3:
        name = 'TFORLOOP'

    if ins.mode == 2 and is_num(ins.B):
        if map_name in ('FORLOOP', 'FORPREP') or name in ('FORLOOP', 'FORPREP'):
            name = 'FORPREP' if (map_name == 'FORPREP' or name == 'FORPREP') else 'FORLOOP'
            if map_name == 'FORPREP':
                name = 'FORPREP'
            if map_name == 'FORLOOP':
                name = 'FORLOOP'
        else:
            name = 'JMP'

    if ins.mode == 3 and is_num(ins.B):
        pidx = ins.B
        nups = ins.C if is_num(ins.C) else 0
        if _proto_at(proto, pidx) and 0 <= nups <= 32 and not ins.isKB and not ins.isKC:
            name = 'CLOSURE'
        elif is_cmp_op(map_name) or is_cmp_op(name):
            name = map_name if is_cmp_op(map_name) else name
        elif name == 'CLOSURE' or map_name == 'CLOSURE':
            name = 'JMP'
        elif map_name and map_name != 'UNKNOWN':
            name = map_name

    if ins.mode == 1 and ins.isKB and ins.C is None:
        if map_name == 'SETGLOBAL':
            name = 'SETGLOBAL'
        elif isinstance(ins.B, str):
            if is_bin_k(ins.B):
                name = 'LOADK'
            elif is_id_str(ins.B) and feeds_global_use(ins, proto):
                name = 'GETGLOBAL'
            else:
                name = 'LOADK'
        elif isinstance(ins.B, bool):
            name = 'LOADBOOL'
        elif is_num(ins.B):
            name = 'GETGLOBAL' if map_name == 'GETGLOBAL' else 'LOADK'

    if ((name in ('GETGLOBAL', 'GETUPVAL') or map_name == 'GETUPVAL')
            and ins.mode == 0 and not ins.isKB and not ins.isKC and is_num(ins.B)):
        name = 'GETUPVAL'
    if name == 'GETGLOBAL' and ins.mode == 0 and not ins.isKB and is_num(ins.B):
        name = 'GETUPVAL'

    if name == 'LOADNIL' and is_num(ins.B) and is_num(ins.A) and ins.B < ins.A:
        if map_name == 'MOVE':
            name = 'MOVE'
        elif map_name and map_name != 'UNKNOWN' and map_name != 'LOADNIL':
            name = map_name
        else:
            name = 'MOVE'

    if ins.mode == 0 and ins.isKB and ins.isKC:
        name = 'SETTABLE'

    if ins.mode == 0 and ins.isKC and not ins.isKB and is_num(ins.B):
        if map_name == 'SETTABLE':
            name = 'SETTABLE'
        elif map_name == 'GETTABLE':
            name = 'GETTABLE'
        elif ins.A == ins.B and isinstance(ins.C, str) and is_id_str(ins.C) and has_call_soon(ins, proto):
            name = 'SELF'
        else:
            name = 'GETTABLE'

    if name == 'CLOSURE' and ins.mode == 0 and (ins.isKC or ins.isKB):
        if ins.isKB and ins.isKC:
            name = 'SETTABLE'
        elif ins.isKC:
            name = 'GETTABLE'

    if name == 'CLOSURE':
        nups = ins.C if is_num(ins.C) else 0
        pidx = ins.B if is_num(ins.B) else -1
        if nups < 0 or nups > 32 or not _proto_at(proto, pidx):
            if ins.mode == 3 and is_num(ins.B):
                name = 'JMP'
            elif (ins.mode == 0 and not ins.isKB and not ins.isKC and is_num(ins.B)
                  and ins.B <= 255 and (ins.C == 0 or ins.C is None)):
                name = 'MOVE'
            elif ins.mode == 0 and not ins.isKB and not ins.isKC:
                name = map_name if map_name in ('CALL', 'SETLIST') else 'CALL'
            elif map_name and map_name != 'UNKNOWN' and map_name != 'CLOSURE':
                name = map_name
            else:
                name = 'UNKNOWN'

    if (ins.mode == 0 and not ins.isKB and not ins.isKC and ins.B == 0
            and (ins.C == 0 or ins.C is None)):
        strong_shape = shape and shape['name'] != 'UNKNOWN' and shape['conf'] >= 55
        if strong_shape and shape['name'] in ('LOADNIL', 'MOVE', 'CALL'):
            name = shape['name']
        elif map_name == 'MOVE':
            name = 'MOVE'
        elif map_name in ('RETURN', 'TAILCALL'):
            if not strong_shape:
                name = map_name
        elif map_name == 'CALL':
            name = 'CALL'
        elif map_name == 'LOADNIL':
            name = 'LOADNIL'
        elif map_name == 'SETLIST':
            name = shape['name'] if strong_shape else 'CALL'
        elif name == 'UNKNOWN' and map_name and map_name != 'UNKNOWN':
            name = map_name

    if name in ('JMP', 'EQ', 'LT', 'LE', 'TEST') and isinstance(ins.B, str):
        if ins.mode == 1 and ins.isKB:
            name = ('GETGLOBAL' if (is_id_str(ins.B) and not is_bin_k(ins.B)
                                    and feeds_global_use(ins, proto)) else 'LOADK')
        elif map_name and map_name != 'UNKNOWN':
            name = map_name

    return name


def ref_op_map(root, opcode_map):
    votes = {}

    def walk(p):
        for i in range(1, _n_instr(p)):
            ins = _instr(p, i)
            if not ins or ins.skipped:
                continue
            ins._index = i
            map_name = ((opcode_map.get(ins.opcode) or {}).get('name')) or 'UNKNOWN'
            name = pref_nm(map_name, ins, p, None, opcode_map)
            shape = shp_guess(ins, p, None, opcode_map)
            if not shape or shape['conf'] < 80:
                continue
            m = votes.setdefault(ins.opcode, {})
            m[name] = m.get(name, 0) + 1
        for c in p.prototypes:
            if c:
                walk(c)

    walk(root)

    for op, m in votes.items():
        if op not in opcode_map:
            opcode_map[op] = {'name': 'UNKNOWN', 'body': ''}
        if opcode_map[op]['name'] != 'UNKNOWN':
            continue
        best = None
        best_n = 0
        total = 0
        for name, cnt in m.items():
            total += cnt
            if cnt > best_n:
                best = name
                best_n = cnt
        if best and best_n == total and best_n >= 2:
            opcode_map[op]['name'] = best
    return opcode_map


# ---------------------------------------------------------------------------
# dispatch tree discovery
# ---------------------------------------------------------------------------


def is_op_idx(expr):
    folded = str_ws(fold_const(expr))
    val = eval_ok(expr)
    return folded == '1' or (is_num(val) and val == 1)


def scan_fetch(folded):
    best = None
    i = 0
    n = len(folded)
    while i < n:
        if folded[i] in ('"', "'"):
            i = sk_str(folded, i)
            continue
        a = rd_id(folded, i)
        if not a:
            i += 1
            continue
        j = sk_ws(folded, a['end'])
        if char(folded, j) != '=':
            i = a['end']
            continue
        j = sk_ws(folded, j + 1)
        code = rd_id(folded, j)
        if not code or char(folded, code['end']) != '[':
            i = a['end']
            continue
        pc = rd_id(folded, code['end'] + 1)
        if not pc or char(folded, pc['end']) != ']':
            i = a['end']
            continue
        j = sk_ws(folded, pc['end'] + 1)
        if char(folded, j) == ';':
            j += 1
        j = sk_ws(folded, j)
        op = rd_id(folded, j)
        if not op:
            i = a['end']
            continue
        j = sk_ws(folded, op['end'])
        if char(folded, j) != '=':
            i = a['end']
            continue
        j = sk_ws(folded, j + 1)
        inst2 = rd_id(folded, j)
        if not inst2 or inst2['name'] != a['name'] or char(folded, inst2['end']) != '[':
            i = a['end']
            continue
        idx_start = inst2['end'] + 1
        depth = 1
        k = idx_start
        while k < n and depth > 0:
            if folded[k] == '[':
                depth += 1
            elif folded[k] == ']':
                depth -= 1
            if depth > 0:
                k += 1
            else:
                break
        if depth != 0:
            i = a['end']
            continue
        idx_expr = folded[idx_start:k]
        if is_op_idx(idx_expr):
            best = {
                'instVar': a['name'],
                'codeVar': code['name'],
                'pcVar': pc['name'],
                'opVar': op['name'],
                'fetchIndex': i,
            }
        i = a['end']
    if not best:
        raise RuntimeError('VM fetch not found')
    return best


def find_op_le(folded, op_var):
    """Patched version: accepts any comparison operator against ``op_var``."""
    hits = []
    start = 0
    while start < len(folded):
        at = find_wd(folded, 'if', start)
        if at < 0:
            break
        then_at = find_wd(folded, 'then', at + 2)
        if then_at < 0:
            start = at + 2
            continue
        cond = folded[at + 2:then_at]
        matched = False
        j = 0
        while j < len(cond):
            ident = rd_id(cond, j)
            if ident and ident['name'] == op_var:
                k = sk_ws(cond, ident['end'])
                op = None
                op_len = 0
                two = cond[k:k + 2]
                if two in ('<=', '>=', '==', '~='):
                    op = two
                    op_len = 2
                elif char(cond, k) in ('<', '>'):
                    op = cond[k]
                    op_len = 1
                if op:
                    k = sk_ws(cond, k + op_len)
                    num = rd_num(cond, k)
                    if num:
                        hits.append({'at': at, 'bound': num['num']})
                        matched = True
                        break
            j += 1
        start = at + 2
        if matched:
            continue
    return hits


def pick_disp(folded, fetch, op_var):
    hits = find_op_le(folded, op_var)
    best = None

    for hit in hits:
        ab = hit if isinstance(hit, (int, float)) else hit['at']
        if ab <= fetch['fetchIndex'] - 50 and ab < fetch['fetchIndex']:
            pass
        elif ab < fetch['fetchIndex'] - 5000:
            continue
        end = find_blk_end(folded, ab)
        if end < 0:
            continue
        length = end - ab
        if length < 400:
            continue
        bound = hit['bound'] if isinstance(hit, dict) else 0
        score = length + bound * 50
        if not best or score > best['score']:
            best = {'start': ab, 'len': length, 'raw': folded[ab:end], 'score': score, 'bound': bound}

    for hit in hits:
        ab = hit if isinstance(hit, (int, float)) else hit['at']
        if ab <= fetch['fetchIndex']:
            continue
        end = find_blk_end(folded, ab)
        if end < 0:
            continue
        length = end - ab
        if length < 400:
            continue
        bound = hit['bound'] if isinstance(hit, dict) else 0
        score = length + bound * 80 + 1000
        if not best or score > best['score']:
            best = {'start': ab, 'len': length, 'raw': folded[ab:end], 'score': score, 'bound': bound}

    if not best:
        raise RuntimeError('Dispatch tree not found for ' + op_var)
    return best


def find_disp(source):
    folded = fold_const(source)
    fetch = scan_fetch(folded)
    tree = pick_disp(folded, fetch, fetch['opVar'])
    out = dict(fetch)
    out.update({
        'start': tree['start'],
        'end': tree['start'] + tree['len'],
        'raw': tree['raw'],
        'folded': folded,
    })
    return out


def scan_sep(s, start):
    depth = 0
    i = start
    hits = []
    while i < len(s):
        if s[i] in ('"', "'"):
            i = sk_str(s, i)
            continue
        tok = next_kw(s, i)
        if not tok:
            break
        if tok['kind'] != 'kw':
            i = tok['end']
            continue
        n = tok['name']
        if n in ('if', 'function', 'repeat', 'do'):
            depth += 1
            i = tok['end']
            continue
        if n == 'until':
            if depth > 0:
                depth -= 1
            i = tok['end']
            continue
        if n == 'elseif':
            if depth == 0:
                hits.append({'type': 'elseif', 'index': tok['start']})
            i = tok['end']
            continue
        if n == 'else':
            if depth == 0:
                hits.append({'type': 'else', 'index': tok['start']})
            i = tok['end']
            continue
        if n == 'end':
            if depth == 0:
                hits.append({'type': 'end', 'index': tok['start']})
                return {'hits': hits, 'end': tok['end']}
            depth -= 1
            i = tok['end']
            continue
        i = tok['end']
    return {'hits': hits, 'end': len(s)}


def parse_if(s):
    if not wd_at(s, 0, 'if') and not (sk_ws(s, 0) == 0 and wd_at(s, 0, 'if')):
        start = sk_ws(s, 0)
        if not wd_at(s, start, 'if'):
            return None
    start = 0 if wd_at(s, 0, 'if') else sk_ws(s, 0)
    if not wd_at(s, start, 'if'):
        return None

    branches = []
    i = start + 2
    while True:
        then_at = find_wd(s, 'then', i)
        if then_at < 0:
            return None
        cond = s[i:then_at].strip()
        body_start = then_at + 4
        scanned = scan_sep(s, body_start)
        hits = scanned['hits']
        first = hits[0] if hits else None
        if not first:
            return None
        branches.append({'cond': cond, 'body': s[body_start:first['index']].strip()})

        if first['type'] == 'end':
            return {
                'branches': branches,
                'elseBody': None,
                'end': first['index'] + 3,
                'full': s[:first['index'] + 3],
            }
        if first['type'] == 'else':
            else_start = first['index'] + 4
            rest = scan_sep(s, else_start)
            end_hit = next((h for h in rest['hits'] if h['type'] == 'end'), None)
            else_end = end_hit['index'] if end_hit else rest['end']
            return {
                'branches': branches,
                'elseBody': s[else_start:else_end].strip(),
                'end': else_end + 3,
                'full': s[:else_end + 3],
            }
        if first['type'] == 'elseif':
            i = first['index'] + 6
            continue
        return None


def parse_cond(cond, op_var):
    i = 0
    while i < len(cond):
        ident = rd_id(cond, i)
        if ident and ident['name'] == op_var:
            j = sk_ws(cond, ident['end'])
            op = None
            two = cond[j:j + 2]
            if two in ('<=', '>=', '==', '~='):
                op = two
                j += 2
            elif char(cond, j) in ('<', '>'):
                op = cond[j]
                j += 1
            if op:
                j = sk_ws(cond, j)
                num = rd_num(cond, j)
                if num:
                    return {'op': op, 'n': num['num']}
        i += 1
    return None


def eval_cond(c, opcode):
    if not c:
        return False
    op = c['op']
    n = c['n']
    if op == '<=':
        return opcode <= n
    if op == '>=':
        return opcode >= n
    if op == '==':
        return opcode == n
    if op == '~=':
        return opcode != n
    if op == '<':
        return opcode < n
    if op == '>':
        return opcode > n
    return False


def fmt_if(branches, else_body):
    if not branches:
        return else_body or ''
    out = ''
    for i, br in enumerate(branches):
        out += ('if ' if i == 0 else 'elseif ') + br['cond'] + ' then ' + br['body'] + ' '
    if else_body is not None:
        out += 'else ' + else_body + ' '
    out += 'end'
    return out.strip()


def res_leaf(fragment, opcode, op_var, depth=0):
    f = fragment.strip()
    if depth > 40:
        return f

    def try_parse(src):
        parsed = parse_if(src)
        if not parsed:
            return None
        for bi, br in enumerate(parsed['branches']):
            c = parse_cond(br['cond'], op_var)
            if not c:
                return fmt_if(parsed['branches'][bi:], parsed['elseBody'])
            if eval_cond(c, opcode):
                return res_leaf(br['body'], opcode, op_var, depth + 1)
        if parsed['elseBody'] is not None:
            return res_leaf(parsed['elseBody'], opcode, op_var, depth + 1)
        return f

    if wd_at(f, 0, 'if') and op_var in f[:80]:
        got = try_parse(f)
        if got is not None:
            return got

    if_idx = find_op_if(f, op_var)
    if 0 <= if_idx < 80:
        got = try_parse(f[if_idx:])
        if got is not None:
            return got
    return f


def find_op_if(src, op_var):
    start = 0
    best = -1
    while start < len(src):
        at = find_wd(src, 'if', start)
        if at < 0:
            break
        j = sk_ws(src, at + 2)
        if char(src, j) == '(':
            j = sk_ws(src, j + 1)
            while char(src, j) == '(':
                j = sk_ws(src, j + 1)
            ident = rd_id(src, j)
            if ident and ident['name'] == op_var:
                j = sk_ws(src, ident['end'])
                two = src[j:j + 2]
                if two in ('<=', '==', '>=') or char(src, j) in ('>', '<'):
                    if best < 0:
                        best = at
                    if at > best + 200:
                        break
        start = at + 2
    return best


def max_op_tree(tree, op_var):
    max_op = 0
    i = 0
    while i < len(tree):
        ident = rd_id(tree, i)
        if ident and ident['name'] == op_var:
            j = sk_ws(tree, ident['end'])
            two = tree[j:j + 2]
            if two in ('<=', '==') or char(tree, j) == '>':
                j += 2 if two in ('<=', '==') else 1
                j = sk_ws(tree, j)
                num = rd_num(tree, j)
                if num:
                    max_op = max(max_op, num['num'])
            i = ident['end']
            continue
        i += 1
    return max_op


def parse_disp(code, op_var):
    folded = fold_const(code)
    start = find_op_if(folded, op_var)
    if start < 0:
        raise RuntimeError('Dispatch tree start not found for ' + op_var)
    root = parse_if(folded[start:])
    if not root:
        raise RuntimeError('Failed to parse dispatch if-tree')

    mapping = {}
    probe_max = max_op_tree(root['full'], op_var) + 8
    for op in range(int(probe_max) + 1):
        mapping[op] = res_leaf(root['full'], op, op_var)
    return {'map': mapping, 'foldedTree': root['full'], 'opVar': op_var, 'maxOp': probe_max}


def find_loc_fn(source, start=0):
    i = start
    while i < len(source):
        at = find_wd(source, 'local', i)
        if at < 0:
            return None
        j = sk_ws(source, at + 5)
        if not wd_at(source, j, 'function'):
            i = at + 5
            continue
        j = sk_ws(source, j + 8)
        fn = rd_id(source, j)
        if not fn:
            i = at + 5
            continue
        j = sk_ws(source, fn['end'])
        if char(source, j) != '(':
            i = at + 5
            continue
        j += 1
        a = rd_id(source, sk_ws(source, j))
        if not a or char(source, a['end']) != ',':
            i = at + 5
            continue
        b = rd_id(source, sk_ws(source, a['end'] + 1))
        if not b or char(source, b['end']) != ',':
            i = at + 5
            continue
        c = rd_id(source, sk_ws(source, b['end'] + 1))
        if not c:
            i = at + 5
            continue
        j = sk_ws(source, c['end'])
        if char(source, j) != ')':
            i = at + 5
            continue
        j = sk_ws(source, j + 1)
        if not wd_at(source, j, 'local'):
            i = at + 5
            continue
        j = sk_ws(source, j + 5)
        d = rd_id(source, j)
        if not d:
            i = at + 5
            continue
        j = sk_ws(source, d['end'])
        if char(source, j) != '=':
            i = at + 5
            continue
        j = sk_ws(source, j + 1)
        e = rd_id(source, j)
        if not e or e['name'] != a['name'] or source[e['end']:e['end'] + 3] != '[1]':
            i = at + 5
            continue
        return {
            'index': at,
            'wrapVar': fn['name'],
            'chunkVar': a['name'],
            'upValVar': b['name'],
            'envVar': c['name'],
            'codeLocal': d['name'],
        }
    return None


def inf_vm_ctx(source, dispatch):
    inst_var = dispatch['instVar']
    op_var = dispatch['opVar']
    pc_var = dispatch['pcVar']
    code_var = dispatch['codeVar']
    folded = fold_const(source[dispatch['start']:dispatch['end']])

    wrap_var = 'v40'
    env_var = 'v74'
    up_val_var = 'v73'
    stack_var = 'v88'
    proto_var = 'v79'
    unpack_var = 'v21'

    wrap_fn = find_loc_fn(source)
    if wrap_fn:
        wrap_var = wrap_fn['wrapVar']
        up_val_var = wrap_fn['upValVar']
        env_var = wrap_fn['envVar']
        sl = source[wrap_fn['index']:wrap_fn['index'] + 400]
        i = 0
        while i < len(sl):
            at = find_wd(sl, 'local', i)
            if at < 0:
                break
            j = sk_ws(sl, at + 5)
            ident = rd_id(sl, j)
            if ident:
                j = sk_ws(sl, ident['end'])
                if char(sl, j) == '=':
                    j = sk_ws(sl, j + 1)
                    base = rd_id(sl, j)
                    if base and sl[base['end']:base['end'] + 3] == '[2]':
                        proto_var = ident['name']
                        break
            i = at + 5

    i = 0
    while i < len(folded):
        left = rd_id(folded, i)
        if not left:
            i += 1
            continue
        needle = '[' + inst_var + '[2]]='
        if folded[left['end']:left['end'] + len(needle)] == needle:
            j = left['end'] + len(needle)
            right = rd_id(folded, j)
            if right and folded[right['end']:right['end'] + len(needle) - 1] == '[' + inst_var + '[3]]':
                if left['name'] == right['name']:
                    stack_var = left['name']
                elif left['name'] == stack_var:
                    up_val_var = right['name']
        i = left['end']

    stk_needle = '[' + inst_var + '[2]]'
    stk_at = folded.find(stk_needle)
    if stk_at > 0:
        k = stk_at - 1
        while k >= 0 and is_dig(folded[k]):
            k -= 1
        if char(folded, k) == 'v':
            ident = rd_id(folded, k)
            if ident:
                stack_var = ident['name']

    un_at = source.find('=unpack or table.unpack')
    if un_at > 0:
        k = un_at - 1
        while k >= 0 and is_ws(source[k]):
            k -= 1
        while k >= 0 and (is_dig(source[k]) or source[k] == 'v'):
            k -= 1
        ident = rd_id(source, k + 1)
        if ident:
            unpack_var = ident['name']

    return {
        'instVar': inst_var, 'opVar': op_var, 'pcVar': pc_var, 'codeVar': code_var,
        'envVar': env_var, 'upValVar': up_val_var, 'stackVar': stack_var,
        'protoVar': proto_var, 'wrapVar': wrap_var,
        'topVar': 'v83',
        'unpackVar': unpack_var,
    }


def find_clos_op(source):
    folded = fold_const(source)
    start = 0
    while start < len(folded):
        at = find_wd(folded, 'if', start)
        if at < 0:
            break
        j = sk_ws(folded, at + 2)
        if char(folded, j) == '(':
            j = sk_ws(folded, j + 1)
            v = rd_id(folded, j)
            if v and char(folded, v['end']) == '[' and char(folded, v['end'] + 1) == '1' and char(folded, v['end'] + 2) == ']':
                j = sk_ws(folded, v['end'] + 3)
                if char(folded, j) == '=' and char(folded, j + 1) == '=':
                    j = sk_ws(folded, j + 2)
                    if char(folded, j) == '(':
                        j += 1
                    num = rd_num(folded, j)
                    if num:
                        return num['num']
        start = at + 2
    return None


def guess_op(ins):
    if not ins or ins.skipped:
        return 'UNKNOWN'
    return pref_nm('UNKNOWN', ins, None, None, {})


def councn(body):
    n = 0
    i = 0
    while i < len(body):
        if body[i] == 'v' and is_dig(char(body, i + 1)):
            j = i + 1
            while j < len(body) and is_dig(body[j]):
                j += 1
            if body[j:j + 2] in ('<=', '=='):
                n += 1
            i = j
            continue
        i += 1
    return n


def an_vm(source):
    try:
        dispatch = find_disp(source)
    except Exception:
        return {
            'dispatch': None,
            'ctx': {},
            'opcodeMap': {},
            'nameToOpcodes': {},
            'closureLocalOp': None,
            'opcodeCount': 0,
        }

    folded = dispatch.get('folded') or fold_const(source)
    ctx = inf_vm_ctx(folded, dispatch)

    try:
        parsed = parse_disp(dispatch['raw'], dispatch['opVar'])
        mapping = parsed['map']
    except Exception:
        return {
            'dispatch': dispatch,
            'ctx': ctx,
            'opcodeMap': {},
            'nameToOpcodes': {},
            'closureLocalOp': find_clos_op(folded),
            'opcodeCount': 0,
        }

    opcode_map = {}
    name_to_opcodes = {}
    for op, body in mapping.items():
        name = ref_op_nm(cls_h(body), body, ctx)
        if councn(body) > 3 and op > 45:
            continue
        opcode_map[op] = {'name': name, 'body': strip_n(body)[:200]}
        name_to_opcodes.setdefault(name, []).append(op)

    return {
        'dispatch': dispatch,
        'ctx': ctx,
        'opcodeMap': opcode_map,
        'nameToOpcodes': name_to_opcodes,
        'closureLocalOp': find_clos_op(folded),
        'opcodeCount': len(opcode_map),
    }
