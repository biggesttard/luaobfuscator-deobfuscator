"""Lua source scanning, constant folding, string and bytecode extraction."""

from __future__ import annotations

import json
import math
import struct

# ---------------------------------------------------------------------------
# low level helpers
# ---------------------------------------------------------------------------


def char(s, i):
    """JS-style ``s[i]``: returns ``''`` when the index is out of range."""
    if 0 <= i < len(s):
        return s[i]
    return ''


def sub(s, start, end=None):
    """JS-style ``s.slice(start, end)`` with clamping."""
    n = len(s)
    if start < 0:
        start = max(0, n + start)
    if end is None:
        return s[start:] if start < n else ''
    if end < 0:
        end = max(0, n + end)
    if end < start:
        end = start
    return s[start:min(end, n)]


def is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def js_number_str(v):
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, int):
        return str(v)
    if v != v:
        return 'NaN'
    if v == float('inf'):
        return 'Infinity'
    if v == float('-inf'):
        return '-Infinity'
    if v.is_integer() and abs(v) < 1e15:
        return str(int(v))
    text = repr(float(v))
    if 'e' in text:
        mant, exp = text.split('e')
        sign = ''
        if exp.startswith(('+', '-')):
            sign, exp = exp[0], exp[1:]
        exp = exp.lstrip('0') or '0'
        text = mant + 'e' + sign + exp
    return text


def js_div(a, b):
    if b == 0:
        if a == 0 or a != a:
            return float('nan')
        return math.copysign(float('inf'), a) * (1.0 if math.copysign(1.0, b) > 0 else -1.0)
    return a / b


def js_mod(a, b):
    if b == 0:
        return float('nan')
    return math.fmod(a, b)


def js_round(v):
    return math.floor(v + 0.5) if v >= 0 else -math.floor(-v + 0.5)


def is_ws(c):
    return c != '' and c in ' \t\n\r\f\v'


def is_dig(c):
    return '0' <= c <= '9'


def is_a(c):
    return ('a' <= c <= 'z') or ('A' <= c <= 'Z')


def is_id0(c):
    return is_a(c) or c == '_'


def is_id(c):
    return is_id0(c) or is_dig(c)


def str_ws(s):
    return ''.join(c for c in s if not is_ws(c))


def col_ws(s):
    out = ''
    space = False
    for c in s:
        if is_ws(c):
            if not space and out:
                out += ' '
                space = True
        else:
            out += c
            space = False
    return out.strip()


def rd_id(src, i):
    if not is_id0(char(src, i)):
        return None
    j = i + 1
    while j < len(src) and is_id(src[j]):
        j += 1
    return {'name': src[i:j], 'end': j}


def rd_num(src, i):
    if not is_dig(char(src, i)) and not (char(src, i) == '.' and is_dig(char(src, i + 1))):
        return None
    j = i
    while j < len(src) and (is_dig(src[j]) or src[j] == '.'):
        j += 1
    text = src[i:j]
    try:
        value = float(text)
    except ValueError:
        value = float('nan')
    return {'value': text, 'end': j, 'num': value}


def sk_str(src, i):
    q = char(src, i)
    if q not in ('"', "'"):
        return i
    j = i + 1
    while j < len(src) and src[j] != q:
        if src[j] == '\\':
            j += 1
        j += 1
    return j + 1


def sk_ws(src, i):
    while i < len(src) and is_ws(src[i]):
        i += 1
    return i


def sk_sp(s, i):
    while i < len(s) and is_ws(s[i]):
        i += 1
    return i


def next_kw(src, i):
    start = sk_ws(src, i)
    if start >= len(src):
        return None
    if src[start] in ('"', "'"):
        return {'kind': 'str', 'start': start, 'end': sk_str(src, start)}
    ident = rd_id(src, start)
    if not ident:
        return {'kind': 'ch', 'ch': src[start], 'start': start, 'end': start + 1}
    return {'kind': 'kw', 'name': ident['name'], 'start': start, 'end': ident['end']}


def is_blk_open(name):
    return name in ('if', 'function', 'repeat', 'do')


def is_blk_skip(name):
    return name in ('for', 'while')


def find_blk_end(src, start):
    head = next_kw(src, start)
    if not head or head['kind'] != 'kw':
        return -1
    if not is_blk_open(head['name']) and not is_blk_skip(head['name']):
        return -1

    i = head['end']
    depth = 1

    if is_blk_skip(head['name']):
        while i < len(src):
            if src[i] in ('"', "'"):
                i = sk_str(src, i)
                continue
            tok = next_kw(src, i)
            if not tok:
                return -1
            if tok['kind'] == 'kw' and tok['name'] == 'do':
                i = tok['end']
                break
            i = tok['end']

    while i < len(src):
        if src[i] in ('"', "'"):
            i = sk_str(src, i)
            continue
        tok = next_kw(src, i)
        if not tok:
            break
        if tok['kind'] != 'kw':
            i = tok['end']
            continue
        name = tok['name']
        if name in ('elseif', 'else'):
            i = tok['end']
            continue
        if is_blk_skip(name):
            i = tok['end']
            continue
        if is_blk_open(name):
            depth += 1
            i = tok['end']
            continue
        if name in ('until', 'end'):
            depth -= 1
            i = tok['end']
            if depth == 0:
                return i
            continue
        i = tok['end']
    return -1


def xtr_q(src, quote_idx):
    if char(src, quote_idx) != '"':
        raise ValueError('expected quote')
    i = quote_idx + 1
    content = []
    while i < len(src):
        c = src[i]
        if c == '\\' and i + 1 < len(src):
            content.append('\\')
            i += 1
            if is_dig(src[i]):
                n = 0
                while i < len(src) and is_dig(src[i]) and n < 3:
                    content.append(src[i])
                    i += 1
                    n += 1
            else:
                content.append(src[i])
                i += 1
        elif c == '"':
            return {'content': ''.join(content), 'end': i}
        else:
            content.append(c)
            i += 1
    raise ValueError('unterminated string')


def wd_at(src, i, word):
    if sub(src, i, i + len(word)) != word:
        return False
    before = char(src, i - 1) if i > 0 else ''
    after = char(src, i + len(word))
    if before and is_id(before):
        return False
    if after and is_id(after):
        return False
    return True


def find_wd(src, word, start=0):
    i = start
    while i < len(src):
        if src[i] in ('"', "'"):
            i = sk_str(src, i)
            continue
        if wd_at(src, i, word):
            return i
        i += 1
    return -1


def has_wd(src, word):
    i = 0
    while i < len(src):
        if wd_at(src, i, word):
            return True
        i += 1
    return False


# ---------------------------------------------------------------------------
# constant folding
# ---------------------------------------------------------------------------


def strip_sp(s):
    return ''.join(c for c in s if not is_ws(c))


def tok(expr):
    tokens = []
    s = strip_sp(str(expr))
    i = 0
    while i < len(s):
        if is_dig(s[i]) or (s[i] == '.' and is_dig(char(s, i + 1))):
            j = i
            while j < len(s) and (is_dig(s[j]) or s[j] == '.'):
                j += 1
            tokens.append({'type': 'num', 'value': float(s[i:j])})
            i = j
        elif s[i] in '+-*/%()^':
            tokens.append({'type': 'op', 'value': s[i]})
            i += 1
        else:
            raise ValueError('bad expr: ' + s[i])
    return tokens


def eval_tok(tokens):
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take():
        nonlocal pos
        t = tokens[pos]
        pos += 1
        return t

    def expr():
        left = term()
        while peek() and peek()['value'] in ('+', '-'):
            op = take()['value']
            right = term()
            left = left + right if op == '+' else left - right
        return left

    def term():
        left = unary()
        while peek() and peek()['value'] in '*/%^':
            op = take()['value']
            right = unary()
            if op == '*':
                left *= right
            elif op == '/':
                left = js_div(left, right)
            elif op == '%':
                left = js_mod(left, right)
            else:
                try:
                    left = left ** right
                except (OverflowError, ValueError):
                    left = float('nan')
        return left

    def unary():
        if peek() and peek()['value'] == '-':
            take()
            return -unary()
        return prim()

    def prim():
        t = peek()
        if not t:
            raise ValueError('eof')
        if t['type'] == 'num':
            take()
            return t['value']
        if t['value'] == '(':
            take()
            v = expr()
            if not peek() or peek()['value'] != ')':
                raise ValueError(')')
            take()
            return v
        raise ValueError('token')

    result = expr()
    if pos != len(tokens):
        raise ValueError('trailing')
    return result


def eval_ex(expr):
    return eval_tok(tok(expr))


def eval_ok(expr):
    try:
        return eval_ex(expr)
    except Exception:
        return None


def is_arith(s):
    has_digit = False
    for c in s:
        if is_dig(c) or c == '.':
            has_digit = True
        elif is_ws(c) or c in '+-*/%':
            continue
        else:
            return False
    return has_digit


def has_bin_op(s):
    i = 0
    while i < len(s) and is_ws(s[i]):
        i += 1
    if char(s, i) == '-':
        i += 1
    while i < len(s):
        c = s[i]
        if is_dig(c) or c == '.':
            i += 1
            continue
        if is_ws(c):
            i += 1
            continue
        if c in '+-*/%^':
            return True
        if c in '()':
            i += 1
            continue
        return False
    return False


def fmt_num(v):
    if not math.isfinite(v):
        return js_number_str(v)
    if v == 0:
        return '0'
    if float(v).is_integer() and abs(v) < 1e15:
        return str(int(v))
    rounded = js_round(v * 1e12) / 1e12
    if float(rounded).is_integer() and abs(rounded) < 1e15:
        return str(int(rounded))
    t = js_number_str(rounded)
    if 'e' in t or 'E' in t:
        return t
    if '.' in t:
        end = len(t)
        while end > 0 and t[end - 1] == '0':
            end -= 1
        if end > 0 and t[end - 1] == '.':
            end -= 1
        t = t[:end]
    return t


def fold_par(code):
    out = code
    changed = True
    while changed:
        changed = False
        i = 0
        nxt = []
        while i < len(out):
            c = out[i]
            if c in ('"', "'"):
                nxt.append(c)
                i += 1
                while i < len(out) and out[i] != c:
                    if out[i] == '\\':
                        nxt.append(out[i])
                        i += 1
                        if i < len(out):
                            nxt.append(out[i])
                            i += 1
                    else:
                        nxt.append(out[i])
                        i += 1
                if i < len(out):
                    nxt.append(out[i])
                    i += 1
                continue
            if c == '(':
                depth = 1
                j = i + 1
                inner = []
                ok = True
                while j < len(out) and depth > 0:
                    cj = out[j]
                    if cj in ('"', "'"):
                        ok = False
                        break
                    if cj == '(':
                        depth += 1
                    elif cj == ')':
                        depth -= 1
                    if depth > 0:
                        inner.append(cj)
                    j += 1
                inner_s = ''.join(inner)
                if ok and depth == 0 and is_arith(inner_s) and has_bin_op(inner_s):
                    try:
                        v = eval_ex(inner_s)
                        if isinstance(v, float) and math.isfinite(v):
                            prev = nxt[-1] if nxt else ''
                            call_paren = is_id(prev) or prev in (')', ']')
                            lit = fmt_num(v)
                            nxt.append('(' + lit + ')' if call_paren else lit)
                            i = j
                            changed = True
                            continue
                    except Exception:
                        pass
            nxt.append(out[i])
            i += 1
        out = ''.join(nxt)
    return out


def rd_num_at(s, i):
    if not (is_dig(char(s, i)) or (char(s, i) == '.' and is_dig(char(s, i + 1)))):
        return None
    j = i
    if is_dig(char(s, j)):
        while j < len(s) and is_dig(s[j]):
            j += 1
    if char(s, j) == '.' and is_dig(char(s, j + 1)):
        j += 1
        while j < len(s) and is_dig(s[j]):
            j += 1
    if char(s, j) in ('e', 'E') and (
        is_dig(char(s, j + 1))
        or (char(s, j + 1) in ('+', '-') and is_dig(char(s, j + 2)))
    ):
        j += 1
        if char(s, j) in ('+', '-'):
            j += 1
        while j < len(s) and is_dig(s[j]):
            j += 1
    value = s[i:j]
    try:
        num = float(value)
    except ValueError:
        num = float('nan')
    return {'value': value, 'end': j, 'num': num}


def fold_bin(code):
    out = code
    changed = True
    while changed:
        changed = False
        i = 0
        nxt = []
        while i < len(out):
            c = out[i]
            if c in ('"', "'"):
                nxt.append(c)
                i += 1
                while i < len(out) and out[i] != c:
                    if out[i] == '\\':
                        nxt.append(out[i])
                        i += 1
                        if i < len(out):
                            nxt.append(out[i])
                            i += 1
                    else:
                        nxt.append(out[i])
                        i += 1
                if i < len(out):
                    nxt.append(out[i])
                    i += 1
                continue

            left = rd_num_at(out, i)
            if left and (i == 0 or not is_id(char(out, i - 1))):
                j = sk_sp(out, left['end'])
                op = char(out, j)
                if op and op in '+-*/%^':
                    j = sk_sp(out, j + 1)
                    right = rd_num_at(out, j)
                    if right and (right['end'] >= len(out) or not is_id(char(out, right['end']))):
                        if op == '+':
                            v = left['num'] + right['num']
                        elif op == '-':
                            v = left['num'] - right['num']
                        elif op == '*':
                            v = left['num'] * right['num']
                        elif op == '/':
                            v = js_div(left['num'], right['num'])
                        elif op == '%':
                            v = js_mod(left['num'], right['num'])
                        else:
                            try:
                                v = left['num'] ** right['num']
                            except (OverflowError, ValueError):
                                v = float('nan')
                        nxt.append(fmt_num(v))
                        i = right['end']
                        changed = True
                        continue
            nxt.append(out[i])
            i += 1
        out = ''.join(nxt)
    return out


def fold_hash(code):
    out = []
    i = 0
    while i < len(code):
        c = code[i]
        if c in ('"', "'"):
            q = c
            out.append(q)
            i += 1
            while i < len(code) and code[i] != q:
                if code[i] == '\\':
                    out.append(code[i])
                    i += 1
                    if i < len(code):
                        out.append(code[i])
                        i += 1
                else:
                    out.append(code[i])
                    i += 1
            if i < len(code):
                out.append(code[i])
                i += 1
            continue
        if c == '#' and char(code, i + 1) in ('"', "'"):
            q = code[i + 1]
            j = i + 2
            length = 0
            while j < len(code) and code[j] != q:
                if code[j] == '\\':
                    j += 1
                j += 1
                length += 1
            if char(code, j) == q:
                out.append(str(length))
                i = j + 1
                continue
        out.append(code[i])
        i += 1
    return ''.join(out)


def cmp_num(a, op, b):
    if op == '==':
        return a == b
    if op == '~=':
        return a != b
    if op == '<':
        return a < b
    if op == '>':
        return a > b
    if op == '<=':
        return a <= b
    if op == '>=':
        return a >= b
    return None


def fold_cmp(code):
    out = code
    changed = True
    while changed:
        changed = False
        i = 0
        nxt = []
        while i < len(out):
            c = out[i]
            if c in ('"', "'"):
                nxt.append(c)
                i += 1
                while i < len(out) and out[i] != c:
                    if out[i] == '\\':
                        nxt.append(out[i])
                        i += 1
                        if i < len(out):
                            nxt.append(out[i])
                            i += 1
                    else:
                        nxt.append(out[i])
                        i += 1
                if i < len(out):
                    nxt.append(out[i])
                    i += 1
                continue

            left = rd_num_at(out, i)
            if left and (i == 0 or not is_id(char(out, i - 1))):
                j = sk_sp(out, left['end'])
                op = None
                two = sub(out, j, j + 2)
                if two in ('==', '~=', '<=', '>='):
                    op = two
                    j += 2
                elif char(out, j) in ('<', '>'):
                    op = out[j]
                    j += 1
                if op:
                    j = sk_sp(out, j)
                    right = rd_num_at(out, j)
                    if right and (right['end'] >= len(out) or not is_id(char(out, right['end']))):
                        v = cmp_num(left['num'], op, right['num'])
                        if v is not None:
                            nxt.append('true' if v else 'false')
                            i = right['end']
                            changed = True
                            continue
            nxt.append(out[i])
            i += 1
        out = ''.join(nxt)
    return out


def repl_pln(s, a, b):
    if not a:
        return s
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c in ('"', "'"):
            q = c
            out.append(q)
            i += 1
            while i < len(s) and s[i] != q:
                if s[i] == '\\':
                    out.append(s[i])
                    i += 1
                    if i < len(s):
                        out.append(s[i])
                        i += 1
                else:
                    out.append(s[i])
                    i += 1
            if i < len(s):
                out.append(s[i])
                i += 1
            continue
        if s.startswith(a, i):
            out.append(b)
            i += len(a)
            continue
        out.append(s[i])
        i += 1
    return ''.join(out)


def simpbt(code):
    out = repl_pln(code, ' or_TRUE', '')
    out = repl_pln(out, 'true or ', 'true or_KEEP ')
    out = repl_pln(out, 'true or_KEEP ', 'true or ')
    return out


def fold_bool(code):
    out = code
    guard = 0
    while guard < 40:
        guard += 1
        prev = out
        out = repl_pln(out, '(true)', 'true')
        out = repl_pln(out, '(false)', 'false')
        out = repl_pln(out, 'true and ', '')
        out = repl_pln(out, ' and true', '')
        out = repl_pln(out, 'false or ', '')
        out = repl_pln(out, ' or false', '')
        out = repl_pln(out, 'false and ', 'false and_STOP ')

        out = repl_pln(out, ' or true', ' or_TRUE')
        out = repl_pln(out, 'and_STOP ', 'and ')

        out = simpbt(out)
        if out == prev:
            break
    return out


def foldt(code):
    out = []
    i = 0
    needle = '(function() return'
    while i < len(code):
        c = code[i]
        if c in ('"', "'"):
            q = c
            out.append(q)
            i += 1
            while i < len(code) and code[i] != q:
                if code[i] == '\\':
                    out.append(code[i])
                    i += 1
                    if i < len(code):
                        out.append(code[i])
                        i += 1
                else:
                    out.append(code[i])
                    i += 1
            if i < len(code):
                out.append(code[i])
                i += 1
            continue
        if code.startswith(needle, i):
            j = sk_sp(code, i + len(needle))
            num = rd_num_at(code, j)
            if num:
                j = sk_sp(code, num['end'])
                if char(code, j) == ';':
                    j = sk_sp(code, j + 1)
                if code.startswith('end)()', j):
                    out.append(js_number_str(num['num']))
                    i = j + 6
                    continue
        out.append(code[i])
        i += 1
    return ''.join(out)


_fold_const_cache = {'in': None, 'out': None}


def fold_const(code):
    src = str(code)
    if src == _fold_const_cache['in']:
        return _fold_const_cache['out']
    out = src
    out = fold_hash(out)
    out = fold_par(out)
    out = fold_bin(out)
    out = fold_cmp(out)
    out = foldt(out)
    out = fold_bool(out)
    out = fold_par(out)
    out = fold_bin(out)
    _fold_const_cache['in'] = src
    _fold_const_cache['out'] = out
    return out


# ---------------------------------------------------------------------------
# XOR payload handling
# ---------------------------------------------------------------------------


def parse_l_str(s):
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            n = s[i + 1]
            if '0' <= n <= '9':
                j = i + 1
                digits = ''
                while j < len(s) and '0' <= s[j] <= '9' and len(digits) < 3:
                    digits += s[j]
                    j += 1
                out.append(int(digits, 10) & 255)
                i = j
            else:
                table = {'n': 10, 'r': 13, 't': 9, 'a': 7, 'b': 8, 'f': 12, 'v': 11,
                         '"': 34, "'": 39, '\\': 92}
                out.append(table[n] if n in table else ord(n))
                i += 2
        else:
            out.append(ord(s[i]) & 255)
            i += 1
    return bytes(out)


def xor_dec(data, key):
    if not len(key):
        return bytes(data)
    out = bytearray(len(data))
    for i in range(len(data)):
        key_idx = 1 + ((i + 1) % len(key))
        out[i] = data[i] ^ key[key_idx - 1]
    return bytes(out)


def find_dec(src, fn_name='v7'):
    results = []
    tag = fn_name + '("'
    start = 0
    while start < len(src):
        at = src.find(tag, start)
        if at < 0:
            break
        try:
            data_q = xtr_q(src, at + len(fn_name) + 1)
            if char(src, data_q['end'] + 1) != ',' or char(src, data_q['end'] + 2) != '"':
                start = at + len(tag)
                continue
            key_q = xtr_q(src, data_q['end'] + 2)
            data = parse_l_str(data_q['content'])
            key = parse_l_str(key_q['content'])
            decrypted = xor_dec(data, key)
            results.append({
                'index': at,
                'data': data,
                'key': key,
                'decrypted': decrypted,
                'text': decrypted.decode('latin-1'),
                'end': key_q['end'] + 1,
            })
            start = key_q['end'] + 1
        except Exception:
            start = at + len(tag)
    return results


def find_v7_calls(src):
    return find_dec(src, 'v7')


def prn_ratio(s):
    if not s:
        return 0.0
    ok = 0
    for c in s:
        code = ord(c)
        if (32 <= code < 127) or code in (9, 10, 13):
            ok += 1
    return ok / len(s)


def is_prn(s):
    return isinstance(s, str) and len(s) > 0 and prn_ratio(s) >= 0.85


def is_ciph(s):
    if not isinstance(s, str) or len(s) < 2 or is_prn(s):
        return False
    bad = 0
    for c in s:
        code = ord(c)
        if code < 9 or (13 < code < 32) or code >= 127:
            bad += 1
    return bad / len(s) >= 0.3


def score_pln(s):
    if not is_prn(s):
        return -1
    score = len(s)
    for c in s:
        code = ord(c)
        if (65 <= code <= 90) or (97 <= code <= 122) or (48 <= code <= 57):
            score += 2
        if code == 32:
            score += 1
    return score


def try_dec(cipher, key):
    if not isinstance(cipher, str) or not isinstance(key, str):
        return None
    if not cipher or not key:
        return None
    plain = xor_dec(cipher.encode('latin-1', 'replace'),
                    key.encode('latin-1', 'replace')).decode('latin-1')
    score = score_pln(plain)
    if score < 0:
        return None
    return {'plain': plain, 'score': score}


def dec_outer(source):
    out = []
    for call in find_v7_calls(source):
        if call['text'].startswith('LOL!') or call['text'] == '..':
            continue
        out.append({
            'index': call['index'],
            'encryptedHex': call['data'].hex(),
            'keyHex': call['key'].hex(),
            'decrypted': call['text'],
            'kind': 'outer_v7',
        })
    return out


def rw_outer(source, fn_name='v7'):
    calls = sorted(find_v7_calls(source), key=lambda c: c['index'], reverse=True)
    text = source
    replaced = 0
    for call in calls:
        if call['text'].startswith('LOL!'):
            continue
        try:
            data = xtr_q(text, call['index'] + len(fn_name) + 1)
            if char(text, data['end'] + 1) != ',' or char(text, data['end'] + 2) != '"':
                continue
            key = xtr_q(text, data['end'] + 2)
            close = key['end'] + 1
            if char(text, close) != ')':
                continue
            text = text[:call['index']] + json.dumps(call['text'], ensure_ascii=False) + text[close + 1:]
            replaced += 1
        except Exception:
            pass
    return {'source': text, 'replaced': replaced}


def patch_ops(proto, old, new):
    for ins in proto.instructions:
        if not ins or ins.skipped:
            continue
        if ins.A == old:
            ins.A = new
        if ins.B == old:
            ins.B = new
        if ins.C == old:
            ins.C = new
    for child in proto.prototypes:
        if child:
            patch_ops(child, old, new)


def best_k(cipher, pool):
    best = None
    for item in pool:
        value = item.get('value')
        if not isinstance(value, str) or not value:
            continue
        hit = try_dec(cipher, value)
        if not hit:
            continue
        if not best or hit['score'] > best['score']:
            best = dict(hit)
            best['key'] = value
            best['keyPath'] = item.get('path')
            best['keyIndex'] = item.get('index')
    if best:
        return best
    for k in range(1, 256):
        hit = try_dec(cipher, chr(k))
        if not hit:
            continue
        if not best or hit['score'] > best['score']:
            best = dict(hit)
            best['key'] = chr(k)
            best['keyPath'] = None
            best['keyIndex'] = None
            best['singleByte'] = True
    return best


def dec_vm(root):
    maps = []
    key_consts = set()

    def walk(proto, path, inherited):
        local = []
        for i in range(1, len(proto.constants)):
            val = proto.constants[i]
            if isinstance(val, str):
                local.append({'index': i, 'value': val, 'path': path})
        pool = local + inherited

        for item in local:
            if not is_ciph(item['value']):
                continue
            filtered = [p for p in pool
                        if not (p['path'] == item['path'] and p['index'] == item['index'])]
            hit = best_k(item['value'], filtered)
            if not hit or hit['score'] < 6:
                continue
            maps.append({
                'protoPath': item['path'],
                'index': item['index'],
                'encrypted': item['value'],
                'encryptedHex': item['value'].encode('latin-1', 'replace').hex(),
                'key': hit['key'],
                'keyPath': hit.get('keyPath'),
                'keyIndex': hit.get('keyIndex'),
                'decrypted': hit['plain'],
                'score': hit['score'],
                'singleByte': bool(hit.get('singleByte')),
            })
            old = item['value']
            proto.constants[item['index']] = hit['plain']
            item['value'] = hit['plain']
            patch_ops(root, old, hit['plain'])
            if hit['key'] and is_ciph(hit['key']):
                key_consts.add(hit['key'])

        for i in range(len(proto.prototypes)):
            if not proto.prototypes[i]:
                continue
            walk(proto.prototypes[i], path + '/' + str(i), pool)

    walk(root, 'main', [])

    def blank_k(proto):
        for i in range(1, len(proto.constants)):
            val = proto.constants[i]
            if isinstance(val, str) and val in key_consts:
                old = val
                proto.constants[i] = None
                patch_ops(root, old, None)
        for child in proto.prototypes:
            if child:
                blank_k(child)

    blank_k(root)

    def sec_pass(proto, path, plains):
        local_plains = list(plains)
        for i in range(1, len(proto.constants)):
            val = proto.constants[i]
            if isinstance(val, str) and is_prn(val):
                local_plains.append({'index': i, 'value': val, 'path': path})
        for i in range(1, len(proto.constants)):
            val = proto.constants[i]
            if not isinstance(val, str) or not is_ciph(val):
                continue
            hit = best_k(val, local_plains)
            if not hit or hit['score'] < 6:
                continue
            maps.append({
                'protoPath': path,
                'index': i,
                'encrypted': val,
                'encryptedHex': val.encode('latin-1', 'replace').hex(),
                'key': hit['key'],
                'decrypted': hit['plain'],
                'score': hit['score'],
                'singleByte': bool(hit.get('singleByte')),
                'pass': 2,
            })
            proto.constants[i] = hit['plain']
            patch_ops(root, val, hit['plain'])
            local_plains.append({'index': i, 'value': hit['plain'], 'path': path})
        for i in range(len(proto.prototypes)):
            if not proto.prototypes[i]:
                continue
            sec_pass(proto.prototypes[i], path + '/' + str(i), local_plains)

    sec_pass(root, 'main', [])

    return maps


def dec_all_str(source, root):
    outer = dec_outer(source)
    rewritten = rw_outer(source)
    vm = dec_vm(root) if root else []
    return {
        'outer': outer,
        'vm': vm,
        'rewrittenSource': rewritten['source'],
        'outerReplaced': rewritten['replaced'],
        'summary': {
            'outerCount': len(outer),
            'vmCount': len(vm),
            'outerReplaced': rewritten['replaced'],
        },
    }


# ---------------------------------------------------------------------------
# bytecode container
# ---------------------------------------------------------------------------


def dec_lol(decrypted, sentinel=0x4F):
    buf = decrypted if isinstance(decrypted, (bytes, bytearray)) else decrypted.encode('latin-1', 'replace')
    magic = bytes(buf[:4]).decode('latin-1')
    if magic != 'LOL!':
        raise ValueError('bc:magic:' + json.dumps(magic))
    s = bytes(buf[4:]).decode('latin-1')
    out = bytearray()
    i = 0
    rep = None
    while i + 1 < len(s):
        a = ord(s[i])
        b = ord(s[i + 1])
        i += 2
        if b == sentinel:
            rep = int(chr(a))
            if math.isnan(rep) if isinstance(rep, float) else False:
                raise ValueError('bc:rle:' + str(i))
            continue
        try:
            byte = int(chr(a) + chr(b), 16)
        except ValueError:
            raise ValueError('bc:hex:' + str(i))
        if rep is not None:
            for _ in range(rep):
                out.append(byte)
            rep = None
        else:
            out.append(byte)
    return bytes(out)


def xtr_rle(source):
    folded = fold_const(source)
    i = 0
    while i < len(folded):
        if folded[i] != '(':
            i += 1
            continue
        close = folded.find(')', i + 1)
        if close < 0 or close - i > 40:
            i += 1
            continue
        inner = folded[i + 1:close]
        comma = inner.rfind(',')
        if comma >= 0:
            j = sk_ws(inner, comma + 1)
            if char(inner, j) == '2' and (j + 1 >= len(inner) or not is_dig(inner[j + 1])):
                k = sk_ws(folded, close + 1)
                if char(folded, k) == '=' and char(folded, k + 1) == '=':
                    k = sk_ws(folded, k + 2)
                    if char(folded, k) == '(':
                        k += 1
                    num = rd_num(folded, k)
                    if num and 32 <= num['num'] < 127:
                        return int(num['num'])
        i += 1
    return None


def is_hex(b):
    return (48 <= b <= 57) or (65 <= b <= 70) or (97 <= b <= 102)


def guess_sent(decrypted):
    buf = decrypted if isinstance(decrypted, (bytes, bytearray)) else decrypted.encode('latin-1', 'replace')
    s = buf[4:]
    votes = {}
    limit = min(len(s), 200)
    i = 0
    while i + 1 < limit:
        a = s[i]
        b = s[i + 1]
        if not is_hex(a) or not is_hex(b):
            if 48 <= a <= 57:
                votes[b] = votes.get(b, 0) + 1
        i += 2
    best = 0x4F
    best_n = 0
    for b, n in votes.items():
        if n > best_n:
            best = b
            best_n = n
    return best


class Reader:
    def __init__(self, buf):
        self.buf = buf
        self.pos = 0

    def remaining(self):
        return len(self.buf) - self.pos

    def byte(self):
        if self.pos >= len(self.buf):
            raise ValueError('EOF byte')
        b = self.buf[self.pos]
        self.pos += 1
        return b

    def u16(self):
        return self.byte() + self.byte() * 256

    def u32(self):
        return self.byte() + self.byte() * 256 + self.byte() * 65536 + self.byte() * 16777216

    def bits(self, n, start, end=None):
        if end is None:
            bit = 2 ** (start - 1)
            return 1 if n % (bit + bit) >= bit else 0
        return math.floor((n / 2 ** (start - 1)) % 2 ** (end - start + 1))

    def double(self):
        lo = self.u32()
        hi = self.u32()
        return struct.unpack('<d', struct.pack('<II', lo & 0xFFFFFFFF, hi & 0xFFFFFFFF))[0]

    def str(self):
        length = self.u32()
        if length == 0:
            return ''
        if self.pos + length > len(self.buf):
            raise ValueError('EOF string')
        s = bytes(self.buf[self.pos:self.pos + length]).decode('latin-1')
        self.pos += length
        return s


class Instr:
    def __init__(self, **kw):
        self.opcode = None
        self.A = None
        self.B = None
        self.C = None
        self.mode = None
        self.kFlags = 0
        self.isKA = False
        self.isKB = False
        self.isKC = False
        self.rawA = None
        self.rawB = None
        self.rawC = None
        self.flag = None
        self.skipped = False
        self._index = None
        self.__dict__.update(kw)


class Proto:
    def __init__(self, params=0, constants=None, instructions=None, prototypes=None):
        self.params = params
        self.constants = constants if constants is not None else [None]
        self.instructions = instructions if instructions is not None else [None]
        self.prototypes = prototypes if prototypes is not None else []


def _at(arr, idx):
    if isinstance(idx, int) and 0 <= idx < len(arr):
        return arr[idx]
    return None


def des_pr(r):
    constants = [None]
    instructions = [None]
    prototypes = []

    const_count = r.u32()
    for i in range(1, const_count + 1):
        t = r.byte()
        if t == 1:
            value = r.byte() != 0
        elif t == 2:
            value = r.double()
        elif t == 3:
            value = r.str()
        else:
            value = None
        constants.append(value)

    params = r.byte()
    inst_count = r.u32()
    for i in range(1, inst_count + 1):
        flag = r.byte()
        if r.bits(flag, 1, 1) == 0:
            mode = r.bits(flag, 2, 3)
            k_flags = r.bits(flag, 4, 6)
            opcode = r.u16()
            A = r.u16()
            B = None
            C = None
            if mode == 0:
                B = r.u16()
                C = r.u16()
            elif mode == 1:
                B = r.u32()
            elif mode == 2:
                B = r.u32() - 65536
            elif mode == 3:
                B = r.u32() - 65536
                C = r.u16()
            is_ka = r.bits(k_flags, 1, 1) == 1
            is_kb = r.bits(k_flags, 2, 2) == 1
            is_kc = r.bits(k_flags, 3, 3) == 1
            raw_a, raw_b, raw_c = A, B, C
            if is_ka:
                A = _at(constants, A)
            if is_kb:
                B = _at(constants, B)
            if is_kc:
                C = _at(constants, C)
            instructions.append(Instr(
                opcode=opcode, A=A, B=B, C=C, mode=mode, kFlags=k_flags,
                isKA=is_ka, isKB=is_kb, isKC=is_kc,
                rawA=raw_a, rawB=raw_b, rawC=raw_c, flag=flag,
            ))
        else:
            instructions.append(Instr(skipped=True, flag=flag))

    proto_count = r.u32()
    for _ in range(proto_count):
        prototypes.append(des_pr(r))

    return Proto(params=params, constants=constants, instructions=instructions, prototypes=prototypes)


def find_pln_lol(source):
    out = []
    start = 0
    while start < len(source):
        at = source.find('"LOL!', start)
        if at < 0:
            break
        try:
            q = xtr_q(source, at)
            if q['content'].startswith('LOL!'):
                out.append({
                    'index': at,
                    'text': q['content'],
                    'decrypted': q['content'].encode('latin-1', 'replace'),
                    'plain': True,
                    'end': q['end'],
                })
            start = q['end'] + 1
        except Exception:
            start = at + 5
    return out


def xtr_bc(source):
    calls = find_v7_calls(source)
    payloads = [
        {'index': c['index'], 'text': c['text'], 'decrypted': c['decrypted'],
         'plain': False, 'end': c['end']}
        for c in calls if c['text'].startswith('LOL!')
    ]
    if not payloads:
        payloads = find_pln_lol(source)
    if not payloads:
        if not calls:
            raise ValueError('bc:no_v7')
        raise ValueError('bc:no_lol')
    payload = payloads[-1]
    sentinel = xtr_rle(source)
    if sentinel is None:
        sentinel = guess_sent(payload['decrypted'])
    raw = dec_lol(payload['decrypted'], sentinel)
    reader = Reader(raw)
    root = des_pr(reader)
    return {
        'payload': payload,
        'raw': raw,
        'root': root,
        'sentinel': sentinel,
        'bytesRead': reader.pos,
        'bytesTotal': len(raw),
        'xorCalls': len(calls),
    }


# ---------------------------------------------------------------------------
# control flow unflattening (source level)
# ---------------------------------------------------------------------------


def sk_str_copy(src, i, out):
    q = src[i]
    out.append(q)
    i += 1
    while i < len(src) and src[i] != q:
        if src[i] == '\\':
            out.append(src[i])
            i += 1
            if i < len(src):
                out.append(src[i])
                i += 1
        else:
            out.append(src[i])
            i += 1
    if i < len(src):
        out.append(src[i])
        i += 1
    return i


def find_wd_then(src, start):
    i = start
    while i < len(src):
        if src[i] in ('"', "'"):
            q = src[i]
            i += 1
            while i < len(src) and src[i] != q:
                if src[i] == '\\':
                    i += 1
                i += 1
            i += 1
            continue
        if wd_at(src, i, 'then'):
            return i
        i += 1
    return -1


def strip_par(s):
    t = s.strip()
    while char(t, 0) == '(' and t and t[-1] == ')':
        depth = 0
        ok = True
        i = 0
        while i < len(t):
            if t[i] in ('"', "'"):
                q = t[i]
                i += 1
                while i < len(t) and t[i] != q:
                    if t[i] == '\\':
                        i += 1
                    i += 1
                i += 1
                continue
            if t[i] == '(':
                depth += 1
            elif t[i] == ')':
                depth -= 1
                if depth == 0 and i < len(t) - 1:
                    ok = False
                    break
            i += 1
        if not ok or depth != 0:
            break
        t = t[1:-1].strip()
    return t


def simp_cond(cond):
    t = strip_par(cond)
    guard = 0
    while guard < 20:
        guard += 1
        prev = t
        t = strip_par(t)
        if t.endswith(' or false'):
            t = t[:-len(' or false')].strip()
        elif t.endswith(' and true'):
            t = t[:-len(' and true')].strip()
        elif t.startswith('false or '):
            t = t[len('false or '):].strip()
        elif t.startswith('true and '):
            t = t[len('true and '):].strip()
        elif t.endswith(' or true'):
            return {'tautology': True}
        elif t.startswith('true or '):
            return {'tautology': True}
        elif t.endswith(' and false'):
            return {'contradiction': True}
        elif t.startswith('false and '):
            return {'contradiction': True}
        if t == prev:
            break
    return {'text': strip_par(t)}


def _state_var_ok(name):
    return name[0] == 'v' and is_dig(char(name, 1))


def rd_st_eq(cond, prefer_var):
    simp = simp_cond(cond)
    if simp.get('tautology') or simp.get('contradiction'):
        return None
    text = simp.get('text') or cond
    i = sk_ws(text, 0)

    num_left = rd_num(text, i)
    if num_left:
        j = sk_ws(text, num_left['end'])
        if sub(text, j, j + 2) != '==':
            return None
        j = sk_ws(text, j + 2)
        ident = rd_id(text, j)
        if not ident or not _state_var_ok(ident['name']):
            return None
        if prefer_var and ident['name'] != prefer_var:
            return None
        j = sk_ws(text, ident['end'])
        if j < len(text) and text[j] == ')':
            j += 1
        j = sk_ws(text, j)
        if j < len(text):
            return None
        return {'stateVar': ident['name'], 'state': num_left['num']}

    ident = rd_id(text, i)
    if not ident or not _state_var_ok(ident['name']):
        return None
    if prefer_var and ident['name'] != prefer_var:
        return None
    j = sk_ws(text, ident['end'])
    if sub(text, j, j + 2) != '==':
        return None
    j = sk_ws(text, j + 2)
    num = rd_num(text, j)
    if not num:
        return None
    j = sk_ws(text, num['end'])
    if j < len(text) and text[j] == ')':
        j += 1
    j = sk_ws(text, j)
    if j < len(text):
        return None
    return {'stateVar': ident['name'], 'state': num['num']}


def rd_st_ne(cond):
    simp = simp_cond(cond)
    if not simp.get('text'):
        return None
    text = simp['text']
    i = sk_ws(text, 0)

    num_left = rd_num(text, i)
    if num_left:
        j = sk_ws(text, num_left['end'])
        if sub(text, j, j + 2) != '~=':
            return None
        j = sk_ws(text, j + 2)
        ident = rd_id(text, j)
        if not ident or not _state_var_ok(ident['name']):
            return None
        j = sk_ws(text, ident['end'])
        if j < len(text):
            return None
        return {'stateVar': ident['name'], 'state': num_left['num']}

    ident = rd_id(text, i)
    if not ident or not _state_var_ok(ident['name']):
        return None
    j = sk_ws(text, ident['end'])
    if sub(text, j, j + 2) != '~=':
        return None
    j = sk_ws(text, j + 2)
    num = rd_num(text, j)
    if not num:
        return None
    j = sk_ws(text, num['end'])
    if j < len(text):
        return None
    return {'stateVar': ident['name'], 'state': num['num']}


def rw_ne_empty(body):
    out = []
    i = 0
    while i < len(body):
        if body[i] in ('"', "'"):
            q = body[i]
            out.append(q)
            i += 1
            while i < len(body) and body[i] != q:
                if body[i] == '\\':
                    out.append(body[i])
                    i += 1
                    if i < len(body):
                        out.append(body[i])
                        i += 1
                else:
                    out.append(body[i])
                    i += 1
            if i < len(body):
                out.append(body[i])
                i += 1
            continue
        if wd_at(body, i, 'if'):
            then_at = find_wd_then(body, i + 2)
            if then_at >= 0:
                cond = body[i + 2:then_at].strip()
                ne = rd_st_ne(cond)
                if ne:
                    j = sk_ws(body, then_at + 4)
                    if wd_at(body, j, 'else'):
                        out.append('if (' + ne['stateVar'] + '==' + js_number_str(ne['state']) + ') then ')
                        i = j + 4
                        continue
        out.append(body[i])
        i += 1
    return ''.join(out)


def parse_if_ch(body):
    body = rw_ne_empty(body)
    cases = {}
    state_var = None
    leading_locals = ''
    i = sk_ws(body, 0)

    while i < len(body):
        i = sk_ws(body, i)
        while i < len(body) and body[i] == ';':
            i = sk_ws(body, i + 1)
        if i >= len(body):
            break
        if wd_at(body, i, 'local'):
            loc_start = i
            j = sk_ws(body, i + 5)
            ident = rd_id(body, j)
            if ident and _state_var_ok(ident['name']):
                j = sk_ws(body, ident['end'])
                if j >= len(body) or body[j] == ';' or is_ws(body[j]):
                    if char(body, j) == ';':
                        j += 1
                    piece = body[loc_start:j].strip()
                    if piece:
                        leading_locals += piece + (' ' if piece.endswith(';') else '; ')
                    i = j
                    continue
            return None
        if not wd_at(body, i, 'if'):
            return None

        then_at = find_wd_then(body, i + 2)
        if then_at < 0:
            return None
        cond = body[i + 2:then_at].strip()
        parsed = rd_st_eq(cond, state_var)
        if not parsed:
            return None
        if not state_var:
            state_var = parsed['stateVar']
        if parsed['stateVar'] != state_var:
            return None

        end_after = find_blk_end(body, i)
        if end_after < 0:
            return None
        case_body = body[then_at + 4:end_after - 3].strip()
        if parsed['state'] in cases:
            return None
        cases[parsed['state']] = case_body
        i = end_after

    if not state_var or not cases:
        return None
    return {'stateVar': state_var, 'cases': cases, 'leadingLocals': leading_locals}


def rd_asg_num(body, j):
    j = sk_ws(body, j)
    num = rd_num(body, j)
    if num:
        return {'state': num['num'], 'end': num['end']}
    needle = '(function() return'
    if body.startswith(needle, j):
        k = sk_ws(body, j + len(needle))
        n = rd_num(body, k)
        if not n:
            return None
        k = sk_ws(body, n['end'])
        if char(body, k) == ';':
            k = sk_ws(body, k + 1)
        if not body.startswith('end)()', k):
            return None
        return {'state': n['num'], 'end': k + 6}
    return None


def find_st_asg(body, state_var):
    last = None
    i = 0
    while i < len(body):
        if body[i] in ('"', "'"):
            q = body[i]
            i += 1
            while i < len(body) and body[i] != q:
                if body[i] == '\\':
                    i += 1
                i += 1
            i += 1
            continue
        if body.startswith(state_var, i):
            after = i + len(state_var)
            if after < len(body) and is_id(body[after]):
                i += 1
                continue
            j = sk_ws(body, after)
            if char(body, j) == '=':
                rhs = rd_asg_num(body, j + 1)
                if rhs:
                    last = {'state': rhs['state'], 'start': i, 'end': rhs['end']}
        i += 1
    return last


def strip_st_n(body, state_var):
    parts = []
    i = 0
    while i < len(body):
        if body[i] in ('"', "'"):
            i = sk_str_copy(body, i, parts)
            continue

        if body.startswith(state_var, i):
            after = i + len(state_var)
            if not (after < len(body) and is_id(body[after])):
                j = sk_ws(body, after)
                if char(body, j) == '=':
                    rhs = rd_asg_num(body, j + 1)
                    if rhs:
                        j = rhs['end']
                        if char(body, j) == ';':
                            j += 1
                        i = j
                        continue

        if wd_at(body, i, 'break'):
            j = i + 5
            if char(body, j) == ';':
                j += 1
            i = j
            continue

        parts.append(body[i])
        i += 1

    out = ''.join(parts)
    cleaned = []
    for c in out:
        if c == ';' and cleaned and cleaned[-1] == ';':
            continue
        cleaned.append(c)
    return ''.join(cleaned).strip()


def lin_cff(cases, state_var, init):
    parts = []
    seen = set()
    state = init
    guard = 0
    while state is not None and state not in seen and guard < 64:
        guard += 1
        seen.add(state)
        raw = cases.get(state)
        if raw is None:
            break
        assign = find_st_asg(raw, state_var)
        cleaned = strip_st_n(raw, state_var)
        if cleaned:
            parts.append(cleaned)
        if not assign and (has_wd(raw, 'return') or has_wd(raw, 'break')):
            break
        state = assign['state'] if assign else None
    if not parts:
        return None
    return ' '.join(parts)


def only_empty_loc(src, start, until):
    i = start
    while i < until:
        i = sk_ws(src, i)
        if i >= until:
            return True
        if src[i] == ';':
            i += 1
            continue
        if not wd_at(src, i, 'local'):
            return False
        j = sk_ws(src, i + 5)
        ident = rd_id(src, j)
        if not ident or not _state_var_ok(ident['name']):
            return False
        j = sk_ws(src, ident['end'])
        if char(src, j) in ('=', ','):
            return False
        if char(src, j) == ';':
            j += 1
        i = j
    return True


def find_init(src, while_at, state_var):
    start = max(0, while_at - 400)
    window = src[start:while_at]
    best = None
    j = 0
    while j < len(window):
        at = window.find(state_var, j)
        if at < 0:
            break
        abs_pos = start + at
        after = at + len(state_var)
        if after < len(window) and is_id(window[after]):
            j = at + 1
            continue
        k = sk_ws(window, after)
        if char(window, k) == '=':
            k = sk_ws(window, k + 1)
            num = rd_num(window, k)
            if num:
                assign_end = start + num['end']
                if only_empty_loc(src, assign_end, while_at):
                    begin = abs_pos
                    loc = src.rfind('local', 0, abs_pos + 5)
                    if loc >= 0 and loc >= abs_pos - 12 and wd_at(src, loc, 'local'):
                        begin = loc
                    best = {'init': num['num'], 'start': begin, 'end': assign_end}
        j = at + 1
    return best


def col_empty_loc(src, start, until):
    prefix = ''
    i = start
    while i < until:
        i = sk_ws(src, i)
        if i >= until:
            break
        if src[i] == ';':
            i += 1
            continue
        if wd_at(src, i, 'local'):
            loc_start = i
            j = sk_ws(src, i + 5)
            ident = rd_id(src, j)
            if not ident:
                break
            j = sk_ws(src, ident['end'])
            if char(src, j) == '=':
                break
            if char(src, j) == ',':
                break
            if char(src, j) == ';':
                j += 1
            piece = src[loc_start:j].strip()
            if piece:
                prefix += piece + (' ' if piece.endswith(';') else '; ')
            i = j
            continue
        break
    return prefix


def try_unflat(src, while_at):
    if not src.startswith('while true do', while_at):
        return None
    end_at = find_blk_end(src, while_at)
    if end_at < 0:
        return None

    body = src[while_at + 13:end_at - 3]

    parsed = parse_if_ch(body)
    if not parsed:
        return None

    init_info = find_init(src, while_at, parsed['stateVar'])
    if init_info:
        init = init_info['init']
    else:
        init = min(parsed['cases'].keys())
    entry = init if init in parsed['cases'] else min(parsed['cases'].keys())
    lin = lin_cff(parsed['cases'], parsed['stateVar'], entry)
    if not lin:
        return None

    start = init_info['start'] if init_info else while_at
    prefix = ''
    if init_info:
        prefix = col_empty_loc(src, init_info['end'], while_at)
    if parsed['leadingLocals']:
        prefix += parsed['leadingLocals']

    return {
        'start': start,
        'end': end_at,
        'code': (prefix + lin).strip(),
        'stateVar': parsed['stateVar'],
        'states': len(parsed['cases']),
    }


def cnt_occ(src, needle):
    n = 0
    i = 0
    while i < len(src):
        at = src.find(needle, i)
        if at < 0:
            break
        n += 1
        i = at + len(needle)
    return n


def unflat_cff(source):
    src = fold_const(str(source))
    replaced = 0
    states_total = 0
    guard = 0

    while guard < 800:
        guard += 1
        start = len(src)
        hit = None
        while start > 0:
            at = src.rfind('while true do', 0, start)
            if at < 0:
                break
            trial = try_unflat(src, at)
            if trial:
                hit = trial
                break
            start = at
        if not hit:
            break
        src = src[:hit['start']] + hit['code'] + src[hit['end']:]
        replaced += 1
        states_total += hit['states']

    return {
        'source': src,
        'replaced': replaced,
        'statesTotal': states_total,
        'remaining': cnt_occ(src, 'while true do'),
    }


def cnt_while(src):
    return cnt_occ(src, 'while true do')


def cnt_state(src):
    n = 0
    i = 0
    while i < len(src):
        at = src.find('local v', i)
        if at < 0:
            break
        j = at + 7
        while j < len(src) and '0' <= src[j] <= '9':
            j += 1
        if char(src, j) == '=' and '0' <= char(src, j + 1) <= '9':
            n += 1
        i = at + 7
    return n


def cnt_opaque(src):
    n = 0
    i = 0
    while i < len(src) - 4:
        if src[i] != '(':
            i += 1
            continue
        j = i + 1
        if not ('0' <= char(src, j) <= '9'):
            i += 1
            continue
        while j < len(src) and '0' <= src[j] <= '9':
            j += 1
        if sub(src, j, j + 2) != '==':
            i += 1
            continue
        j += 2
        begin = j
        while j < len(src) and '0' <= src[j] <= '9':
            j += 1
        if j > begin and char(src, j) == ')':
            n += 1
        i += 1
    return n


def inv_prot(source, extras=None):
    extras = extras or {}
    src = str(source)
    layers = []

    while_true = cnt_while(src)
    states = cnt_state(src)
    opaque = cnt_opaque(src)

    if 'bxor' in src or 'function v7(' in src or 'local function v7(' in src:
        layers.append({'id': 'xor'})
    if 'LOL!' in src or 'math.ldexp' in src or 'ldexp' in src:
        layers.append({'id': 'vm'})
    if extras.get('wrapperCff') and extras['wrapperCff'].get('replaced', 0) > 0:
        w = extras['wrapperCff']
        layers.append({
            'id': 'cff',
            'status': 'ok' if w.get('remaining', 0) <= 1 else 'partial',
            'metrics': dict({'whileTrue': while_true, 'states': states}, **w),
        })
    elif while_true >= 3 or states >= 5:
        layers.append({'id': 'cff', 'status': 'seen', 'metrics': {'whileTrue': while_true, 'states': states}})
    if opaque > 0:
        layers.append({'id': 'opaque', 'metrics': {'opaque': opaque}})
    if 'getfenv' in src or 'setmetatable' in src:
        layers.append({'id': 'env'})
    if extras.get('bytecodeCff') and extras['bytecodeCff'].get('removed', 0) > 0:
        layers.append({'id': 'bc_cff', 'metrics': extras['bytecodeCff']})
    elif extras.get('bytecodeCff') and extras['bytecodeCff'].get('jmps', 0) > 0:
        layers.append({'id': 'bc_jmp', 'metrics': extras['bytecodeCff']})

    return {'layers': layers, 'metrics': {'whileTrue': while_true, 'states': states, 'opaque': opaque}}


# ---------------------------------------------------------------------------
# family detection
# ---------------------------------------------------------------------------


def find_pln(src, word, start=0):
    i = start
    while i < len(src):
        at = src.find(word, i)
        if at < 0:
            return -1
        if wd_at(src, at, word):
            return at
        i = at + 1
    return -1


def parse_ver(src):
    alpha_at = 0
    while True:
        alpha_at = src.find('Alpha ', alpha_at)
        if alpha_at < 0:
            return None
        ver = src[alpha_at + 6:alpha_at + 20]
        if char(ver, 0) == '0' and char(ver, 1) == '.':
            i = 2
            while i < len(ver) and is_dig(ver[i]):
                i += 1
            if char(ver, i) == '.':
                i += 1
                begin = i
                while i < len(ver) and is_dig(ver[i]):
                    i += 1
                if i > begin:
                    return ver[:i]
        alpha_at += 6


def has_wrap(src):
    start = 0
    while start < len(src):
        at = find_pln(src, 'return', start)
        if at < 0:
            return False
        j = sk_ws(src, at + 6)
        a = rd_id(src, j)
        if a and char(src, a['end']) == '(':
            j = sk_ws(src, a['end'] + 1)
            b = rd_id(src, j)
            if b and sub(src, b['end'], b['end'] + 2) == '()':
                j = sk_ws(src, b['end'] + 2)
                if char(src, j) == ',':
                    j = sk_ws(src, j + 1)
                    if sub(src, j, j + 2) == '{}':
                        return True
        start = at + 6
    return False


def has_op_unpk(src):
    start = 0
    while start < len(src):
        at = src.find('[1]', start)
        if at < 0:
            return False
        i = at - 1
        while i >= 0 and is_ws(src[i]):
            i -= 1
        if i < 0 or not is_id(src[i]):
            start = at + 3
            continue
        while i >= 0 and is_id(src[i]):
            i -= 1
        inst = src[i + 1:at]
        if not inst or inst[0] != 'v':
            start = at + 3
            continue
        window = src[at:at + 280]
        if '[2]' not in window:
            start = at + 3
            continue
        if '[3]' in window:
            return True
        needle = inst + '['
        hits = 1
        pos = 0
        while hits < 3:
            p = window.find(needle, pos)
            if p < 0:
                break
            hits += 1
            pos = p + len(needle)
        if hits >= 3:
            return True
        start = at + 3
    return False


def has_op_tree(src):
    hits = 0
    start = 0
    while start < len(src) and hits < 3:
        at = src.find('<=', start)
        if at < 0:
            break
        i = at - 1
        while i >= 0 and is_ws(src[i]):
            i -= 1
        while i >= 0 and is_id(src[i]):
            i -= 1
        left = src[i + 1:at].strip()
        if left and left[0] == 'v' and is_dig(char(left, 1)):
            j = sk_ws(src, at + 2)
            if is_dig(char(src, j)):
                hits += 1
        start = at + 2
    return hits >= 3


def has_vm_loop(src):
    start = 0
    while start < len(src):
        at = src.find('while true do', start)
        if at < 0:
            return False
        window = src[at:at + 1200]
        fetch = False
        tree = False
        k = 0
        while k < len(window):
            ident = rd_id(window, k)
            if not ident or not _state_var_ok(ident['name']):
                k += 1
                continue
            j = sk_ws(window, ident['end'])
            if char(window, j) != '=':
                k = ident['end']
                continue
            j = sk_ws(window, j + 1)
            r = rd_id(window, j)
            if not r or char(window, r['end']) != '[':
                k = ident['end']
                continue
            inner = rd_id(window, r['end'] + 1)
            if inner and char(window, inner['end']) == ']':
                fetch = True
            k = ident['end']
        le = 0
        p = 0
        while True:
            p = window.find('<=', p)
            if p < 0:
                break
            le += 1
            p += 2
        if le >= 2:
            tree = True
        if fetch and tree:
            return True
        start = at + 13
    return False


def find_lol(src):
    def try_fn(fn):
        try:
            calls = find_v7_calls(src) if fn == 'v7' else find_dec(src, fn)
            for c in calls:
                if c['text'].startswith('LOL!'):
                    return {'found': True, 'fn': fn, 'preview': c['text'][:24], 'plain': False}
        except Exception:
            pass
        return None

    hit = try_fn('v7')
    if hit:
        return hit
    xor_nm = find_xor_nm(src)
    if xor_nm and xor_nm != 'v7':
        hit = try_fn(xor_nm)
        if hit:
            return hit
    at = src.find('"LOL!')
    if at >= 0:
        return {'found': True, 'fn': None, 'preview': src[at + 1:at + 25], 'plain': True}
    return {'found': False, 'fn': None, 'preview': None, 'plain': False}


def has_xor_bod(body):
    key_mix = '% #' in body or '%#' in body
    xor_use = 'bxor' in body or key_mix
    mod256 = ('%256' in body
              or '% 256' in body
              or '%(256' in body
              or ('%(' in body and ('256' in body or '150' in body or '106' in body)))
    char_pipe = 'v0(' in body or 'char' in body or mod256
    return xor_use and (mod256 or (key_mix and char_pipe))


def find_xor_nm(src):
    start = 0
    while start < len(src):
        at = src.find('function', start)
        if at < 0:
            return None
        if not wd_at(src, at, 'function'):
            start = at + 8
            continue
        j = sk_ws(src, at + 8)
        name = rd_id(src, j)
        if not name or char(src, name['end']) != '(':
            start = at + 8
            continue
        close = src.find(')', name['end'])
        if close < 0:
            return None
        depth = 1
        k = close + 1
        begin = k
        while k < len(src) and depth > 0:
            if src[k] in ('"', "'"):
                q = src[k]
                k += 1
                while k < len(src) and src[k] != q:
                    if src[k] == '\\':
                        k += 1
                    k += 1
                k += 1
                continue
            if wd_at(src, k, 'function') or wd_at(src, k, 'then') or wd_at(src, k, 'do') or wd_at(src, k, 'repeat'):
                depth += 1
                ident = rd_id(src, k)
                k = ident['end'] if ident else k + 1
                continue
            if wd_at(src, k, 'end'):
                depth -= 1
                if depth == 0:
                    body = src[begin:k]
                    if has_xor_bod(body):
                        return name['name']
                    break
                k += 3
                continue
            k += 1
        start = at + 8
    return None


def find_boot(src):
    need = ['string.char', 'string.byte', 'string.sub', 'bit32 or bit', '.bxor',
            'table.concat', 'table.insert']
    start = 0
    while start < len(src):
        anchor = src.find('string.char', start)
        if anchor < 0:
            return None
        pos = anchor
        ok = True
        for token in need:
            at = src.find(token, pos)
            if at < 0 or at > anchor + 500:
                ok = False
                break
            pos = at + len(token)
        if not ok:
            start = anchor + 11
            continue
        tail = src[pos:pos + 80]
        if 'function' not in tail:
            start = anchor + 11
            continue
        return {'start': anchor, 'afterAliases': pos}
    return None


def has_fn_v(slice_):
    start = 0
    while start < len(slice_):
        at = slice_.find('function', start)
        if at < 0:
            return False
        if not wd_at(slice_, at, 'function'):
            start = at + 8
            continue
        j = sk_ws(slice_, at + 8)
        if char(slice_, j) == 'v' and is_dig(char(slice_, j + 1)):
            while j < len(slice_) and is_dig(slice_[j]):
                j += 1
            j = sk_ws(slice_, j)
            if char(slice_, j) == '(':
                return True
        start = at + 8
    return False


def has_boot(src):
    boot = find_boot(src)
    if not boot:
        return False
    fn = find_xor_nm(src)
    if fn:
        return True
    slice_ = src[boot['afterAliases']:boot['afterAliases'] + 2500]
    if not has_fn_v(slice_):
        return False
    return has_xor_bod(slice_)


def strip_tail(src):
    t = str(src).rstrip()
    guard = 0
    while guard < 20 and t:
        guard += 1
        t = t.rstrip()
        nl = t.rfind('\n')
        line = (t if nl < 0 else t[nl + 1:]).strip()
        if line.startswith('--') and '[[' not in line and ']]' not in line:
            t = '' if nl < 0 else t[:nl]
            continue
        if t.endswith(']]--'):
            opn = t.rfind('--[[')
            if opn >= 0:
                t = t[:opn]
                continue
        if t.endswith(']]'):
            opn = t.rfind('--[[')
            if opn >= 0:
                t = t[:opn]
                continue
        break
    return t.rstrip()


def scan_blk(src):
    depth = 0
    max_depth = 0
    i = 0
    in_str = None
    while i < len(src):
        c = src[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ('"', "'"):
            in_str = c
            i += 1
            continue
        if c == '[' and char(src, i + 1) in ('[', '='):
            j = i + 1
            eq = 0
            while char(src, j) == '=':
                eq += 1
                j += 1
            if char(src, j) == '[':
                close = ']' + '=' * eq + ']'
                at = src.find(close, j + 1)
                i = len(src) if at < 0 else at + len(close)
                continue
        if c == '-' and char(src, i + 1) == '-':
            if char(src, i + 2) == '[':
                j = i + 3
                eq = 0
                while char(src, j) == '=':
                    eq += 1
                    j += 1
                if char(src, j) == '[':
                    close = ']' + '=' * eq + ']'
                    at = src.find(close, j + 1)
                    i = len(src) if at < 0 else at + len(close)
                    continue
            while i < len(src) and src[i] != '\n':
                i += 1
            continue
        if wd_at(src, i, 'function') or wd_at(src, i, 'then') or wd_at(src, i, 'do') or wd_at(src, i, 'repeat'):
            depth += 1
            if depth > max_depth:
                max_depth = depth
            ident = rd_id(src, i)
            i = ident['end'] if ident else i + 1
            continue
        if wd_at(src, i, 'end'):
            depth -= 1
            i += 3
            continue
        i += 1
    return {'depth': depth, 'max': max_depth, 'openStr': bool(in_str)}


def is_trunc(src):
    t = strip_tail(src)
    if not t:
        return {'bad': True, 'reason': 'empty_source'}
    bal = scan_blk(t)
    last = t[-1]
    ok_end = last in (')', ';', '}', 'd', ']')

    if last in (',', '=', '(', '[', '{', '.', '+', '*', '/', '%', '^', '#'):
        return {'bad': True, 'reason': 'ends_mid_expr'}
    if last == '-' and not t.endswith('end'):
        return {'bad': True, 'reason': 'ends_mid_expr'}

    i = len(t) - 1
    while i >= 0 and t[i] in ' \t\n\r':
        i -= 1
    j = i
    while j >= 0 and is_id(t[j]):
        j -= 1
    tail_id = t[j + 1:i + 1]
    if tail_id and j >= 0 and t[j] == ',':
        return {'bad': True, 'reason': 'ends_mid_list'}
    if tail_id == 'v' or (tail_id and tail_id[0] == 'v' and is_dig(char(tail_id, 1))
                          and j >= 0 and t[j] in (',', '=')):
        before = t[max(0, len(t) - 60):]
        if 'for ' in before:
            return {'bad': True, 'reason': 'ends_mid_for'}

    if bal['openStr'] and not ok_end:
        return {'bad': True, 'reason': 'unclosed_string'}

    if bal['depth'] > 0 and bal['depth'] == bal['max'] and bal['max'] >= 20 and not ok_end:
        return {'bad': True, 'reason': 'unclosed_blocks'}

    if not ok_end:
        return {'bad': True, 'reason': 'bad_tail'}

    return {'bad': False, 'reason': None, 'bal': bal}


def val_fam(src, family, bits):
    trunc = is_trunc(src)
    if trunc['bad']:
        return {'ok': False, 'reason': 'invalid_syntax:' + trunc['reason']}

    if family == 'luaobfuscator-chaotic-evil':
        if not bits['lol'] and not bits['wrap']:
            return {'ok': False, 'reason': 'incomplete_evil:missing_lol_or_wrap'}
        if not bits['ldexp'] and not bits['lol']:
            return {'ok': False, 'reason': 'incomplete_evil:missing_vm_shape'}
        if not (bits['bootstrap'] or bits['xorFn'] or bits['hasXor']):
            return {'ok': False, 'reason': 'incomplete_evil:missing_xor_bootstrap'}
        return {'ok': True, 'reason': None}

    if family == 'luaobfuscator-chaotic-good':
        if not bits['bootstrap']:
            return {'ok': False, 'reason': 'incomplete_good:missing_bootstrap'}
        if not bits['xorFn'] and not bits['hasXor']:
            return {'ok': False, 'reason': 'incomplete_good:missing_xor'}
        if bits['ldexp']:
            return {'ok': False, 'reason': 'invalid_good:vm_double_reader'}
        return {'ok': True, 'reason': None}

    if family == 'luaobfuscator-v1':
        if not bits['lol']:
            return {'ok': False, 'reason': 'incomplete_v1:missing_lol'}
        if not bits['ldexp']:
            return {'ok': False, 'reason': 'incomplete_v1:missing_vm_shape'}
        if not bits['bootstrap']:
            return {'ok': False, 'reason': 'incomplete_v1:missing_bootstrap'}
        return {'ok': True, 'reason': None}

    return {'ok': False, 'reason': 'unknown_family'}


def det(source):
    src = str(source)
    signals = []

    lol = find_lol(src)
    wrap = has_wrap(src)
    ldexp = 'math.ldexp' in src or ('ldexp' in src and 'math' in src)
    unpack = has_op_unpk(src)
    tree = has_op_tree(src)
    loop = has_vm_loop(src)
    watermark = ('LuaObfuscator.com' in src
                 or 'Much Love, Ferib' in src
                 or 'Much Love,Ferib' in src)
    version = parse_ver(src)
    xor_fn = find_xor_nm(src)
    bootstrap = has_boot(src)
    has_xor = 'bxor' in src and ('bit32' in src or 'string.char' in src)

    if lol['found']:
        signals.append('lol_bytecode')
    if wrap:
        signals.append('vm_wrap_return')
    if ldexp:
        signals.append('double_reader')
    if unpack:
        signals.append('opcode_unpack')
    if tree:
        signals.append('opcode_tree')
    if loop:
        signals.append('vm_dispatch')
    if watermark:
        signals.append('ferib_watermark')
    if version:
        signals.append('alpha_version')
    if xor_fn:
        signals.append('xor_fn:' + xor_fn)
    if bootstrap:
        signals.append('good_bootstrap')
    if has_xor:
        signals.append('xor_decrypt')

    opcode_score = (1 if unpack else 0) + (1 if tree else 0) + (1 if loop else 0) + (1 if ldexp else 0)
    bits = {
        'lol': lol['found'],
        'wrap': wrap,
        'ldexp': ldexp,
        'unpack': unpack,
        'tree': tree,
        'loop': loop,
        'bootstrap': bootstrap,
        'xorFn': xor_fn,
        'hasXor': has_xor,
        'opcodeScore': opcode_score,
    }

    if lol['found'] and lol['plain'] and ldexp and bootstrap:
        family = 'luaobfuscator-v1'
    elif lol['found'] or (wrap and opcode_score >= 2) or (wrap and ldexp and unpack):
        family = 'luaobfuscator-chaotic-evil'
    elif ldexp and (tree or loop):
        family = 'luaobfuscator-chaotic-evil'
    elif bootstrap and not lol['found'] and not wrap and not ldexp:
        family = 'luaobfuscator-chaotic-good'
    else:
        family = None

    candidate = family
    reason = None
    valid = False
    if not family:
        reason = 'not_luaobfuscator'
    else:
        v = val_fam(src, family, bits)
        valid = v['ok']
        reason = v['reason']
        if not valid:
            family = None

    matched = valid and bool(family)

    return {
        'matched': matched,
        'family': family if matched else None,
        'candidate': family if matched else candidate,
        'valid': valid,
        'reason': reason,
        'version': version,
        'score': len(signals),
        'signals': signals,
        'lol': {'fn': lol['fn'], 'preview': lol['preview']} if lol['found'] else None,
        'opcodes': ({'unpack': unpack, 'tree': tree, 'loop': loop, 'ldexp': ldexp, 'wrap': wrap}
                    if matched and family == 'luaobfuscator-chaotic-evil' else None),
        'format': {'bootstrap': True, 'xorFn': xor_fn}
                  if matched and family == 'luaobfuscator-chaotic-good' else None,
    }


# ---------------------------------------------------------------------------
# Chaotic Good reconstruction
# ---------------------------------------------------------------------------


def strip_wm(src):
    s = str(src)
    out = []
    i = 0
    while i < len(s):
        c = s[i]

        if c in ('"', "'"):
            q = c
            out.append(q)
            i += 1
            while i < len(s) and s[i] != q:
                if s[i] == '\\':
                    out.append(s[i])
                    i += 1
                    if i < len(s):
                        out.append(s[i])
                        i += 1
                else:
                    out.append(s[i])
                    i += 1
            if i < len(s):
                out.append(s[i])
                i += 1
            continue

        if c == '[':
            j = i + 1
            eq = 0
            while char(s, j) == '=':
                eq += 1
                j += 1
            if char(s, j) == '[':
                close = ']' + '=' * eq + ']'
                at = s.find(close, j + 1)
                if at < 0:
                    out.append(s[i:])
                    break
                out.append(s[i:at + len(close)])
                i = at + len(close)
                continue

        if c == '-' and char(s, i + 1) == '-':
            if char(s, i + 2) == '[':
                j = i + 3
                eq = 0
                while char(s, j) == '=':
                    eq += 1
                    j += 1
                if char(s, j) == '[':
                    close = ']' + '=' * eq + ']'
                    at = s.find(close, j + 1)
                    i = len(s) if at < 0 else at + len(close)
                    continue
            i += 2
            while i < len(s) and s[i] != '\n':
                i += 1
            continue

        out.append(c)
        i += 1
    return ''.join(out)


def find_end(src, start):
    depth = 1
    i = start
    while i < len(src):
        if src[i] in ('"', "'"):
            q = src[i]
            i += 1
            while i < len(src) and src[i] != q:
                if src[i] == '\\':
                    i += 1
                i += 1
            i += 1
            continue
        if src[i] == '-' and char(src, i + 1) == '-':
            if char(src, i + 2) == '[':
                j = i + 3
                eq = 0
                while char(src, j) == '=':
                    eq += 1
                    j += 1
                if char(src, j) == '[':
                    close = ']' + '=' * eq + ']'
                    at = src.find(close, j + 1)
                    i = len(src) if at < 0 else at + len(close)
                    continue
            while i < len(src) and src[i] != '\n':
                i += 1
            continue
        if wd_at(src, i, 'function') or wd_at(src, i, 'then') or wd_at(src, i, 'do') or wd_at(src, i, 'repeat'):
            ident = rd_id(src, i)
            depth += 1
            i = ident['end'] if ident else i + 1
            continue
        if wd_at(src, i, 'end'):
            depth -= 1
            if depth == 0:
                return i
            i += 3
            continue
        i += 1
    return -1


def find_xor(src):
    start = 0
    while start < len(src):
        at = src.find('function', start)
        if at < 0:
            break
        if not wd_at(src, at, 'function'):
            start = at + 8
            continue
        j = sk_ws(src, at + 8)
        name = rd_id(src, j)
        if not name or char(src, name['end']) != '(':
            start = at + 8
            continue
        body_start = src.find(')', name['end'])
        if body_start < 0:
            break
        end_at = find_end(src, body_start + 1)
        if end_at < 0:
            start = at + 8
            continue
        body = src[body_start + 1:end_at]
        if ('%256' in body
                or 'bxor' in body
                or ('char' in body and 'byte' in body)):
            decl_start = at
            k = at
            while k > 0 and is_ws(src[k - 1]):
                k -= 1
            if k >= 5 and wd_at(src, k - 5, 'local'):
                decl_start = k - 5
            return {'name': name['name'], 'start': decl_start, 'end': end_at + 3}
        start = at + 8
    return None


def is_xor_alias(path):
    if path in ('bit32', 'bit'):
        return True
    if path.endswith('.bxor'):
        return True
    dot = path.find('.')
    if dot <= 0:
        return False
    lib = path[:dot]
    return lib in ('string', 'table')


def strip_xor_boot(src, fn_name):
    out = src
    fn = find_xor(out)
    limit = len(out)
    if fn and (not fn_name or fn['name'] == fn_name):
        limit = fn['start']
        out = out[:fn['start']] + out[fn['end']:]
    else:
        limit = min(len(out), 1200)

    guard = 0
    while guard < 20:
        guard += 1
        changed = False
        i = 0
        while i < len(out) and i < limit:
            if not wd_at(out, i, 'local'):
                i += 1
                continue
            begin = i
            j = sk_ws(out, i + 5)
            name = rd_id(out, j)
            if not name:
                i += 1
                continue
            j = sk_ws(out, name['end'])
            if char(out, j) != '=':
                i = name['end']
                continue
            j = sk_sp(out, j + 1)
            if out.startswith('bit32 or bit', j) or out.startswith('bit or bit32', j):
                end = j + 12
                while end < len(out) and out[end] != ';':
                    end += 1
                if char(out, end) == ';':
                    end += 1
                removed = end - begin
                out = out[:begin] + out[end:]
                limit = max(0, limit - removed)
                changed = True
                break
            rhs = rd_id(out, j)
            if not rhs:
                i = name['end']
                continue
            k = rhs['end']
            path = rhs['name']
            while char(out, k) == '.':
                part = rd_id(out, k + 1)
                if not part:
                    break
                path += '.' + part['name']
                k = part['end']
            if is_xor_alias(path):
                end = k
                while end < len(out) and out[end] != ';':
                    end += 1
                if char(out, end) == ';':
                    end += 1
                removed = end - begin
                out = out[:begin] + out[end:]
                limit = max(0, limit - removed)
                changed = True
                break
            i = name['end']
        if not changed:
            break

    return out


def tidy_sp(src):
    out = []
    i = 0
    while i < len(src):
        c = src[i]
        n = char(src, i + 1)
        if c == ' ' and n in (';', ',', ')', '}', '\n'):
            i += 1
            continue
        if c in ('(', '{') and n == ' ':
            out.append(c)
            while char(src, i + 1) == ' ':
                i += 1
            i += 1
            continue
        if c == ';' and n == ';':
            i += 1
            continue
        out.append(c)
        i += 1
    return ''.join(out).strip()


def clean_noise(src):
    out = []
    i = 0
    while i < len(src):
        if src[i] in ('"', "'"):
            q = src[i]
            out.append(q)
            i += 1
            while i < len(src) and src[i] != q:
                if src[i] == '\\':
                    out.append(src[i])
                    i += 1
                    if i < len(src):
                        out.append(src[i])
                        i += 1
                else:
                    out.append(src[i])
                    i += 1
            if i < len(src):
                out.append(src[i])
                i += 1
            continue
        if src[i] == ';' and char(src, i + 1) == ';':
            out.append(';')
            i += 2
            while char(src, i) == ';':
                i += 1
            continue
        if src[i] == ' ' and char(src, i + 1) == ' ':
            out.append(' ')
            i += 1
            while char(src, i) == ' ':
                i += 1
            continue
        if src[i] == ',' and char(src, i + 1) == ' ':
            out.append(', ')
            i += 2
            while char(src, i) == ' ':
                i += 1
            continue
        out.append(src[i])
        i += 1
    return tidy_sp(''.join(out))


def is_fmt_open(name):
    return name in ('then', 'do', 'repeat', 'else')


def fmt_lua(src):
    out = []
    ind = 0
    i = 0
    line = []

    def flush():
        nonlocal line
        t = ''.join(line).rstrip()
        if t:
            out.append('  ' * max(0, ind) + t.lstrip() + '\n')
        line = []

    def sk_str_local():
        nonlocal i
        q = src[i]
        line.append(q)
        i += 1
        while i < len(src) and src[i] != q:
            if src[i] == '\\':
                line.append(src[i])
                i += 1
                if i < len(src):
                    line.append(src[i])
                    i += 1
            else:
                line.append(src[i])
                i += 1
        if i < len(src):
            line.append(src[i])
            i += 1

    def copy_par():
        nonlocal i
        if char(src, i) != '(':
            return False
        depth = 0
        while i < len(src):
            if src[i] in ('"', "'"):
                sk_str_local()
                continue
            if src[i] == '(':
                depth += 1
            if src[i] == ')':
                depth -= 1
                line.append(src[i])
                i += 1
                if depth == 0:
                    return True
                continue
            line.append(src[i])
            i += 1
        return False

    while i < len(src):
        if src[i] in ('"', "'"):
            sk_str_local()
            continue
        if src[i] == '-' and char(src, i + 1) == '-':
            flush()
            j = i
            if char(src, j + 2) == '[':
                k = j + 3
                eq = 0
                while char(src, k) == '=':
                    eq += 1
                    k += 1
                if char(src, k) == '[':
                    close = ']' + '=' * eq + ']'
                    at = src.find(close, k + 1)
                    j = len(src) if at < 0 else at + len(close)
                    out.append(src[i:j] + '\n')
                    i = j
                    continue
            while j < len(src) and src[j] != '\n':
                j += 1
            out.append(src[i:j] + '\n')
            i = j + (1 if char(src, j) == '\n' else 0)
            continue

        ident = rd_id(src, i)
        if ident:
            if ident['name'] in ('elseif', 'else'):
                ind = max(0, ind - 1)
                flush()
                line.append(ident['name'])
                i = ident['end']
                if ident['name'] == 'else':
                    flush()
                    ind += 1
                continue
            if ident['name'] in ('end', 'until'):
                ind = max(0, ind - 1)
                flush()
                line.append(ident['name'])
                i = ident['end']
                flush()
                continue
            if ident['name'] == 'function':
                line.append('function')
                i = ident['end']
                while i < len(src) and is_ws(src[i]):
                    line.append(src[i])
                    i += 1
                name = rd_id(src, i)
                if name:
                    line.append(name['name'])
                    i = name['end']
                    while i < len(src) and is_ws(src[i]):
                        line.append(src[i])
                        i += 1
                if char(src, i) == '(':
                    copy_par()
                    flush()
                    ind += 1
                continue
            line.append(ident['name'])
            i = ident['end']
            if is_fmt_open(ident['name']):
                flush()
                ind += 1
            continue

        if src[i] == ';':
            i += 1
            flush()
            continue
        if src[i] == '\n':
            flush()
            i += 1
            continue
        line.append(src[i])
        i += 1
    flush()
    return col_blank(''.join(out))


def col_blank(src):
    out = []
    nl = 0
    for c in src:
        if c == '\n':
            nl += 1
            if nl <= 2:
                out.append(c)
        else:
            nl = 0
            out.append(c)
    return ''.join(out).strip() + '\n'


def deobf_gd(source):
    src = strip_wm(str(source))
    xor = find_xor(src)
    fn_name = xor['name'] if xor else 'v7'

    if fn_name == 'v7':
        outer = dec_outer(src)
    else:
        outer = [{'index': c['index'], 'decrypted': c['text'], 'kind': 'outer_v7'}
                 for c in find_dec(src, fn_name)]

    if fn_name == 'v7':
        rewritten = rw_outer(src, fn_name)
    else:
        calls = sorted(find_dec(src, fn_name), key=lambda c: c['index'], reverse=True)
        text = src
        replaced = 0
        for call in calls:
            text = text[:call['index']] + json.dumps(call['text'], ensure_ascii=False) + text[call['end'] + 1:]
            replaced += 1
        rewritten = {'source': text, 'replaced': replaced}

    cff1 = unflat_cff(rewritten['source'])
    folded = fold_const(cff1['source'])
    cff2 = unflat_cff(folded)
    cleaned = strip_xor_boot(cff2['source'], fn_name)
    cleaned = fold_const(cleaned)
    cleaned = clean_noise(cleaned)
    cleaned = strip_xor_boot(cleaned, fn_name)
    cleaned = strip_wm(cleaned)
    lua = fmt_lua(cleaned)

    return {
        'family': 'luaobfuscator-chaotic-good',
        'strings': {
            'outer': outer,
            'summary': {'outerCount': len(outer), 'outerReplaced': rewritten['replaced']},
        },
        'wrapperCff': {
            'replaced': cff1['replaced'] + cff2['replaced'],
            'statesTotal': cff1['statesTotal'] + cff2['statesTotal'],
            'remaining': cff2['remaining'],
        },
        'lua': lua,
        'reconstructed': lua,
    }
