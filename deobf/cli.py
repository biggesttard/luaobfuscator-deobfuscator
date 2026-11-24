"""Command line interface for deobf.

Python port of ``index.js``.
"""

from __future__ import annotations

import json
import os
import sys

from .deobf import deobf, DeobfError

USAGE = 'deobf <file.lua> [--out out.lua] [--disasm] [--json] [--stdout]\n'


def line_count(text):
    if not text:
        return 0
    return len(str(text).splitlines()) or 1


def main(argv=None):
    argv = list(sys.argv if argv is None else argv)
    args = argv[1:]

    if not args or '-h' in args or '--help' in args:
        sys.stderr.write(USAGE)
        return 0 if args else 1

    file = next((a for a in args if not a.startswith('-')), None)
    if not file:
        sys.stderr.write(USAGE)
        return 1

    out_path = None
    if '--out' in args:
        idx = args.index('--out')
        if idx + 1 < len(args):
            out_path = args[idx + 1]

    want_disasm = '--disasm' in args
    want_json = '--json' in args
    want_stdout = '--stdout' in args

    abs_in = os.path.abspath(file)
    # Mirror the original (Buffer -> utf8): undecodable bytes become U+FFFD.
    with open(abs_in, 'rb') as fh:
        source = fh.read().decode('utf-8', 'replace')

    try:
        result = deobf(source, {'log': not want_json})
    except DeobfError as exc:
        sys.stderr.write('\x1b[31m[err] ' + str(exc) + '\x1b[0m\n')
        return 1
    except Exception as exc:  # noqa: BLE001 - mirror the reference CLI behaviour
        sys.stderr.write('\x1b[31m[err] ' + str(exc) + '\x1b[0m\n')
        return 1

    detection = result['detection']
    is_good = detection.get('family') == 'luaobfuscator-chaotic-good'

    if want_json:
        vm_info = result.get('vm')
        payload = {
            'detection': detection,
            'vm': ({
                'opcodeCount': vm_info['opcodeCount'],
                'closureLocalOp': vm_info['closureLocalOp'],
                'usedMap': vm_info['usedMap'],
                'nameToOpcodes': vm_info['nameToOpcodes'],
            } if vm_info else None),
            'lua': result['lua'],
            'disasm': result['disasm'],
        }
        text = json.dumps(payload, indent=2)
        if out_path:
            with open(os.path.abspath(out_path), 'w', encoding='utf-8') as fh:
                fh.write(text)
        else:
            sys.stdout.write(text + '\n')
        return 0

    if want_disasm and not is_good:
        output = result['disasm'] + '\n\n' + result['reconstructed'] + '\n\n' + result['lifted'] + '\n'
    else:
        output = result['reconstructed']

    if out_path:
        dest = os.path.abspath(out_path)
    else:
        dest = os.path.join(os.getcwd(), 'output', os.path.basename(abs_in), 'deobfuscated.lua')

    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, 'w', encoding='utf-8') as fh:
        fh.write(output)

    sys.stderr.write('lines=' + str(line_count(output)) + '\n')
    sys.stderr.write(dest + '\n')

    if want_stdout:
        sys.stdout.write(output)
    return 0


if __name__ == '__main__':
    sys.exit(main())
