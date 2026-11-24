from deobf import luaio as io


def mk_proto(raw):
    def mk_ins(item):
        if item is None:
            return None
        return io.Instr(
            opcode=item.get('opcode'),
            A=item.get('A'),
            B=item.get('B'),
            C=item.get('C'),
            mode=item.get('mode'),
            kFlags=item.get('kFlags') or 0,
            isKA=bool(item.get('isKA')),
            isKB=bool(item.get('isKB')),
            isKC=bool(item.get('isKC')),
            skipped=bool(item.get('skipped')),
        )

    return io.Proto(
        params=raw['params'],
        constants=list(raw['constants']),
        instructions=[mk_ins(i) for i in raw['instructions']],
        prototypes=[mk_proto(p) for p in raw['prototypes']],
    )


def opcode_map(spec):
    return {int(k): v for k, v in spec['opcodeMap'].items()}
