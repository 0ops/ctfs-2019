import re

import capstone


def readb(filename):
    with open(filename, 'rb') as fin:
        return fin.read()


def solve7(c1, c2, c3, c4, c5, c6, c7):
    sol1 = [c for c in range(256) if (c ** 2 * c5 + c * c3 + c6) % (c * c4 + c7) == 0]
    sol2 = [c for c in range(256) if (c * c1 + c2) % 256 in sol1]
    if len(sol2) != 1:
        print('Warning:', sol2)
    return sol2[0]


cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
code = readb('./cursed_app.elf')[0x117f:0x1f3b]

consts = []

for address, size, mnemonic, op_str in cs.disasm_lite(code, 0x117f):
    if mnemonic == 'movsx':
        print('---')
        print(len(consts))
        assert len(consts) % 7 == 0
    if mnemonic == 'imul' and len(op_str) > 10:
        consts.append(int(op_str[10:], 0))
    elif mnemonic == 'add' and op_str.startswith('eax, '):
        consts.append(int(op_str[5:], 0))
    elif mnemonic == 'lea':
        # print('lea', op_str)
        if op_str in ('eax, [rax + rax*4]', 'edx, [rdx + rdx*4]'):
            consts.append(5)
        else:
            consts.append(int(re.findall(r'\+ ([0-9a-fx]+)\]', op_str, re.IGNORECASE)[0], 0))

        if 'rdx*8' in op_str:
            consts.insert(-3, 8)
        elif 'rdx + rdx + ' in op_str:
            consts.insert(-3, 2)
    elif mnemonic == 'shl':
        print('shl', op_str)
        if op_str == 'edx, 5':
            consts.append(32)


print(consts)
print(len(consts))
print(bytes(print('Solve:', i) or solve7(*consts[i*7:i*7+7]) for i in range(59)))
