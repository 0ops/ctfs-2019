#!/usr/bin/env python
from pwn import *

import sys
import re
from Crypto.Util.number import *

'''
def keygen(nbit):
    while True:
        p = getPrime(nbit)
        a, b, c, d = [random.randint(1, p-1) for _ in range(4)]
        key = p, a, b, c, d
        if gcd(a, b) * gcd(c, d) == 1 and isPrime(p) > 0 and a*d - b*c != 0:
            return key


def encrypt(msg, key):
    msg = bytes_to_long(msg)
    p, a, b, c, d = key
    assert msg < p
    m_d = (msg * a + b) % p
    m_n = (msg * c + d) % p
    if m_n > 0:
        return int(m_d * inverse(m_n, p)) % p
    else:
        return 'encryption failed'
'''
io = remote('76.74.177.206', 1337)
chall = io.recvline()
pattern = re.compile(r'Please submit a printable string X, such that (\w+)\(X\)\[-6:\] = (\w+) and len\(X\) = (\d+)')
algo, suffix, length = re.findall(pattern, chall)[0]
algo = eval(algo+'sumhex')
length = int(length)
answer = iters.bruteforce(lambda x: algo(x).endswith(suffix), string.printable.strip(), length, 'fixed')
io.sendline(answer)

io.sendlineafter('[Q]uit!', 't')
io.recvuntil('is: ')
encflag = int(io.recvline())

data = []
for i in range(10):
    io.sendlineafter('[Q]uit!', 's')
    io.sendline(long_to_bytes(i))
    io.recvuntil('enc = ')
    enc = int(io.recvline())
    data.append((i, enc))

print 'encflag =', encflag
print 'data =',data
