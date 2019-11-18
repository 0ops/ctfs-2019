#!/usr/bin/env python

import random
from Crypto.Util.number import *
from flag import flag

def gen_rand(nbit, l):
    R = []
    while True:
        r = random.randint(0, nbit-1)
        if r not in R:
            R.append(r)
            if len(R) == l:
                break
    R.sort()
    rbit = '1'
    for i in range(l-1):
        rbit += (R[i+1] - R[i] - 1) * '0' + '1'
    rbit += (nbit - R[-1] - 1) * '0'
    return int(rbit, 2)

def genkey(p, l):
    n = len(bin(p)[2:])
    f, skey = gen_rand(n, l), gen_rand(n, l)
    pkey = f * inverse(skey, p) % p
    return (p, pkey), skey

def encrypt(msg, pkey):
    p, g = pkey
    msg, enc, n = bytes_to_long(msg), [], len(bin(p)[2:])
    for b in bin(msg)[2:]:
        s, t = gen_rand(n, l), gen_rand(n, l)
        c = (s * g + t) % p
        if b == '0':
            enc.append((c, t))
        else:
            enc.append((p-c, t))
    return enc
    
p = 862718293348820473429344482784628181556388621521298319395315527974911
l = 5

pkey, skey = genkey(p, l)
enc = encrypt(flag, pkey)
H = pkey[1] ** 2 % p
print 'H =', H
print 'enc =', enc