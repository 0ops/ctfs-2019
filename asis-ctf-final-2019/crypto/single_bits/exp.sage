from Crypto.Util.number import long_to_bytes
from itertools import product
import re

p = 862718293348820473429344482784628181556388621521298319395315527974911
p_p = [1504073, 20492753, 59833457464970183, 467795120187583723534280000348743236593]
assert all(is_prime(x) for x in p_p)
assert prod(p_p) == p

H = 381704527450191606347421195235742637659723827441243208291869156144963
roots = []
for q in p_p:
    F.<x> = PolynomialRing(Zmod(q))
    f=x^2-H
    roots.append(int(r[0]) for r in f.roots())

pkeys = [crt(list(x), p_p) for x in product(*roots)]


pat = re.compile('\((\d+) (\d+)')
ct = [(int(c), int(t)) for c, t in pat.findall(open('output.txt').read())]

for pkey in pkeys:
    msg = ''
    for c,t in ct:
        s=(c-t)*inverse_mod(pkey,p)%p
        if bin(s).count('1') == 5:
            msg += '0'
        else:
            msg += '1'
    if msg.count('0') > 0:
        print long_to_bytes(int(msg, 2))
