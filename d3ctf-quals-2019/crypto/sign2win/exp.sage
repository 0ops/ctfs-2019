import hashlib

a = 0
b = 7
p = 115792089237316195423570985008687907853269984665640564039457584007908834671663L
E = EllipticCurve(Zmod(p), [a, b])
n = E.order()
g = (55066263022277343669578718895168534326250603453777594175500187360389116729240L, 32670510020758816978083085130507043184471273380659243275938904335757337482424L)
g = E(g)
m1 = "I want the flag"
m2 = "I hate the flag"
h1 = int(hashlib.sha256(m1).hexdigest(), 16)
h2 = int(hashlib.sha256(m2).hexdigest(), 16)

K = randint(1, n)
r = (g*K).xy()[0].lift()
dd = (h1-h2)*inverse_mod(r, n) % n

d1 = (-h1-h2) * inverse_mod(2*r, n) % n
d2 = (dd + d1) % n

pubkey1 = d1*g

pk1x = pubkey1.xy()[0]
pk1y = pubkey1.xy()[1]
pk =  hex(int(pk1x))[2:-1] + hex(int(pk1y))[2:-1]

s1 = (h1 + r*d1)*inverse_mod(K, n) % n
s2 = (h2 + r*d2)*inverse_mod(K, n) % n 

s = hex(r)[2:-1].zfill(64)+hex(s1)[2:-1].zfill(64)
print "pk: " + pk
print "s:  " + s