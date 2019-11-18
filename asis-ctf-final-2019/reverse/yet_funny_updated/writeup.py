import re
import string
from pwn import *

r = remote("76.74.177.238", 7777)
algo, _, suffix, _, length = re.search(r"such that (.+?)\((.+?) = ([0-9A-Fa-f]{6})(.+?) = ([0-9]+)", r.recv()).groups()
answer = iters.bruteforce(lambda x: eval(algo+"sumhex")(x).endswith(suffix), string.printable.strip(), int(length), "fixed")
r.sendline(answer)

r.sendlineafter("!\n", "g")
code = r.recvuntil("}\n")
c, d, _, a, b = re.search(r"  c = (-?[0-9]+), d = (-?[0-9]+);\n(.+?)a = (-?[0-9]+), b = (-?[0-9]+);", code).groups()
c, d, a, b = map(int, [c, d, a, b])

def egcd(a,b):
    if b==0:
        return 1,0
    else:
        x,y=egcd(b,a%b)
        return y,x-a/b*y
cc, dd = egcd(a, b)
cc = cc - c
dd = dd - d

def consturct(x):
    if x < 0:
        x = abs(x)
        return "--"*(x+1)+"++"
    else:
        return "++"*(x+1)+"--"
cc = consturct(cc)
dd = consturct(dd)

r.sendlineafter("!\n", "t")
r.sendlineafter(":\n", cc)
r.sendlineafter(":\n", dd)
r.interactive()
r.close()