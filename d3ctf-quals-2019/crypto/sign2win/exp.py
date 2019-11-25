from pwn import *
import re
import string

r = remote("129.226.163.141", 12233)
pattern = re.compile(r"sha256\(XXXX\+(\w+)\) == ([0-9a-f]+)")
suffix, result = re.findall(pattern, r.recv())[0]

answer = iters.bruteforce(lambda x:sha256sumhex(x+suffix)==result, string.digits+string.ascii_letters, 4, "fixed")

r.sendline(answer)
r.interactive()