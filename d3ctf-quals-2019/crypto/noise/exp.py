#!/usr/bin/env python
# coding=utf-8

from pwn import *
import random

# context.log_level = 'debug'

def randn(n):
    return random.randint(1, (1<<n)-1)

def test(n):
    global r
    r.sendline('god')
    r.sendline(str(n))
    return int(r.recvline().strip())

def guess(n):
    global r
    r.sendline('bless')
    r.sendline(str(n))
    log.info(r.recvline())

# r = process('./noise_6bf8bcee73.py')
r = remote('129.226.75.200', 30122)
log.info(r.recvline())
a = 1 << 1024
res = test(a)
if res > a:
    log.info('Fail!')
    r.close()
    exit(0)
res2 = test(a>>1)
if res2 < (a>>1):
    log.info('Fail!')
    r.close()
    exit(0)
a -= res
log.info("a: %x", a)

k = 1
for i in range(46):
    k <<= 22
    tmp = a * k
    res = test(tmp)
    a = (tmp - res) / (k - 1)
    log.info("a: %x", a)
guess(a+1)