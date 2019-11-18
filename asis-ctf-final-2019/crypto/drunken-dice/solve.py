#!/usr/bin/env python
# coding=utf-8

from pwn import *

def enc(a, b, table):
    tmp = table[a|(b<<4)]
    return tmp&0xf, tmp>>4

def check1(t):
    rec = []
    for i in range(16):
        a, b = enc(0, i, t)
        if a != i:
            return False
        rec.append(b)
    return set(rec) == set(range(16))

def check2(t):
    rec = []
    const = None
    for i in range(16):
        a, b = enc(i, 0, t)
        if const == None:
            const = a ^ i
        else:
            if const != a ^ i:
                return False
        rec.append(b)
    return set(rec) == set(range(16))

def check3(t):
    rec = [None] * 16
    for i in range(16):
        for j in range(16):
            a, b = enc(i, j, t)
            if a == 0:
                tmp = b ^ i
                if rec[j] != None:
                    if rec[j] != tmp:
                        return False
                else:
                    rec[j] = tmp
    return set(rec) == set(range(16))

def check4(t):
    rec = []
    for i in range(16):
        for j in range(16):
            a, b = enc(i, j, t)
            if a == 0:
                tmp = b ^ j
                rec.append(tmp)
    return set(rec) == set(range(16))

def check5(t):
    for k in range(16):
        rec = set()
        for i in range(16):
            for j in range(16):
                a, b = enc(i, j, t)
                if j == k:
                    # print i, a, b ^ i
                    if (a, b ^ i) in rec:
                        return False
                    rec.add((a, b^i))
    return True

if __name__ == '__main__':
    r = remote('76.74.177.238', 12345)
    r.sendlineafter('uit!\n', 'p')
    while True:
        log.info(r.recvline())
        r.recvuntil('is: ')
        data = r.recvline().strip().split()
        data = map(int, data)
        if check1(data):
            res = 1
        elif check2(data):
            res = 2
        elif check3(data):
            res = 3
        elif check4(data):
            res = 4
        elif check5(data):
            res = 5
        else:
            res = 6
        log.info('Guess %d', res)
        r.sendlineafter('\n', str(res))
        r.recvline()
    log.info(r.recv(1024))
    log.info(r.recv(1024))
    log.info(r.recv(1024))
    log.info(r.recv(1024))
