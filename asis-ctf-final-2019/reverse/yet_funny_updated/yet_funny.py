#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess
import random
import sys, os, string
from hashlib import *
from flag import flag
 
 
def genrandstr(N):
    return ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(N))
 
 
def isprintable(mystr):
    return all(c in string.printable for c in mystr)
 

def PoW():
    r = random.randint(0, 5)
    HASH = [md5, sha1, sha224, sha256, sha384, sha512]
    X = genrandstr(14)
    l = random.randint(10, 40)
    pr("Please submit a printable string X, such that", HASH[r].__name__.split('_')[1] + "(X)[-6:] =",
       HASH[r](X).hexdigest()[-6:], 'and len(X) =', l)
    Y = sc()
    return isprintable(Y) and HASH[r](Y).hexdigest()[-6:] == HASH[r](X).hexdigest()[-6:] and len(Y) == l
 
 
def aux(inp):
    pm = set(inp)
    try:
        vux = inp.replace(list(pm)[0] * 2, chr(0)).replace(list(pm)[1] * 2, chr(1))
        if set(vux) == set([chr(0), chr(1)]) and len(inp) <1<<10:
            return True and len(inp) > 4
    except:
        pass
    return False
 
 
def GCD(x, y):
    while (y):
        x, y = y, x % y
    return x

def rangen():
	return [random.randint(32, 64), random.randint(-64, -32)][random.randint(0, 1)]
 
def rancof():
    rs = (random.randint(0, 128) + 128, random.randint(0, 128) + 128)
    while True:
        if GCD(rs[0], rs[1]) == 1:
            break
        rs = (random.randint(0, 128) + 128, random.randint(0, 128) + 128)
    return rs
 
code = r'''
        #include <stdio.h>
        int main(){
           int c = 0, d = 0;
           c = first_number, d = second_number;
           int a = first_random, b = second_random;
           if((a*c + b*d) == 1)
               return 0;
           return -1;
        }
        '''
 
def var_handler(first_var, second_var, first_rand, second_rand, first_number, second_number):
    global code
    tmp_code = code
    tmp_code = str(tmp_code).replace("first_random", str(first_rand))
    tmp_code = str(tmp_code).replace("second_random", str(second_rand))
    tmp_code = str(tmp_code).replace("first_number", str(first_var) + "c+" + str(first_number))
    tmp_code = str(tmp_code).replace("second_number", str(second_var) + "d+" + str(second_number))
    random_name = genrandstr(16)
    full_random_name = '/tmp/' + random_name + '.cpp'
    c_file = open(full_random_name, 'w')
    c_file.write(tmp_code)
    c_file.flush()
    c_file.close()
    command1 = "g++ " + full_random_name + " -o " + "/tmp/" + random_name
    command2 = "/tmp/" + random_name
    os.system(command1)
    process = subprocess.Popen(command2, shell=True, stdout=subprocess.PIPE)
    process.wait()
    os.remove("/tmp/" + random_name)
    os.remove('/tmp/' + random_name + '.cpp')
    if str(process.returncode) == '0':
        return True
    else:
        return False
 
border = "█"

def main():
    if PoW():
        pr(border * 82)
        pr(border, "Elliot has been trying to defeat the Red Army since May 9th hacking incident. ", border)
        pr(border, "He has ultimately found a way to their hidden bank using a Mr.Robot!          ", border)
        pr(border, "You have to play your role in the story and help Elliot to arrange his attack!", border)
        pr(border * 82)
        first_number, second_number = [rangen() for _ in range(2)]
        first_rand, second_rand = rancof()
        while True:
            pr("| Options: \n|\t[G]et the C source code \n|\t[T]ry to solve \n|\t[Q]uit!")
            ans = sc().lower()
            if ans == 'g':
                global code
                tmp_code = code
                tmp_code = str(tmp_code).replace("second_number", str(second_number))
                tmp_code = str(tmp_code).replace("first_number", str(first_number))
                tmp_code = str(tmp_code).replace("first_random", str(first_rand))
                tmp_code = str(tmp_code).replace("second_random", str(second_rand))
                pr(tmp_code)
            elif ans == 't':
                pr("Please enter first variable:")
                first_var = sc()
                pr("Please enter second variable:")
                second_var = sc()
                if isprintable(first_var) and isprintable(second_var) and aux(first_var) and aux(second_var):
                    if var_handler(first_var, second_var, first_rand, second_rand, first_number, second_number):
                        die("You win the battle, here you are :", flag)
                    else:
                        die("Bye Loser...")
                else:
                    die("000ps... Inappropriate variable")
            elif ans == 'q':
                die(border, "Quiting ...")
            else:
                die(border, "Bye ...")
    else:
        die('PoW challenge failed :P')
 
 
def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc():
    return sys.stdin.readline().strip()

if __name__ == '__main__':
    main()
