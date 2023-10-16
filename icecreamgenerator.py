from pwn import *

class LCG:
    def __init__(self, a, c, p):
        self.a, self.c, self.p = a, c, p
    
    seed = 1337

    def gen_next(self):
        self.seed = (self.a*self.seed + self.c) % self.p
        return self.seed

io = remote('amt.rs', 31310)

def add(a, b):
    io.recvuntil(b'finish?')
    io.sendline(b'add')
    io.recvuntil(b'bowl: ')
    to_send = ' '.join([str(i) for i in [a, b]])
    io.sendline(to_send.encode())

def combine_bowl(a, b, op):
    io.recvuntil(b'finish?')
    io.sendline(b'combine')
    io.recvuntil(b'operation: ')
    to_send = ' '.join([str(i) for i in [a, b, op]])
    io.sendline(to_send.encode())

def finish_bowl():
    io.recvuntil(b'finish?')
    io.sendline(b'finish bowl')
    io.recvline()
    p = int(io.recvline().decode().strip().split(': ')[1])
    io.recvuntil(b'Signature:')
    io.recvline()
    sign = int(io.recvline().decode().strip())
    return p, sign

def finish():
    io.recvuntil(b'finish?')
    io.sendline(b'finish')
    io.recvuntil(b'OPTIONS:')
    

io.recvuntil(b'Choice: ')
io.sendline(b'1')

#recover a, p
add('2', '1')
add('3', '2')
combine_bowl('1', '2', 'sub')
add('1', '2')
add('2', '3')
combine_bowl('2', '3', 'sub')
combine_bowl('1', '2', 'div')
p, a = finish_bowl()

print(a, p)

#recover c, p
add('5', '1')
add('6', '2')
combine_bowl('1', '2', 'sub')
add('4', '2')
add('5', '3')
combine_bowl('2', '3', 'sub')
combine_bowl('1', '2', 'div')
add('4', '2')
combine_bowl('2', '1', 'mult')
add('5', '1')
combine_bowl('1', '2', 'sub')
p, c = finish_bowl()
print(c, p)

finish()

lcg = LCG(a, c, p)

for i in range(1337):
    lcg.gen_next()

flavors = [lcg.gen_next() for i in range(1338)]
sign = flavors[1337]

io.recvuntil(b'Choice: ')
io.sendline(b'3')

io.recvuntil(b'NUMBER: ')
io.sendline(str(p).encode())

io.recvuntil(b'RECIPE: ')
io.sendline(b'[[1337,0]]')
io.recvuntil(b'SIGNATURE: ')
io.sendline(str(sign).encode())

io.interactive()
# amateursCTF{bruh_why_would_you_use_lcg_for_signature}

'''
Algortihm to recover a:
-------------------------

(x2-x3)/(x1-x2)

1) mov x2 to b1
2) mov x3 to b2
3) b1 - b2
4) mov x1 to b2
5) mov x2 to b3
6) b2 - b3
7) b1 / b2

Algorithm to recover b:
------------------------

x5 - x4 * a

x5 - x4 * (x5 - x6)/(x4 - x5)

1) mov x5 to b1
2) mov x6 to b2
3) b1 - b2
4) mov x4 to b2
5) mov x5 to b3
6) b2 - b3
7) b1 / b2
8) mov x4 to b2
9) b2 * b1
10) mov x5 to b1
11) b1 - b2

'''
