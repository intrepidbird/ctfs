from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl
from Crypto.Cipher import AES
from pwn import *
from tqdm import trange

class YourDidItRNG:
    def __init__(self,size):
        self.mask = (1 << size) - 1;
        self.mod = 79563462179368165893806602174110452857247538703309854535186209058002907146727;
        self.seed = 0;

    def infuseYourDidItPower(self,power,step):
        self.seed = (step * power) % self.mod;

    def next(self):
        self.seed = ((self.seed * 573462395956462432646177 + 7453298385394557473) % self.mod); # try converting these to text ;)
        return self.seed & self.mask;

    def yourdidit(self,goodjob):
        for i in range(5 * 5):
            self.next();
        YourSoDidIt = self.next() | self.next() | self.next() | self.next() | self.next();
        YourSoDidIt = ((YourSoDidIt & goodjob) ^ self.next()) & self.mask;
        return YourSoDidIt

def ydi(step, ct, pt):
    y = YourDidItRNG(128)
    y.infuseYourDidItPower(btl(ct), step)
    return y.yourdidit(btl(pt)).to_bytes(16, 'big')
    
def star(step, ct):
    y = YourDidItRNG(128)
    y.infuseYourDidItPower(btl(ct), step)
    for i in range(30):
        y.next()
    return y.next().to_bytes(16, 'big')

sh = remote('litctf.org', 31789)

def getmsg(inp):
    sh.sendlines([b'E', inp])
    sh.readuntil(b'fied message: ')
    return bytearray.fromhex(sh.readline().decode())
    
orig = getmsg(b'')
lastknown, n = b"ere's the flag: ", -80

while b'}' not in lastknown:
    flag = orig[n:n+16]

    prevXOR = ydi((len(orig)+n-32)*2, orig[n-16:n],  lastknown)

    known = []
    for j in range(1,17):
        enc = getmsg(bytes(5012 - j))
        enc[16:32] = flag
        
        for i in range(len(known)):
            enc[i] = known[i] ^ j
        for i in trange(256):
            enc[j-1] = i
            sh.sendlines([b'V', enc.hex().encode()])
            if b'YOUR DID IT!' in sh.readline_contains(b'verification:'):
                known.append(i ^ j)
                break
        else:
            assert False, 'BROKEN'

    lastknown = xor(known, prevXOR)
    print(lastknown)
    n += 16
