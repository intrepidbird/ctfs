from Crypto.Util.number import *
import random
from pwn import *
from tqdm import tqdm

ROUNDS = 5
BLOCK_LEN = 8
HEX_BLOCK_LEN = BLOCK_LEN * 2

r = remote('mercury.picoctf.net', number)
r.recvuntil(b"Selection?")
r.sendline(b"2")
r.recvuntil(b"you like to read?")
r.sendline(b"0")
flag = bytes.fromhex(r.recvline().strip().decode())

delta = int("0" + "1"*62 + "0", 2)
assert delta == 2 ** 63 - 2

st1, st2, st3, st4 = [], [], [], []

for i in range(32):
	rand = ''.join([str(random.randint(0,1)) for _ in range(62)])

	pt1 = int(''.join(["0" + rand + "0"]), 2)
	pt1_ = pt1 ^ delta
	pt2, pt2_ = pt1 ^ 2**63, pt1_ ^ 2**63
	pt3, pt3_ = pt1 ^ 1, pt1_ ^ 1
	pt4, pt4_ = pt2 ^ 1, pt2_ ^ 1

	st1.append([(b"\x00"*(8-len(long_to_bytes(pt1))) + long_to_bytes(pt1)).hex(), (b"\x00"*(8-len(long_to_bytes(pt1_))) + long_to_bytes(pt1_)).hex()])
	st2.append([(b"\x00"*(8-len(long_to_bytes(pt2))) + long_to_bytes(pt2)).hex(), (b"\x00"*(8-len(long_to_bytes(pt2_))) + long_to_bytes(pt2_)).hex()])
	st3.append([(b"\x00"*(8-len(long_to_bytes(pt3))) + long_to_bytes(pt3)).hex(), (b"\x00"*(8-len(long_to_bytes(pt3_))) + long_to_bytes(pt3_)).hex()])
	st4.append([(b"\x00"*(8-len(long_to_bytes(pt4))) + long_to_bytes(pt4)).hex(), (b"\x00"*(8-len(long_to_bytes(pt4_))) + long_to_bytes(pt4_)).hex()])

plaintexts = [st1, st2, st3, st4]

def condition1(pair):
	a,b = pair
	if (a ^ b) % 4 == 2 and a % 2 == 0 and b % 2 == 0:
		return True
	else:
		return False

ciphertexts = []

i = 1
for struct in plaintexts:

	ct_struct = []
	for pair in struct:

		ct_pair = []
		for pt in pair:
			r.recvuntil(b'Selection?')
			r.sendline(b"1")
			r.recvuntil(b"note to encrypt:")
			r.sendline(pt.encode())

			r.recvuntil(b'Selection?')
			r.sendline(b"2")
			r.recvuntil(b"you like to read?")
			r.sendline(str(i).encode())

			ct = bytes.fromhex(r.recvline().strip().decode())
			ct_pair.append(ct)

			i += 1

		ct_struct.append(ct_pair)

	ciphertexts.append(ct_struct)

assert len(ciphertexts) == len(plaintexts)

def g(i):
	b = bin(i).lstrip("0b").rjust(BLOCK_LEN * 8, "0")
	return int(b[::-1], 2)

def part_decrypt_odd(ct_res, k_odd):
	key = k_odd | 1
	news = []
	for structs in ct_res:
		args = []
		for pair in structs:
			pairs = []
			for ct in pair:
				inv = inverse(key, 2**64)
				res = g((bytes_to_long(ct) * inv) % 2**64)
				pairs.append(res)
			args.append(pairs)
		news.append(args)
	return news

def part_decrypt(ct_res, key):
	news = []
	for structs in ct_res:
		args = []
		for pair in structs:
			pairs = []
			for ct in pair:
				res = ct ^ key
				pairs.append(long_to_bytes(res))
			args.append(pairs)
		news.append(args)
	return news

def crack_subkey(cts):
	match = []
	for struct in cts:
		for pair in struct:
			p = [bytes_to_long(pair[0]), bytes_to_long(pair[1])]
			if condition1(p) == True:
				match.append(p)

	poss = []
	for pair in match:
		c1,c2 = pair
		r_side = c1 + c2
		k_odd_poss = ((r_side//2) * inverse(delta, 2**64)) % 2**64
		poss.append(k_odd_poss)

	k = max(set(poss), key = poss.count)

	return [k, k ^ 1, k ^ 2**63, k ^ 2**63 ^ 1]

key_5 = crack_subkey(ciphertexts)

def pad(b):
	return b'\x00'*(8-len(b)) + b

def decrypt_block(block, k):

	result = int(block.hex(), 16)
	for i in range(ROUNDS-1,-1,-1):
		key = int((k[i * BLOCK_LEN:(i + 1) * BLOCK_LEN]).hex(), 16)
		key_odd = key | 1
		result = (result * inverse(key_odd, 2**64)) % (1 << 64)
		result = g(result)
		result ^= key

	return long_to_bytes(result)

possible_keys = []

for key5 in key_5:
	cts5 = part_decrypt_odd(ciphertexts, key5)
	cts5 = part_decrypt(cts5, key5)
	key_4 = crack_subkey(cts5)
	for key4 in key_4:
		cts4 = part_decrypt_odd(cts5, key4)
		cts4 = part_decrypt(cts4, key4)
		key_3 = crack_subkey(cts4)
		for key3 in key_3:
			cts3 = part_decrypt_odd(cts4, key3)
			cts3 = part_decrypt(cts3, key3)
			key_2 = crack_subkey(cts3)
			for key2 in key_2:
				cts2 = part_decrypt_odd(cts3, key2)
				cts2 = part_decrypt(cts2, key2)
				key_1 = crack_subkey(cts2)
				for key1 in key_1:
					possible_keys.append(pad(long_to_bytes(key1)) + pad(long_to_bytes(key2)) + pad(long_to_bytes(key3)) + pad(long_to_bytes(key4)) + pad(long_to_bytes(key5)))

def encrypt_block(b, k):
	assert (len(b) * ROUNDS) == len(k)
	result = int(b.hex(), 16)
	for i in range(ROUNDS):
		key = int((k[i * BLOCK_LEN:(i + 1) * BLOCK_LEN]).hex(), 16)
		key_odd = key | 1
		result ^= key
		result = g(result)
		result = (result * key_odd) % (1 << 64)
	return hex(result).lstrip("0x").rjust(HEX_BLOCK_LEN, "0")

def encrypt(msg, k):
	plain = msg
	result = ""
	for i in range(0, len(plain), BLOCK_LEN):
		result += encrypt_block(plain[i:i + BLOCK_LEN], k)
	return result

real_key = None
for key in possible_keys:
	enc = encrypt(bytes.fromhex(plaintexts[0][0][0]), key)
	if enc == ciphertexts[0][0][0].hex():
		real_key = key
		break

def decrypt_flag(flag, k):
	ct = flag
	result = b""
	for i in range(0, len(ct), BLOCK_LEN):
		result += decrypt_block(ct[i:i + BLOCK_LEN], k)
	return result

flag = decrypt_flag(flag, real_key)
print(flag.decode())
