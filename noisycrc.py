from pwn import *
from tqdm.auto import tqdm

Fn = GF(2)
Rn.<x> = PolynomialRing(Fn)

r = remote("chals.sekai.team", int(3005))
r.recvuntil(b"flag: ")
flag_enc = r.recvline().strip().decode()

def oracle_send(x): # helper to query with polynomial
    x = ZZ(list(x.change_ring(ZZ)), 2)
    r.sendline(f"{x}".encode())

def oracle_recv(): # helper to return polynomial
    r.recvuntil(b"ial: ")
    crcs = safeeval.expr(r.recvline())
    crcs = [ Rn(ZZ(crc).bits()) for crc in crcs ]
    return crcs

# Query 100 sets of g(x) * h_i(x)
n = 100
integrity_modulus = x^4 + x + 1
assert integrity_modulus.is_irreducible()

queries = []
while len(queries) < n:
    query = Rn.random_element(degree=12)
    # In case random_element collides
    if query not in queries:
        queries.append(query)
        oracle_send(query * integrity_modulus)

results = []
for _ in tqdm(range(n)):
    results.append(oracle_recv())
