from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
from hashlib import sha256
from secret import flag, p


def add_points(P, Q):
    return ((P[0]*Q[0]-P[1]*Q[1]) % p, (P[0]*Q[1]+P[1]*Q[0]) % p)

def multiply(P, n):
    Q = (1, 0)
    while n > 0:
        if n % 2 == 1:
            Q = add_points(Q, P)
        P = add_points(P, P)
        n = n//2
    return Q

def gen_key():
    g = (0x43bf9535b2c484b67c68cb98bace14ae9526d955732e2e30ac0895ab6ba, 0x4a9f13a6bd7bb39158cc785e05688d8138b05af9f1e13e01aaef7c0ab94)
    sk = random.randint(0, 2**256)
    pk = multiply(g, sk)
    return sk, pk


a, A = gen_key()
b, B = gen_key()
print(A)
print(B)

shared = multiply(A, b)[0]
key = sha256(long_to_bytes(shared)).digest()
aes = AES.new(key, AES.MODE_ECB)
ciphertext = aes.encrypt(pad(flag.encode(), AES.block_size))
print(ciphertext.hex())
