from sympy.ntheory.modular import crt
from Crypto.Cipher import AES
from Crypto.Util.number import *
from hashlib import sha256
import random

def brute_force(g, A, upper, p):
	g_ = g
	dlog = 1
	while dlog <= upper:
		if is_equal(g_, A):
			return dlog
		g_ = add_points(g_, g)
		dlog += 1
	print("Something's Wrong man")

def discrete_log(g, A, p, order, factors):
	g_ = g
	A_ = A
	modulus = []
	dlogs = []
	for factor in factors:
		pi, ei = factor
		while ei > 1:
			if is_identity(multiply(g, pi**ei)):
				ei -= 1
			else:
				break
		g_ = multiply(g, order // (pi**ei))
		A_ = multiply(A, order // (pi**ei))
		print("\n[(0)] ++++----------------------------------------++++++++\n")
		print("[+] Trying modulus = ", pi, ei, pi**ei, (pi**ei).bit_length(), " bits")
		print("[*] g_ = ", g_)
		print("[*] A_ = ", A_)
		dlog = brute_force(g_, A_, pi**ei, p)
		print("[+] dlog = ",dlog)
		dlogs.append(dlog)
		modulus.append(pi**ei)
		print("[*] dlogs = ", dlogs)
		print("[*] modulus = ", modulus)
		print("\n")
	return modulus, dlogs

def is_equal(g, A):
	return (g[0] == A[0] and g[1] == A[1])

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
	
def is_identity(g):
	return (g[0] == 1 and g[1] == 0)

def random_complex(p):
	return (random.randint(0, p - 1), random.randint(0, p - 1))

def gen_nth_order(p, order, tar_order):
	assert order % tar_order == 0
	exp = order // tar_order
	while True:
		g = random_complex(p)
		a = multiply(g, exp)
		if not is_identity(a):
			return a

p = 108848362000185157098908557633810357240367513945191048364780883709439999

A = (70584838528566138057920558091160583247156394376694509226477175997005624, 47208562635669790449305203114934717034939475647594168392271311241505021)
B = (28274152596231079767179933954556001021066477327209843622539706192176128, 99565893173481261433550089673695177934890207483997197067732588009694082)
g = (0x43bf9535b2c484b67c68cb98bace14ae9526d955732e2e30ac0895ab6ba, 0x4a9f13a6bd7bb39158cc785e05688d8138b05af9f1e13e01aaef7c0ab94)

order = 11847965910123352093857771255596982641892197963724301333011529692408947198573202576324410523650499595813456025153507415697892044783346181120000
factors = [(2, 13), (3, 6), (5, 4), (7, 4), (11, 2), (13, 1), (31, 1), (41, 1), (89, 1), (109, 1), (241, 1), (283, 1), (881, 1), (21397, 1), (126517, 1), (480941, 1), (1496753, 1), (2492279, 1), (3471359, 1), (5852653, 1), (24485459, 1)]

modulus, dlogs = discrete_log(g, A, p, order, factors)

print("modulus = ", modulus)
print("dlogs = ", dlogs)

A_secret = int(crt(modulus, dlogs)[0])
print("[*] A_secret = ", A_secret)

ct = "aaa21dce78ef99d23aaa70e5d263719de9245f33b8a9e2a0a63c8847dba61296c5a1f56154b062d3a347faa31b8d8030"

shared = multiply(B, A_secret)[0]
key = sha256(long_to_bytes(shared)).digest()
aes = AES.new(key, AES.MODE_ECB)
flag = aes.decrypt(bytes.fromhex(ct))
print("\n[*] flag = ", flag)


# ptm{c1rcl3s_r_n0t_4s_53cur3_4s_ell1ps3s}
