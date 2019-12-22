from pwn import remote
from hashlib import sha256
from Crypto.Util.number import *

def bytes_to_int(s):
	out = 0
	for ch in reversed(s):
		out = (out << 8) + ord(ch)
	return out

def int_to_bytes(n,w):
	s = ''
	while n:
		s = s + chr(n & 0xff)
		n >>= 8
	return s.ljust(w/8,'\x00')

def int_to_poly(num):
	res =  map(int, bin(num)[2:].zfill(32)[::-1])
	# print(num)
	return res

def poly_to_int(ll):
	return int("".join(map(str, ll))[::-1], 2)

# F = GF(2^32)
# R.<y> = PolynomialRing(F)
# S.<x> = R.quotient(y^32 + 1)

def breakRudolph(hex1, hex_ct1, hex_ct2):
	F = GF(2^32)
	R.<y> = PolynomialRing(F)
	S.<x> = R.quotient(y^32 + 1)
	mulMatrix = Matrix(S, [[x^28 + x^24 + x^22 + x^21 + x^17 + x^16 + x^15 + x^13 + x^11 + x^10 + x^4 + x^3 + 1, x^31 + x^30 + x^29 + x^28 + x^22 + x^21 + x^20 + x^14 + x^12 + x^11 + x^8 + x^5 + x^2 + x], [x^29 + x^25 + x^24 + x^23 + x^22 + x^20 + x^17 + x^14 + x^11 + x^8 + x^4 + x^2 + x + 1, x^31 + x^28 + x^24 + x^23 + x^22 + x^19 + x^18 + x^16 + x^14 + x^12 + x^9 + x^6 + x^2]])
	deter = mulMatrix.determinant()
	mulInv = (1/deter)*(mulMatrix.adjoint())
	A1 = S(int_to_poly(bytes_to_int(hex1[:8].decode("hex"))))
	B1 = S(int_to_poly(bytes_to_int(hex1[8:].decode("hex"))))
	C1 = S(int_to_poly(bytes_to_int(hex_ct1[:8].decode("hex"))))
	D1 = S(int_to_poly(bytes_to_int(hex_ct1[8:].decode("hex"))))
	C2 = S(int_to_poly(bytes_to_int(hex_ct2[:8].decode("hex"))))
	D2 = S(int_to_poly(bytes_to_int(hex_ct2[8:].decode("hex"))))
	pt1 = Matrix(S, [[A1], [B1]])
	ct1 = Matrix(S, [[C1], [D1]])
	ct2 = Matrix(S, [[C2], [D2]])
	key = ct1 - (mulMatrix*pt1)
	pt2 = mulInv*(ct2 - key)
	A2 = pt2[0][0]
	B2 = pt2[1][0]
	hex2 = int_to_bytes(poly_to_int(map(Integer, A2.list())), 32).encode("hex")
	hex2 += int_to_bytes(poly_to_int(map(Integer, B2.list())), 32).encode("hex")
	print(hex2)
	return hex2

def intro():
	conn.recvuntil("Try to solve this task he left for you.\n")

def PoW(hash_end):
	i = 0
	while 1:
		if sha256(long_to_bytes(i)).hexdigest().endswith(hash_end):
			return long_to_bytes(i)
		i += 1

def poc():
	conn.recvuntil("Provide a hex string X such that sha256(X)[-6:] = ")
	hash_end = conn.recvuntil("\n").strip("\n")
	print("poc :: " + hash_end)
	val = PoW(hash_end)
	conn.sendline(val.encode("hex"))
	print(conn.recvuntil("\n"))

def recv_challenge():
	conn.recvuntil("message 1: ")
	m1 = conn.recvuntil(" ").strip()
	conn.recvuntil("ciphertext 1: ")
	ct1 = conn.recvuntil("\n").strip("\n")
	conn.recvuntil("ciphertext 2: ")
	ct2 = conn.recvuntil("\n").strip("\n")
	return m1, ct1, ct2

def answer(ans):
	conn.recvuntil("\n")
	conn.sendline(ans)

conn = remote('challs.xmas.htsp.ro', 10002)
poc()
intro()
for i in range(10):
	m1, ct1, ct2 = recv_challenge()
	print(str(i + 1) + " " + m1 + " " + ct1 + " " + ct2)
	ans = breakRudolph(m1, ct1, ct2)
	print("ans = " + ans)
	answer(ans)
	print(conn.recvuntil("\n"))
conn.interactive()

# X-MAS{5_b17_t00_1nd3p3nden7_f0r_my_t45t3}
