from pwn import remote
from itertools import product
from Crypto.Util.number import long_to_bytes, bytes_to_long
from hashlib import sha256
import string

def compute_pow(suffix, tar):
	charset = string.digits + string.ascii_letters
	poss = product(charset, repeat = 4)
	for i in poss:
		if sha256((''.join(i) + suffix).encode()).hexdigest() == tar:
			return ''.join(i)
	print("Unable to compute pow")
	print("suffix = ", suffix)
	print("target = ", tar)
	exit()	 

def pow():
	line = conn.recvline().strip().decode()
	target = line.split(" ")[-1]
	suffix = line.split(" ")[0].split("+")[-1].strip(")")
	answer = compute_pow(suffix, target)
	conn.recvline()
	conn.sendline(answer.encode())
	return

def check_vals(e1):
	r2 = e1 & 0xffff
	r1 = e1 >> 16
	for i in range(2**17):
		print("[+] Checking val = ", hex(i))
		if Ec.is_x_coord((i << 240) + r1):
			qx = (i << 240) + r1
			seed = (Ec.lift_x(qx) * inverse_mod(1735, order)).xy()[0]
			t2 = long_to_bytes((int(seed) * Q).xy()[0])[-30:][:2]
			if r2 == bytes_to_long(t2):
				return int(seed)

def gen_ecprng(seed):
	s1 = int((seed * P).xy()[0])
	seed = int((s1 * P).xy()[0])

	r1 = (s1 * Q).xy()[0]
	r2 = (seed * Q).xy()[0]

	return bytes_to_long(long_to_bytes(r1)[-30:] + long_to_bytes(r2)[-30:][:2])

p = 2**256 - 2**224 + 2**192 + 2**96 - 1
a = p-3
b = 41058363725152142129326129780047268409114441015993725554835256314039467401291

order = 115792089210356248762697446949407573529996955224135760342422259061068512044369
Qx = 75498749949015782244392151836890161743686522667385613237212787867797557116642
Qy = 19586975827802643945708711597046872561784179836880328844627665993398229124361

Px = 115113149114637566422228202471255745041343462839792246702200996638778690567225
Py = 88701990415124583444630570378020746694390711248186320283617457322869078545663

Ec = EllipticCurve(GF(p), [a, b])

_Px = 53881495764268889303293517690095107010093794097958309592680107528631746121613
_Py = 69534606358473748292927094386662082099432383517498778127513290350658945146669

P = Ec(Px, Py)
Q = Ec(Qx, Qy)

G = Ec(_Px, _Py)

conn = remote("34.74.30.191", 3333)
pow()
print("Pow completed")

conn.recvuntil(b"Enter your choice: ")
conn.sendline(b"1")
conn.recvuntil(b"point Q: ")
conn.sendline((str(_Px) + ":" + str(_Py)).encode())
conn.recvuntil(b"point R: ")
conn.sendline((str(_Px) + ":" + str(_Py)).encode())
conn.recvuntil(b"take e: ")

e = conn.recvline().strip().split(b"m")[-1]

print("e = ", e)

e = Integer(e)

conn.recvuntil(b"give me s: ")

conn.sendline(str(e + 1).encode())

conn.recvuntil(b"Enter your choice: ")
conn.sendline(b"2")

seed = check_vals(e)
print("seed = ", seed)

en = gen_ecprng(seed)
print("en = ", en)

conn.recvuntil(b"Enter your choice: ")
conn.sendline(b"2")
conn.recvuntil(b"point Q: ")
conn.sendline((str(_Px) + ":" + str(_Py)).encode())
conn.recvuntil(b"point R: ")
conn.sendline((str(_Px) + ":" + str(_Py)).encode())
conn.recvuntil(b"give me s: ")
conn.sendline(str(en + 1).encode())
conn.recvuntil(b"Enter your choice: ")
conn.sendline(b"1")
conn.interactive()

# inctf{Ev3ry_wa11_1s_4_d00r_but_7his_1s_4_D0ubl3_d0or}
