from hashlib import sha1, sha256
from pwn import remote
from itertools import product
from binascii import unhexlify, hexlify
import string

from ecdsa.ecdsa import Signature
from ecdsa.util import sigdecode_string
from ecdsa import SigningKey, NIST192p

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

def recv_menu():
	global iteration
	iteration += 1
	conn.recvuntil(b"[ecdsa@cryptolab]# ")
	print("[+] iteration = ", iteration)
	return

def obtain_signature(val, msg=b"inctf"):
	recv_menu()
	conn.sendline(b"1")
	conn.recvuntil(b"Enter a message to sign: ")
	conn.sendline(msg)
	conn.recvuntil(b"Now insert a really stupid value here: ")
	conn.sendline(str(val).encode())

	sig = conn.recvline().decode()
	sig = sig.strip().split(" ")[-1]
	sig = unhexlify(sig)
	r, s = sigdecode_string(sig, order)

	return r, s

def obtain_pubkeys(r, s, msg=b"inctf"):
	signature = Signature(r, s)
	e = int(sha1(msg).hexdigest(), 16)
	pk1, pk2 = signature.recover_public_keys(e, NIST192p.generator)
	pk1x = int(pk1.point.x())
	pk1y = int(pk1.point.y())
	pk2x = int(pk2.point.x())
	pk2y = int(pk2.point.y())
	return [(pk1x, pk1y), (pk2x, pk2y)]

def check_offsets(P, Q, G, offsets):
	for offset in offsets:
		if Q == P + offset * G:
			return True, offsets[offset]
	return False, None

def obtain_points(val):
	sig = obtain_signature(val)
	pubkeys = obtain_pubkeys(sig[0], sig[1])
	P1, P2 = E(pubkeys[0]), E(pubkeys[1])

	return P1, P2

def calc_pubkey():

	P1, P2 = obtain_points(0)
	Q1, Q2 = obtain_points(3)

	offsets = {3: 0, 1 : 1, -1 : 2, -3 : 3}

	check1, offset1 = check_offsets(P1, Q1, G, offsets)
	check2, offset2 = check_offsets(P1, Q2, G, offsets)
	check3, offset3 = check_offsets(P2, Q1, G, offsets)
	check4, offset4 = check_offsets(P2, Q2, G, offsets)

	assert check1 + check2 + check3 + check4 == 1, "Check failed"

	if check1:
		return P1, offset1
	elif check2:
		return P1, offset2
	elif check3:
		return P2, offset3
	else:
		return P2, offset4

	print("Unable to find correct Public Key")
	print("sig1 = ", sig1, "sig2 = ", sig2)
	exit()

def calc_secret_key():
	P, low_bits = calc_pubkey()
	print("[+] Obtained Original Public key = {0} and lowbits = {1}\n".format(P, low_bits))
	shift = 2
	base = 3
	secret_key = low_bits
	while shift < 101:
		Q1, Q2 = obtain_points(base << shift)
		offsets = {(2**shift + 2**(shift + 1)) : 0, (2**(shift + 1) - 2**shift) : 1, 
					(-2**(shift + 1) + 2**shift) : 2, (-2**(shift + 1) - 2**shift) : 3
					}
		check, offset = check_offsets(P, Q1, G, offsets)
		if not check:
			check, offset = check_offsets(P, Q2, G, offsets)
			assert check, sig		
		secret_key += offset << shift
		shift += 2
		print("[*] secret_key = {0}, shift = {1}\n".format(secret_key, shift))
	print("\n[*] secret_key = ", secret_key)

	assert P == secret_key * G

	return secret_key

def get_flag(secret_key):
	msg = b'please_give_me_the_flag'
	signingKey = SigningKey.from_secret_exponent(secret_key)
	signature = signingKey.sign(msg)
	signature = hexlify(signature)
	recv_menu()
	conn.sendline(b"3")
	conn.recvuntil(b"Forged Signature: ")
	conn.sendline(signature)
	conn.interactive()

a = -3
b = 2455155546008943817740293915197451784769108058161191238065
p = 6277101735386680763835789423207666416083908700390324961279
Gx = 602046282375688656758213480587526111916698976636884684818
Gy = 174050332293622031404857552280219410364023488927386650641
order = 6277101735386680763835789423176059013767194773182842284081

E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)

iteration = 0

conn = remote("34.74.30.191", 9999)

pow()

print("[*] Pow Completed")

secret_key = calc_secret_key()
get_flag(secret_key)

# inctf{i_see_bitflip_i_see_family}

# 00 --> Q1 = P1 + 3*G
# 01 --> Q1 = P1 + G
# 10 --> Q1 = P1 - G
# 11 --> Q1 = P1 - 3*G

# 00 --> Q1 = P1 + (3 << 2) * G
# 01 --> Q1 = P1 + (1 << 2) * G
# 10 --> Q1 = P1 - (1 << G
# 11 --> Q1 = 