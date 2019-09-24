from hashlib import sha256
from Crypto.Util.number import *

def genBasis(ti, ui, q, ct, cu):
	n = len(ti)
	ti = vector(ti + [ct, 0])
	ui = vector(ui + [0, cu])
	lis = [0 for i in range(n + 2)]
	basis = []
	for i in range(n):
		ri = lis[:]
		ri[i] = q
		ri = vector(ri)
		basis.append(ri)
	basis.append(ti)
	basis.append(ui)
	
	return basis

def check_d(d):
	# check if given d is the correct private key by velidating a signature signed by the server

	n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
	p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
	a = p-3
	b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
	z = 48635463943209834798109814161294753926839975257569795305637098542720658922315
	check_r = 106214896535742251750840161018006438799104136675357154159604584776176060913281
	s_inv = 64642628174331870633922188531399890850609549706588247736008574334730479490087
	u_1 = (s_inv*z) % n
	u_2 = (s_inv*check_r) % n

	E = EllipticCurve(GF(p), [a, b])
	Gx = 105628562773329337640893595054548446109845168797622368389180213953990926700662
	Gy = 32408302692268607486270308925513058111871258446764614158480809006157801114098
	G = E(Gx, Gy)
	P = d*G
	T = u_1*G + u_2*P
	return Integer(check_r) == Integer(T.xy()[0])

def slice_string(s, _len):
    return long_to_bytes(int(bin(bytes_to_long(s))[2:2+_len], 2))

def calc_z(message):
	e = sha256(message).digest()
	Ln = 256
	z = bytes_to_long(slice_string(e, Ln))
	return z

def sign(d):
	k = 13
	# z = calc_z("admin")
	z = 63510138342444003596188279565448361031871357402171886015166189192138742868248
	p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
	a = p-3
	b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
	E = EllipticCurve(GF(p), [a, b])
	Gx = 105628562773329337640893595054548446109845168797622368389180213953990926700662
	Gy = 32408302692268607486270308925513058111871258446764614158480809006157801114098
	G = E(Gx, Gy)
	R = k*G
	r = Integer(R.xy()[0])
	s = (inverse_mod(k, n)*(z + r*d)) % n
	return (r, s)


n = 115792089210356248762697446949407573529996955224135760342422259061068512044369

signatures = eval(open("signatures").read())

tu = []
for i in signatures:
	z = calc_z(str(i).encode())
	r, s = signatures[i]
	t = (r*inverse_mod(s*(2^8), n)) % n
	u = (3*inverse_mod(2^8, n)) % n
	u = (u - (z*inverse_mod(s*(2^8), n))) % n
	tu.append((t, u))

q = n
cu = q/(2^8)
ct = 1/(2^8)

tlist = map(Integer, [i[0] for i in tu])
ulist = map(Integer, [i[1] for i in tu])

for i in range(10, 50):
	basis = genBasis(tlist[:i], ulist[:i], q, ct, cu)
	A = Matrix(QQ, basis)
	B = A.LLL()
	for j in B:
		if j[-1] == cu:
			dct_ = j[-2]
			d = Integer((dct_/ct)*-1)
			if check_d(d):
				print("d = " + str(d))
				print("signature of 'admin' = " + str(sign(d)))
				break
	else :
		print(i)
		continue
	break

# d = -12978944819504458167916888695353741508975746904433093121164615085423925141911
# signature of 'admin' = (86453481839912264388441896771335295330978879990314190873342252877241630428572, 
#						100041516778278991619512866638645023271277451757485296203649320067506167138122)
# inctf{well_well_congratulations_ECDSA_biased_nonce_s0lver}
