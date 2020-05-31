import gmpy2
from Crypto.Util.number import *

def rem_terms(N, pa1, pa3, sizes):
	s1, s2, s3 = sizes
	N = N - (pa3**2) - 2*((pa1 * pa3) << (s2 + s3)) - ((pa1 ** 2) << (2*(s2 + s3)))
	return N

def check_roots(a, b, c):
	det = b**2 - 4*a*c
	if det <= 0:
		return False, None
	if not gmpy2.is_square(det):
		return False, None
	detsqrt = int(gmpy2.isqrt(det))
	root1 = -b + detsqrt
	root2 = -b - detsqrt
	if root1 % (2*a) != 0 or root2 % (2*a) != 0 or (root1 < 0) or (root2 < 0):
		return False, None
	return True, [root1//(2*a), root2//(2*a)]

def sqrtmodulopower2(a, p, e = 1):
	if e >= 3 and a % 8 == 1:
		res = []
		for x in [1, 3]:
			for k in range(3, e):
				i = (x*x - a)//(2**k) % 2
				x = x + i*2**(k-1)
			res.append(x)
			res.append(p**e - x)
		return res
	if e < 3:
		return [x for x in xrange(0, p**e) if x*x % p**e == a % p**e]
	print("Cannot find roots")
	return []

N = 0xf7e6ddd1f49d9f875904d1280c675e0e03f4a02e2bec6ca62a2819d521441b727d313ec1b5f855e3f2a69516a3fea4e953435cbf7ac64062dd97157b6342912b7667b190fad36d54e378fede2a7a6d4cc801f1bc93159e405dd6d496bf6a11f04fdc04b842a84238cc3f677af67fa307b2b064a06d60f5a3d440c4cfffa4189e843602ba6f440a70668e071a9f18badffb11ed5cdfa6b49413cf4fa88b114f018eb0bba118f19dea2c08f4393b153bcbaf03ec86e2bab8f06e3c45acb6cd8d497062f5fdf19f73084a3a793fa20757178a546de902541dde7ff6f81de61a9e692145a793896a8726da7955dab9fc0668d3cfc55cd7a2d1d8b631f88cf5259ba1

# Generate all possible pa3 and pa1 values for different values of s3, s2 and s1
Pa1s = []
Pa3s = {}
for s3 in range(16, 1000 + 1):
	a = N % (2**s3)
	pa3s = sqrtmodulopower2(a, 2, s3)
	for s2 in range(16, 505):
		s1 = (1024 - s2 - s3)
		if s1 >= s2 or s1 < 8:
			continue
		squ = N >> (2*(s2 + s3))
		pa1 = int(gmpy2.isqrt(squ))
		Pa1s.append([s2, s3, pa1])
	Pa3s[s3] = pa3s

# Try second approach for all the cases where s2 < s3
Remaining_Pa1s = []

for sizes_ in Pa1s:
	s2, s3, pa1 = sizes_
	if s2 >= s3:
		Remaining_Pa1s.append(sizes_)
		continue
	s1 = 1024 - s2 - s3
	print("Trying... s1 = {0}, s2 = {1}, s3 = {2}".format(s1, s2, s3))

	for pa3 in Pa3s[s3]:
		remN = rem_terms(N, pa1, pa3, [s1, s2, s3])
		remN = remN >> s3
		invpa3 = inverse(pa3, 2**s3)
		sumpa2qa2 = ((remN % 2**s3) * invpa3) % (2**s3)
		remN = remN - ((sumpa2qa2 * pa1) << (s2 + s3))
		remN = remN - (sumpa2qa2 * pa3)
		remN = remN >> s3
		prodpa2qa2 = remN
		check, roots = check_roots(1, -sumpa2qa2, prodpa2qa2)
		if check:
			print("pa1 = {0}, pa3 = {1}".format(pa1, pa3))
			print("roots = ", roots)
			print("sizes = ", [s1, s2, s3])
			p = (pa1 << (s2 + s3)) + (roots[0] << s3) + pa3
			if N % p == 0:
				print("p = ", p)
				print("q = ", N//p)
				quit()

Pa1s = Remaining_Pa1s

# Try Coppersmith Attack for the remaining possibilities

P.<x> = PolynomialRing(Zmod(N))

for size_ in Pa1s:
	s2, s3, pa1 = size_
	s1 = 1024 - s2 - s3
	print("Trying... s1 = {0}, s2 = {1}, s3 = {2}".format(s1, s2, s3))
	upper_bound = 2**s2
	for pa3 in Pa3s[s3]:
		f = pa1*(2**(s2 + s3)) + x*(2**s3) + pa3
		f = f.monic()
		roots = f.small_roots(beta = 0.5, X = upper_bound)
		if len(roots) != 0:
			print("[*] roots = ", roots)
			print("pa1 = {0}, pa3 = {1}".format(pa1, pa3))
			for pa2 in roots:
				p = int(pa1*(2**(s2 + s3)) + pa2*(2**s3) + pa3)
				if N % p == 0:
					q = N // p
					print("[+] p = %d" % p)
					print("[+] q = %d" % q)
					quit()

# s1 = 236, s2 = 438, s3 = 350
# b'Here is the message: CTF-BR{w3_n33d_more_resources_for_th3_0mni_pr0j3ct}\n'
