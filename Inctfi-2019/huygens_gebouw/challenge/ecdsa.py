#!/usr/bin/env python2.7
from Crypto.Random import random
from Crypto.Util.number import long_to_bytes, bytes_to_long, GCD, inverse
from ecc import *
from hashlib import sha256
from secret import d, flag
import sys

class Unbuffered(object):
   def __init__(self, stream):
       self.stream = stream
   def write(self, data):
       self.stream.write(data)
       self.stream.flush()
   def writelines(self, datas):
       self.stream.writelines(datas)
       self.stream.flush()
   def __getattr__(self, attr):
       return getattr(self.stream, attr)

sys.stdout = Unbuffered(sys.stdout)

def slice_string(s, _len):
    return long_to_bytes(int(bin(bytes_to_long(s))[2:2+_len], 2))

def gen_rand(lower_limit, upper_limit):
    _rand_num = random.randint(lower_limit, upper_limit)
    _rand_num = map(ord, list(long_to_bytes(_rand_num)))
    for i in range(len(_rand_num)):
        _rand_num[i] ^= _rand_num[-1]
        _rand_num[i] = ((_rand_num[i] << 1) + 3) % 256
    _rand_num = bytes_to_long("".join(map(chr, _rand_num)))
    return _rand_num

p = 2**256 - 2**224 + 2**192 + 2**96 - 1
a = p-3
b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
EC = CurveFp(p, a, b)

_Px = 105628562773329337640893595054548446109845168797622368389180213953990926700662
_Py = 32408302692268607486270308925513058111871258446764614158480809006157801114098

assert EC.contains_point(_Px, _Py)

class PrivateKey:
    def __init__(self, EC, n, d, G):
        self.EC = EC
        self.n = n
        self.d = d
        self.G = G
        assert self.EC.contains_point(self.G.x(), self.G.y())
        assert self.G * self.n == INFINITY

    def get_public_key(self):
        return self.d*self.G

def sign(self, m):
    e = sha256(m).digest()
    Ln = len(bin(self.n)[2:])
    z = bytes_to_long(slice_string(e, Ln))
    k = gen_rand(1, self.n-1)
    r = (k*self.G).x()
    assert GCD(k, self.n) == 1
    s = (inverse(k, self.n)*(z + r*self.d)) % self.n
    return (r, s)

class PublicKey:
    def __init__(self, curve, P, G, n):
        self.curve = curve
        self.P = P
        self.G = G
        self.n = n
        try:
            assert self.P != INFINITY
            assert self.curve.contains_point(self.P.x(), self.P.y())
            assert self.n*self.P == INFINITY
        except:
            print "[-] Invalid parameters!"
            sys.exit(0)

    def verify(self, signature, m):
        try:
            r, s = signature
            assert GCD(s, self.n) == 1
            assert r >= 1
        except:
            return False
        e = sha256(m).digest()

        Ln = len(bin(self.n)[2:])
        z = bytes_to_long(slice_string(e, Ln))

        s_inv = inverse(s, self.n)
        u_1 = (s_inv*z) % self.n
        u_2 = (s_inv*r) % self.n

        T = u_1*self.G + u_2*self.P
        return r == T.x()

G = Point(EC, _Px, _Py, n)
obj = PrivateKey(EC, n, d, G)
print "Possible operations that can be performed by the server"
print "[1] Sign"
print "[2] Verify"
choice = int(raw_input("Enter your choice: "))
if choice == 1:
    message = raw_input("Enter the message you want to sign: ")
    if "admin" in message:
        print "[-] Cannot sign this message"
        sys.exit(0)
    signature = obj.sign(message)
    print "Here, take the signature (r, s):", signature
elif choice == 2:
    P = obj.get_public_key()
    assert (d*G).x() == P.x() and (d*G).y() == P.y()
    obj2 = PublicKey(EC, P, G, n)
    r = int(raw_input("Enter r: "))
    s = int(raw_input("Enter s: "))
    message = raw_input("Enter the message corresponding to the signature: ")
    print ""
    result = obj2.verify((r, s), message)
    if result == True:
        print "[+] Signature Verified to be true!"
        if message == "admin":
            print "Welcome admin!"
            print "Take your flag:", flag
    else:
        print "[-] Invalid signature!"
else:
    print "[-] Invalid choice"
    sys.exit(0)
