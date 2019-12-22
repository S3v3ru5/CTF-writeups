import os
from hashlib import sha256
from text import *
from RudolphCipher import *
from binascii import *

def Pow():
    s = os.urandom(10)
    h = sha256(s).hexdigest()
    inp = raw_input("Provide a hex string X such that sha256(X)[-6:] = {}\n".format(h[-6:]))
    is_hex = 1
    for c in inp:
        if not c in '0123456789abcdef':
            is_hex = 0

    if is_hex and sha256(inp.decode('hex')).hexdigest()[-6:] == h[-6:]:
        print 'Good, you can continue!'
        return True
    else:
        print 'Oops, your string didn\'t respect the criterion.'
        return False

if not Pow():
    exit()

print intro

error = False

for i in range(1, 11):
    key = os.urandom(16)
    r = RudolphCipher5(key,32,18)
    msg1 = os.urandom(8)
    msg2 = os.urandom(8)
    
    hex1 = hexlify(msg1)
    hex2 = hexlify(msg2)

    ct1 = r.encrypt(msg1)
    ct2 = r.encrypt(msg2)

    hex_ct1 = hexlify(ct1)
    hex_ct2 = hexlify(ct2)

    print str(i), hex1, hex2, hex_ct1, hex_ct2
    inp = raw_input(chall_request)
    
    is_hex = 1
    for c in inp:
        if not c in '0123456789abcdef':
            is_hex = 0

    if not is_hex:
        print invalid_input
        error = True
        break
    if hex2 == inp:
        print challange_win
    else:
        print challange_loose
        error = True
        break

if not error:
    print win.format(FLAG)
