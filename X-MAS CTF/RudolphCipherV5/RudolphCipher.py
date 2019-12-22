e = 2.718281828459045
phi = 1.618033988749894

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

def Odd(x):
    return int(x/2) * 2 + 1

def rotate_left(val, r_bits, max_bits):
	v1 = (val << r_bits % max_bits) & (2 ** max_bits - 1)
	v2 = ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))
	return v1 | v2

def rotate_right(val, r_bits, max_bits):
	v1 = ((val & (2 ** max_bits - 1)) >> r_bits % max_bits)
	v2 = (val << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1))
	return v1 | v2

class RudolphCipher5(object):
    def __init__(self, key, word_size, rounds): #32, 18
        self.word_size = word_size
        self.rounds = rounds
        self.Pw = Odd((e - 2) * 2**self.word_size)
        self.Qw = Odd((phi - 1) * 2**self.word_size)
        self.mask = 2**word_size - 1
        self.S = self._expand_key(key)

    def _expand_key(self, key):
    	byte_size = self.word_size / 8
        t = 2 * (self.rounds + 1)
        L = []
        
        for i in range(0, len(key), byte_size):
            L.append(bytes_to_int(key[i : i + byte_size]))
	    c = len(L)

        S= [self.Pw]
        for i in range(1, t): 
            S.append((S[i - 1] + self.Qw) & self.mask)

        i = j = A = B = 0
        for step in range(3 * max(t, c)): 
            A = S[i] = rotate_left((S[i] + A + B), 3, self.word_size)
            B = L[j] = rotate_left((L[j] + A + B), A + B, self.word_size)
            i = (i + 1) % t
            j = (j + 1) % c

        return S

    def encrypt(self, message):
        print(message[:self.word_size / 8])
        print(message[self.word_size / 8:])
        A = bytes_to_int(message[:self.word_size / 8])
        B = bytes_to_int(message[self.word_size / 8:])
        
        A = A ^ self.S[0]
        B = B ^ self.S[1]
        for i in range(1, self.rounds + 1):
            A = rotate_left((A ^ B), i, self.word_size) ^ self.S[2 * i]
            B = rotate_left((B ^ A), i, self.word_size) ^ self.S[2 * i + 1]
        print("C = "+str(A))
        print("D = "+str(B))
        return int_to_bytes(A,self.word_size) + int_to_bytes(B,self.word_size)

    def decrypt(self, message):
        A = bytes_to_int(message[:self.word_size / 8])
        B = bytes_to_int(message[self.word_size / 8:])
        
        for i in range(self.rounds, 0, -1):
            B = rotate_right(B ^ self.S[2 * i + 1], i, self.word_size) ^ A
            A = rotate_right(A ^ self.S[2 * i], i, self.word_size) ^ B

        B = B ^ self.S[1]
        A = A ^ self.S[0]

        return int_to_bytes(A,self.word_size) + int_to_bytes(B,self.word_size)
