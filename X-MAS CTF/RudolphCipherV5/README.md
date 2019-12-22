<h1> RudolpCipherV5 Writeup [Crypto] </h1>

<br> Two files are given in this challenge server.py & RudolphCipher.py and a serive to connect. </br>
Service works as follow
<pre>

1.) It generates two random messages of 8 bytes each.(m1, m2)
2.) Encrypts both the messages using the Rudolph Cipher with a random key.(c1, c2)
3.) Gives us the one(m1) of the messages, and the two ciphertexts(c1, c2) and
4.) we have to calculate the other message(m2) by using the given m1, c1, c2.

</pre>
This process is repeated 10 times. If we were able to decrypt the message m2 all 10 times then the server greets with the flag.
<br><br>The main part of the Rudolph Cipher for us is 

```python
def encrypt(self, message):
    A = bytes_to_int(message[:self.word_size / 8])
    B = bytes_to_int(message[self.word_size / 8:])
    A = A ^ self.S[0]
    B = B ^ self.S[1]
    for i in range(1, self.rounds + 1):
	A = rotate_left((A ^ B), i, self.word_size) ^ self.S[2 * i]
	B = rotate_left((B ^ A), i, self.word_size) ^ self.S[2 * i + 1]
    return int_to_bytes(A,self.word_size) + int_to_bytes(B,self.word_size)
```

In the above code, S is a list of 38 subkeys created using the expand key function and word size is 32 bits.
so, encrypt function divides the given 8 bytes message into two equal parts and does some xor operations & some rotation
operations on both the parts. There are total of 18 rounds and in each round the subkeys are combined with a xor operation.

Now, in order to get the flag we have to decrypt a random ciphertext by using a plaintext, ciphertext pair (m1, c1) only.

<h3> Breaking the Rudolph Cipher </h3>
In the encryption function all the operations are either xor or rotation. And this operation are done on the 32 bit integers.
remember A, B are 4 bytes each & all the subkeys are also 32 bit integers.<br>
Most important thing to know in order to solve this challenge is that <pre>xor is same as the addition in finite field GF(2)</pre>
so, if we consider A, B to be binary vectors (vectors with only 1 & 0 as entries) in GF(2).<br><br>
we can represent xor between A, B or S as Vector addition and if all the operations done in the encryption process are xor alone then, Complete encryption can be represented as sum of the vector with plaintext vectors & subkey vectors resulting in the ciphertext vectors.<br><br>
From One plaintext and ciphertext pairs we can extract all the subkey part using appropriate vector operations & use that to decrypt the other Ciphertext.<br>
But in our challenge another operation is also included that is rotation of bits.
We can't represent rotation as an vector operation & above process will not work.

But We can represent the rotation of bits as the multiplication operation if we consider the numbers as the elements(polynomials) of extension field GF(2^32) with modulus = y\**32 + 1.(but resultant is not a field but a PolynomialRing as modulus = y\**32 + 1 is reducible ).
<pre>
To clear up about considering numbers as the polynomials,
consider a = 1920282659. a is a 32 bit integer it's binary notation is 
a = (1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1) 
so, resulting polynomial would be <br>
</pre>

```python
a_poly = 0
a = a[::-1]
for i in range(32):
	a_poly += a[i]*(x**i)
```
<pre>
In simple words 
(1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1) 
is the coefficient vector of resulting polynomial with rightmost(lsb) bit as the coefficient of x**0.
</pre>

Coming back to idea of rotation of bits represented as polynomial operation.<br>
rotate_left(A, i) operation is same as the A*(x\**i)(if we consider lsb as the constant term) in PolynomialRing.<br>

Finally, we know this
<pre>
- xor operation is same as the addition of corresponding polynomials in above defined PolynomialRing.
- rotation can be represented as the multiplication with x\**i.
</pre>
knowing this two points is enough to completely solve the challenge.<br><br>
I will trace upto first rounds of encryption for better understanding.
<pre>
Consider A, B and SUBKEYS [S0,S1,...,S38] as polynomials.
and Assume C, D as the intermediate Outputs
first step is 
	C = A ^ S0 equivalent to C = A + S0
	D = B ^ S1 equivalent to D = B + S1
	<br>
round1:	C = rotate_left((C ^ D), 1, 32) ^ S2 equivalent to  C = (C + D)*(x**1) + S2
	D = rotate_left((D ^ C), 1, 32) ^ S3 equivalent to  D = (D + C)*(x**1) + S3
	....
	iterates for 18 rounds with variable rotations and subkeys

Consider C, D after the 1st round
C = (C + D)*(x**1) + S2
C = ((A + S0) + (B + S1))*(x**1) + S2 (C = A^S0 and D = B^S1 at the start of encryption)
C = (A + B + S0 + S1)*x + S2
C = A*x + B*x + S0*x + S1*x + S2
and
D = (D + C)*(x**1) + S3
D = (D + (A*x + B*x + S0*x + S1*x + S2))*x + S3
D = ((B + S1) + (A*x + B*x + S0*x + S1*x + S2))*x + S3
D = B*x + S1*x + A*(x**2) + B*(x**2) + S0*(x**2) + S1*(x**2) + S2*x + S3
D = A*x**2 + B*(x + x**2) + S0*x**2 + S1*(x + x**2) + S2*x + S3
</pre>
After first round
<pre>
C = A*x + B*x + S0*x + S1*x + S2
D = A*x**2 + B*(x + x**2) + S0*x**2 + S1*(x + x**2) + S2*x + S3
</pre>
so, after 18 rounds C, D will have this form.
<pre>
C = A*(polynomial t1) + B*(polynomial t2) + (combinations of subkeys S0, S1, ... S37  K1)
D = A*(polynomial t3) + B*(polynomial t4) + (combination of subkeys S0, S1, ... S37   K2)
</pre>
<pre>
Seeing C, D after 1st round in this form will give
t1 = x, t2 = x , K1 = S0*x + S1*x + S2

t3 = x**2, t4 = (x + x**2) , K2  = S0*x**2 + S1*(x + x**2) + S2*x + S3
</pre>
I used sage to calculate t1, t2, t3, t4 as calculating them by hand will be impossible.
After 18 rounds they turned out to be
<pre>
t1 = x**28 + x**24 + x**22 + x**21 + x**17 + x**16 + x**15 + x**13 + x**11 + x**10 + x**4 + x**3 + 1
t2 = x**31 + x**30 + x**29 + x**28 + x**22 + x**21 + x**20 + x**14 + x**12 + x**11 + x**8 + x**5 + x**2 + x

t3 = x**29 + x**25 + x**24 + x**23 + x**22 + x**20 + x**17 + x**14 + x**11 + x**8 + x**4 + x**2 + x + 1
t4 = x**31 + x**28 + x**24 + x**23 + x**22 + x**19 + x**18 + x**16 + x**14 + x**12 + x**9 + x**6 + x**2
</pre>
So, After 18 rounds final Ciphertexts C, D will be
<pre>
C = A*t1 + B*t2 + K1
D = A*t3 + B*t4 + K2
</pre>
representing relation in form of matrices helps in better understanding
<pre>

T*Pt + K = Ct

T =  [t1	t2]  , Pt = [ A ] , K = [ K1 ] , Ct = [ C ]
     [t3	t4]         [ B ]       [ K2 ]        [ D ] 

Where A, B are plaintext polynomials and C, D are final ciphertext polynomials.
</pre>

<pre>
T*Pt + K = Ct
Pt = (T**-1)*(Ct - K) 
and
K = Ct - T*Pt
</pre>

Coming back to our challenge, we were given with one plaintext(m1) and ciphertext pair(ct1) and second ciphertext(c2) to which we have to calculate the corresponding plaintext(m2).
<pre>
from m1, c1 calculate A1, B1, C1, D1
Pt1 = [ A1 ] , Ct1 = [ C1 ]
      [ B1 ]         [ D1 ]

Calculate K = Ct1 - T*Pt1
then, calculate Pt2 using CT2 = [ C2 ] , K as Pt2 = (T**-1)*(Ct2 - K)
                                [ D2 ]

Convert Polynomials to the numbers and to text.
</pre>
Repeat the above process for 10 times and get the flag

Check Out solve.sage for implementation.
<h5> Flag :: X-MAS{5_b17_t00_1nd3p3nden7_f0r_my_t45t3} </h5>

There are small details which should be taken care of most important one is that bytes_to_int and int_to_bytes 
functions used by the server assumes the string to be little endian.<br>
Because of this detail I have wasted so much of my time by testing on the wrong pair of numbers.<br>
And another detail is version of sage that I'm using gives an Not implemented error when I tried to calculate the inverse of 
Matrix T (don't know about the updated versions though). <br>
I have used (1/det(T))*T.adjoint() formula to calculate the inverse of Matrix T.
