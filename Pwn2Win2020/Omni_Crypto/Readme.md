# Omni_Crypto challenge writeup [Crypto]

In this challenge, we were given the [enc.py](https://github.com/S3v3ru5/CTF-writeups/blob/master/Pwn2Win2020/Omni_Crypto/enc.py) and [output.txt](https://github.com/S3v3ru5/CTF-writeups/blob/master/Pwn2Win2020/Omni_Crypto/output.txt) files.<br>
`enc.py` implements rsa algorithm with primes of 1024 bits generated using the below function.
```python
def getPrimes(size):
    half = random.randint(16, size // 2 - 8)
    rand = random.randint(8, half - 1)
    sizes = [rand, half, size - half - rand]

    while True:
        p, q = 0, 0
        for s in sizes:
            p <<= s
            q <<= s
            chunk = random.getrandbits(s)
            p += chunk 
            if s == sizes[1]:
                chunk = random.getrandbits(s)
            q += chunk
        p |= 2**(size - 1) | 2**(size - 2) | 1
        q |= 2**(size - 1) | 2**(size - 2) | 1
        if gmpy2.is_prime(p) and gmpy2.is_prime(q):
            return p, q
```
`getPrimes(size)` function first generates three random numbers assume them as `[s1, s2, s3](sizes list in line 4)` with `s1 + s2 + s3 = size` and
few constraints.<br>
Then the function generates `primes p and q` such that lower `s3 bits` of `p` & `q` are equal and also upper `s1 bits` of `p` & `q` are 
equal.<br>
Assume, 
```
p = (pa1 << (s2 + s3)) + (pa2 << s3) + pa3
q = (pa1 << (s2 + s3)) + (qa2 << s3) + pa3
```
`pa1, pa2, pa3` are of sizes `s1, s2, s3` bits and upper, middle, lower bits of prime p respectively.<br>
`qa2` is same as `pa2` but for prime `q`.

`N` in terms of `pa1, pa2, pa3, qa2` obtained by multiplying above equations is

`N = pa3**2 + ((pa3*qa2) << s3) + ((pa3*pa1) << (s2 + s3)) + ((pa2*pa3) << s3) + ((pa2*qa2) << (2*s3)) + ((pa2*pa1) << (s2 + 2*s3)) + ((pa1*pa3) << (s2 + s3)) + ((pa1*qa2) << (s3 + s2 + s3)) + ((pa1**2) << (2*(s2 + s3)))`

The lower `s3` bits of `N` come from the lower `s3` bits of `pa3**2`.<br>
==> `N % 2**s3 = pa3**2 % 2**s3`

so, if we are able to calculate the `square root` of `N % 2**s3 modulo 2**s3`, then we will get the original value of `pa3` as it is less than `2**s3`.<br>
[This thread](https://projecteuler.chat/viewtopic.php?t=3506) discuss the algorithm to calculate `square root` modulo `powers of 2`.<br>
Discussed algorithm works for the given challenge `N` and we can obtain the value of `pa3`.<br>

For the value of `pa1`, the upper bits of the `N` is approximately equal to `pa1**2`.
so, taking the approximate `square root` of `N >> (2*(s2 + s3))` gives the value of `pa1`.

As, we can calculate the values of `pa1` and `pa3`, we can use the `coppersmith attack` to calculate one of the primes.
```python
P.<x> = PolynomialRing(Zmod(N))
f = pa1*(2**(s2 + s3)) + x*(2**s3) + pa3
f = f.monic()
roots = f.small_roots(beta = 0.5)
```
One problem is that we don't know the values of `s2` and `s3`. so, we have to check all the possible values and factor `N`.

After trying all the possible values for `s2` and `s3`, I could not factor `N` because of a small but bad mistake that I realised
after trying another approach which only works for half of the cases.

Another approach which doesn't depend on `coppersmith attack` works only if `s2 < s3` is <br>

As `N` can be written as <br>
`N = pa3**2 + ((pa3*qa2) << s3) + ((pa3*pa1) << (s2 + s3)) + ((pa2*pa3) << s3) + ((pa2*qa2) << (2*s3)) + ((pa2*pa1) << (s2 + 2*s3)) + ((pa1*pa3) << (s2 + s3)) + ((pa1*qa2) << (s3 + s2 + s3)) + ((pa1**2) << (2*(s2 + s3)))`

and as we know the values of `pa1` and `pa3`, we can remove all the terms which depend only on `pa1` and `pa3` which leaves us with value equal to
<pre>
remN = ((pa1*qa2 + pa1*pa2) << (s2 + 2*s3)) + ((pa2*qa2) << (2*s3)) + ((pa3*qa2 + pa3*pa2) << s3)
	   = ((pa1*(qa2 + pa2)) << (s2 + 2*s3)) + ((pa2*qa2) << (2*s3)) + ((pa3*(qa2 + pa2)) << s3)
</pre>
we can find the `sum` of `qa2` and `pa2` modulo `2**s3` using `remN`.
```
remN % 2**s3 = pa3*(qa2 + pa2) % 2**s3
(qa2 + pa2) % 2**s3 = (remN % 2**s3)*inverse(pa3, 2**s3) % 2**s3
```
if `s2 < s3` then `(qa2 + pa2) % 2**s3 = qa2 + pa2`.

Now, using the `pa1`, `pa3`, `qa2 + pa2` and `remN`, we can calculate the value of `qa2*pa2`.

And given the sum and product of `pa2` & `qa2` we can calculate the values of `pa2` & `qa2` by finding the roots `quadratic equation` `x**2 + b*x + c` with `b = -(qa2 + pa2)` and `c = qa2*pa2`.

This approach is faster but only works for half of the cases and it doesn't work for the challenge `N`.

I realised my mistake that I did while trying `coppersmith attack` which is : 
when using `small_roots` method I only specified the `beta` parameter and leave out `X (upper bound of root)` parameter for the method to decide.

So, after trying the `coppersmith attack` with all the parameters, it found the root.

Decrypting the ciphertext gives us the flag,

FLAG :: `Here is the message: CTF-BR{w3_n33d_more_resources_for_th3_0mni_pr0j3ct}\n`

solution code :: [omni_crypto_solve.sage](https://github.com/S3v3ru5/CTF-writeups/blob/master/Pwn2Win2020/Omni_Crypto/omni_crypto_solve.sage)


