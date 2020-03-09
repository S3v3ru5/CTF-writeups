<h1> Dirty Laundry Challenge Writeup [Crypto] </h1>

The description of this challenge doesn't give much information about the challenge. In the given attachments, there are two
files `chall.py` and `output.txt`.

This challenge is a combination of shamir secret sharing scheme and paillier cryptosystem.

First, it chooses a 1024 bit Prime p, and defines a sharmir secret sharing scheme with flag as the secret with number of shares
equal to 5 and k = 3 (i.e requires minimum of 3 shares to obtain the secret). Each of the share(f(x)) is combined with a noise
term ei and are encrypted with the paillier cryptosystem. For each share a new key pair of paillier cryptosystem is generated.

we are given the x , encrypted f(x) and correspoding paillier public key \[n, g\].
Corresponding code snippets are ::

Shamir secret Sharing ::
```python
def make_shares(secret, k, shares, prime=PRIME):
    PR, x = PolynomialRing(GF(prime), name='x').objgen()
    f = PR([secret] + [ZZ.random_element(prime) for _ in range(k-1)])
    xy = []
    pubkey = []
    for x in range(1, shares+1):
        noise = prng.rand()
        n, g, y = paillier_enc(f(x) + noise, prime, noise)
        pubkey.append([n, g])
        xy.append([x, y])
    return pubkey, xy
```
 Paillier Encryption code ::
 ```python
 def paillier_enc(m, p, noise):
    p = next_prime(p + noise)
    q = getStrongPrime(512)
    n = p * q
    g = (1 + prng.rand() * n) % n**2
    c = pow(g, m, n**2) * pow(prng.rand(), n, n**2) % n**2
    return n, g, c
```

all the noises and random values required for paillier encryption are generated using PRNG256 class.

In the paillier_enc function, observe that all the public keys ni contains (p + noise(ei)) as a factor. p is same for all the
ni. <br> 
My intial thought was to use this fact to solve the challenge, but I haven't got any lead. So, I left that thought and looked for any other ways and I finally took the following approach to solve this challenge.

First step is to decrypt the paillier encrypted shares.
Paillier encryption works as follows.

generate n = p\*q     (p & q are primes) <br>
generate g = (1 + r1*n) % n\**2   (r1 can be random or equal to 1) <br>
ciphertext = (g\**m)\*(r2\**n) % n\**2     (m is the message we want to encrypt and r2 is a random value). <br>

To decrypt we would need phi(n) = (p-1)\*(q-1) which requires factorization of n.

Another way we can decrypt the paillier encrypted ciphertext that I found requires the random values r1 and r2.

Given r1, r2 (random values used in paillier encryption) and \[n, g\] (public key) and ciphertext. <br>
we can obtain (g\**m) mod n\**2 by multiplying ciphertext c with the inverse of (r2\**n) modulo n\**2. <br>
given the (g\**m) we can obtain the message <br>
`m = (g**m - 1)/(r1*n)` <br>
The proof of this is <br>
Using the Binomial Expansion <br>
```
(1 + r1*n)**x = 1 + x*(r1*n) + (xC2)*(r1*n)**2 + ...
(1 + r1*n)**x mod n**2 = 1 + x*(r1*n) mod n**2

x = (((1 + r1*n)**x) - 1)/(r1*n)
```

we have all the terms except r1 and r2. <br>
we can obtain r1 from g and n. <br>


 
