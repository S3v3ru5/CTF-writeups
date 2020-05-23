
<h1> King Exchange Challenge Writeup [Crypto] </h1>

Luckily, I got First blood for this challenge.

In this challenge, we were given with two files `server.py` and `output.txt`.

The Execution flow of `server.py` is quite simple, it generates a key using `Diffie-Hellman Key Exchange` and `encrypts
the flag using AES` with shared key.

The Group over which the DH key exchange done is not given exactly, but I assumed from addition function
and Multiplication function that Group is related to Elliptic Curves.

This is the code for Addition and Multiplication of points.

```python
# p is a prime
def add_points(P, Q):
    return ((P[0]*Q[0]-P[1]*Q[1]) % p, (P[0]*Q[1]+P[1]*Q[0]) % p)

def multiply(P, n):
    Q = (1, 0)
    while n > 0:
        if n % 2 == 1:
            Q = add_points(Q, P)
        P = add_points(P, P)
        n = n//2
    return Q
```

Multiplication is done using Double and Add method.

Searching through various forms of the elliptic curves for a similar addition law, I found that [Edwards Curve](https://en.wikipedia.org/wiki/Edwards_curve) addition law is 
quite similar to the addition law used by add_points function.

Edwards Elliptic Curves are of the form `x^2 + y^2 = 1 + d*x^2*y^2. (d != 0 & 1)`

Edwards Curve Additon law --> `(x1, y1) + (x2, y2) = (x1y2 + x2y1) / (1 + dx1x2y1y2) ,  (y1y2 - x1x2) / (1 - dx1x2y1y2).`

if d = 0 <br>
    Addition law becomes  --> `(x1, y1) + (x2, y2) = x1y2 + x2y1 ,  y1y2 - x1x2 `
  
Assuming points are represented as `(x, y)` in `server.py` and `P = (x1, y1), Q = (x2, y2)`
`add_points(P, Q)` function calculates new point as `(x3, y3) = x1x2 - y1y2 , x1y2 + x2y1.`

clearly, both the formulas doesn't match and also neutral element of Edwards Curve is (0, 1) whereas neutral element used 
in the multiply function is (1, 0). 

The formulas do match  if we consider that points in server.py are represented as `(y, x)`. 
Assuming that points are represented in `(y, x)` form and `P = (y1, x1) , Q = (y2, x2).` <br>
`add_points(P, Q)` function calculates new point as `(y3, x3) = (y1y2 - x1x2, x1y2 + x2y1).`

Now, both formulas and neutral elements match exactly.

Even though both formulas match, I am not sure whether this approach is correct or not because representing points in this `((y,x))` way
is quite unusual and Another issue is that when we substitute d = 0 in Edwards Curve equation, it becomes, `x^2 + y^2 = 1` which is `not an Elliptic Curve` but an Equation of the Circle.

The definition of the Edwards Curve also specifies that d != 0.

Coming back to solution, As both formulas match assuming that points statisfy the equation `x^2 + y^2 = 1`. 
We can easily calculate the prime p using this information.
As we were given three points `(generator g, A's PublicKey A, B's PublicKey B)` which statisfy the equation modulo `p`.

==> `gx^2 + gy^2 = 1 + k1*p, Ax^2 + Ay^2 = 1 + k2*p, Bx^2 + By^2 = 1 + k3*p.`

so, `GCD(gx^2 + gy^2 - 1, Ax^2 + Ay^2 - 1, Bx^2 + By^2 - 1)` will give us the required `prime p`, somtimes along with small factors.

After obtaining prime p, I had no idea on how to proceed further.

I realized after a failed attempt that the function `add_points(P, Q)` does `Complex number multiplication` if we consider <br>
`P = P[0] + P[1]*i, Q = Q[0] + Q[1]*i` and `multiply(P, n)` function does `Modular Complex Exponentiation`.

I had searched how will be the structure of Group with `Modular Complex Multiplication` as operation and found [this paper](https://www.researchgate.net/publication/319731501_COMPLEX_PUBLIC_KEY_CRYPTOSYSTEMS).
After reading few pages and realizing that elements in `Complex Finite Field`(term used in the linked paper) statisfy most properties of Finite fields.
I wanted to find the number of elements are in a Complex Finite field with prime p. Using my small brain I calculated it
as `(p**2 - 1)`. The reasoning for this is,

`complex numbers are of form (x + y*i) and x & y belongs to {0, 1,...,p-1} which gives p**2 combinations and taking out (0, 0)
from the combinations results in p**2 - 1.`

I have verified this by exponentiating random complex numbers to `(p**2 - 1)` and checking that result is identity element `(1, 0)`.

for the `p` value which our challenge uses, `(p**2 - 1)` i.e order has many small factors. `(factors < 2**20)`

We can use the `pohlig-hellman` attack over the `Complex finite field` to solve the `discrete log` first in sub groups with the help of bruteforce and Using
`Chinese Remainder Theorem` to calculate the complete secret.

`solve.py` contains my naive implementation of pohlig hellman attack and other solution code.

My Failed (May be foolish) Attempt is I tried to convert Edwards curve with d = 0 to Weierstrass form, resulting Elliptic Curve is
is a singular curve (node)  but [this attack](https://crypto.stackexchange.com/questions/61302/how-to-solve-this-ecdlp/61434) cannot work directly cause `a` 
as in (x^2*(x + a)) is not a square in GF(p). We have to use other transformation to transfer points to Multiplicative group. 
(Attack details were given in Section 2.10 of the Elliptic Curves: Number Theory and Cryptography 2nd Edition book by Washington).




