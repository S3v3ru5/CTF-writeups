# Pwn2Win2020 CTF Writeups

- [Omni_Crypto](#omnicrypto)
  - Category : Crypto
  - Files : [enc.py](Omni_Crypto/enc.py), [output.txt](Omni_Crypto/output.txt)
  - Points : 246
  - Solves : 32
  - solution code : [omni_crypto_solve.sage](Omni_Crypto/omni_crypto_solve.sage)
- [Load_qKeys](#lost_qkeys)
  - Category : Crypto
  - Files : [server-model.py](Lost_qkeys/server-model.py)
  - Points : 246
  - Solves : 32
  - solution code : [lost_qkeys_solve.py](Lost_qkeys/lost_qkeys_solve.py)

---

# <a name="omnicrypto"></a> Omni_Crypto challenge writeup [Crypto]

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


---


# <a name="lost_qkeys"></a>Lost_qKeys crypto challenge writeup

In this challenge, we were given with [server-model.py](https://github.com/S3v3ru5/CTF-writeups/blob/master/Pwn2Win2020/Lost_qkeys/server-model.py) file and an netcat connection.<br>
The `server-model.py` basically constructs a `quantum circuit` based on a `password`(taken from the user), `Key`(generated using  `os.urandom()`) and `flag`.
It executes the circuit one time and measures the state of qubits and it gives the measured values to user.<br>
`server-model.py` uses [qiskit framework](https://qiskit.org/) to simulate the circuit.

The program flow of the `server-model.py` is quite simple

First it asks for a `password` with a prompt passwd: and then
it passes the `password` to below method

```python
    def send_qubits(self, msg, dest):
        qbit_config = self.decode(msg)
        q = qiskit.QuantumRegister(9*len(qbit_config))
        circ = qiskit.QuantumCircuit(q)
        for j, c in enumerate(qbit_config):
            if c=='1':
                circ.x(q[9*j])
            circ.cx(q[9*j],q[9*j+3])
            circ.cx(q[9*j],q[9*j+6])
            circ.h(q[9*j])
            circ.h(q[9*j+3])
            circ.h(q[9*j+6])
            circ.cx(q[9*j],q[9*j+1])
            circ.cx(q[9*j],q[9*j+2])
            circ.cx(q[9*j+3],q[9*j+4])
            circ.cx(q[9*j+3],q[9*j+5])
            circ.cx(q[9*j+6],q[9*j+7])
            circ.cx(q[9*j+6],q[9*j+8])
    return quantum_channel(circ, dest)
    
 ```
msg parameter is the `password` in the above method.<br>
The `password` is converted to a `bit-string` of `nbits`(padded if necessary).<br>
nbits is equal to 8*len(flag) which in our case is 520.<br>
The method creates a `Quantum register` with `9*nbits qubits`.<br>
It divides all the `qubits` into `groups of size 9` and takes each group of 9 qubits and sets state of `first qubit in the group to the corresponding bit of password` and then applies same operations on every group of `qubits`.<br>
Then the method passes control to the following method.
```python
    def read_qubits(self, circ):
        self.received_qubits = circ.qubits
        for i in range(0, len(self.received_qubits), 9):
            circ.cx(self.received_qubits[i], self.received_qubits[i+1])
            circ.cx(self.received_qubits[i], self.received_qubits[i+2])
            circ.ccx(self.received_qubits[i+1], self.received_qubits[i+2], self.received_qubits[i])
            circ.h(self.received_qubits[i])
            circ.cx(self.received_qubits[i+3], self.received_qubits[i+4])
            circ.cx(self.received_qubits[i+3], self.received_qubits[i+5])
            circ.ccx(self.received_qubits[i+4], self.received_qubits[i+5], self.received_qubits[i+3])
            circ.h(self.received_qubits[i+3])
            circ.cx(self.received_qubits[i+6], self.received_qubits[i+7])
            circ.cx(self.received_qubits[i+6], self.received_qubits[i+8])
            circ.ccx(self.received_qubits[i+7], self.received_qubits[i+8], self.received_qubits[i+6])
            circ.h(self.received_qubits[i+6])
            circ.cx(self.received_qubits[i], self.received_qubits[i+3])
            circ.cx(self.received_qubits[i], self.received_qubits[i+6])
            circ.ccx(self.received_qubits[i+3], self.received_qubits[i+6], self.received_qubits[i])

        circ = self.encrypt_flag(circ)
        self.decrypt_flag(circ)
```
This method also takes each `group of 9 qubits` and does similar operations an each group and passes control to the `encrypt_flag` method.
```python
    def encrypt_flag(self, circ):
        self.qbuffer = qiskit.QuantumRegister(self.nbits)
        circ.add_register(self.qbuffer)

        for i, c in enumerate(self.encoded_flag):
            if c=='1':
                circ.x(self.qbuffer[i])

        for i in range(len(self.key)):
            if self.key[i]=='1':
                circ.h(self.qbuffer[i])
        return circ
```
This is where `flag` comes into play.The method creates an additional `QuantumRegister` with size `nbits`.<br>
In order to understand the solution and the above code we need to have a small understanding of the operations done in all the mentioned functions.

According to [Qiskit docs](https://qiskit.org/documentation/tutorials/circuits/3_summary_of_quantum_operations.html) and [wikipedia page on Quantum gates](https://en.wikipedia.org/wiki/Quantum_logic_gate)
```
- All the qubits have default state 0 at the time of intialisation in qiskit framework.
- circ.h(qi) represents a Hadamard(H) gate which acts on a single qubit and after this operation there's an equal probability to measure the state of the qubit as 0 or 1.
- circ.x(qi) represents Pauli-X gate which acts on a single qubit and is quantum equivalent of Classical NOT gate i.e flips the state of qubit.
- circ.cx(qc, qi) is a Controlled NOT gate, if the qubit qc results in state 1 when measured then Pauli-X(Classical NOT) gate is applied on the qubit qi.
- circ.ch(qc, qi) is a Controlled Hadamard gate, if the qubit qc results in state 1 then Hadamard(H) gate is applied on qubit qi.
- circ.ccx(qc1, qc2, qi) represents Toffoli(CCNOT) gate, if the first two qubits qc1 & qc2 are in state 1 then Pauli-X(Classical NOT) gate is applied on the third qubit qi.
```
Coming back to `encrypt_flag` method, as it created the nbits number of qubits.<br>
It assigns each bit of `flag` to `qubit state` i.e if flag bit is 1, then qubit is flipped as qubit is intially in state 0 flipping results in state 1.

After flipping necessary qubits accordingly, it adds the `Key` i.e it iterates over `Key bits`.<br>
And if `key bit is 1` then it passes corresponding `flag qubit` into `Hadamard gate` which results in the bit being in state 0 or 1 equally likely. 
`flag qubits` are not involved in any of the operation if the corresponding `Key bit` is 0.

And this is where the `main flaw` is, 
```
For an nth flag qubit the probability that corresponding key bit is 1 is 1/2
probability that Hadamard gate flips the qubit is 1/2.
so, given a nth flag qubit the probability that it flips is (1/2)*(1/2) = 1/4.
if we take measurements for a noticable number of times then there will be a bias towards the correct bit.
```
We can use the above observation to calculate the entire `flag`.

Even though the following method is called after `encrypt_flag` method which adds some operations to the circuit, it `doesn't change the result` much.
```python
    def decrypt_flag(self, circ):
        for i in range(self.nbits):
            circ.ch(self.received_qubits[9*i], self.qbuffer[i])

        output = qiskit.ClassicalRegister(self.nbits)
        circ.add_register(output)
        circ.measure(self.qbuffer, output)

        bk = qiskit.Aer.get_backend('qasm_simulator')
        job = qiskit.execute(circ, bk, shots=1)
        res = job.result()
        if not res.success:
            raise MemoryError('You should use a real quantum computer...')
        res = res.get_counts(circ)
        self.res = [self.encode(int(k,2)) for k in res.keys()]
```
This function adds `Controlled Hadamard gate` to the `flag qubits` whose `control qubits` are taken from the previously created qubits(created based on the user `password`) and measures the state of flag qubits into output Classical Register and gives the output.

The reason that I think this `addition of Controlled Hadamard gates doesn't change` much because it only applies on the `flag qubits` when `control qubit is 1` and if we see the operations(in methods `send_qubits` and `read_qubits`) which result in the control qubits and using description of the gates we can assume that the probability of control qubit being in state 1 is very less after the operations.

solution code :: [lost_qkeys_solve.py](https://github.com/S3v3ru5/CTF-writeups/blob/master/Pwn2Win2020/Lost_qkeys/lost_qkeys_solve.py)

`FLAG :: _#__CTF-BR{_1s_th4t_HoW_u_1mPl3meNt_@_QUantUm_0ne_t1m3_paD_???}_\\` 
