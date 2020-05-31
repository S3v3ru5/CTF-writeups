# Lost_qKeys crypto challenge writeup

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
