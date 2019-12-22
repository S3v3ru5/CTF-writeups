<h1> RudolpCipherV5 Writeup [Crypto] </h1>

<br> Two files are given in this challenge server.py & RudolphCipher.py and a serive to connect. </br>
Service works as follow
<pre>

1.) It generates two random messages of 8 bytes each.(m1, m2)
2.) Encrypts both the messages using the Rudolph Cipher.(c1, c2)
3.) Gives us the one(m1) of the messages, and the two ciphertexts(c1, c2) and
4.) we have to calculate the other message(m2) by using the given m1, c1, c2.

</pre>
This process is repeated 10 times. If we were able to decrypt the message m2 all 10 times then the server greets with the flag.
<br><br>The main part of the Rudolph Cipher for us is 

```python
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
```




