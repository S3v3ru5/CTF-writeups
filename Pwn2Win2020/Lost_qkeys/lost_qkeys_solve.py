from pwn import *
from Crypto.Util.number import long_to_bytes

counter = {}
def init_counter(counter):
	for i in range(520):
		counter[i] = {0:0, 1:0}

init_counter(counter)

for i in range(100):
	conn = remote("quantum.pwn2.win", 1337)
	conn.recvline()
	conn.sendline(b"0"*65)
	res = conn.recvline().strip()
	print("i = ", i)
	print("res = ", res)
	val = list(map(int, bin(int(res, 16))[2:].zfill(520)[::-1]))
	for i in range(520):
		counter[i][val[i]] += 1
	print("------------------*****************----------------")
	conn.close()

flag = ""

for i in range(520):
	if counter[i][0] < counter[i][1]:
		flag += "1"
	else:
		flag += "0"

print("flag = ", long_to_bytes(int(flag, 2)))
