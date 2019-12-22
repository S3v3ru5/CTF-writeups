<h1> The Weather Challenge Writeup [pwn]</h1>

In this Challenge we were given a service to connect, but no binary has been given.<br>
When we connect to the service it prints a long base64 encoded string and asks us to give name as input after that
it gretts us and closes.<br>
The long base64 encoded string is a elf binary bytes and same elf is running on the service after printing the base64 encoded string.<br>
After connecting to the server two to three times, we can observe that elf file is changing slightly.<br>
Every binary follows the same pattern i.e Asks for the name using gets (with random offsets) then greet us and close.<br>
So, our goal is to find the offset between the return address and input buffer and then construct a ROP chain to get a 
shell.We have to do all this dynamically before the service timesout.<br>
I used pwn tools to calculate the offset.<br>
In the strings of the binary we can find "libc.so.6". I assumed it to be the libc file that the service is using.<br><br>
Exploit path would be
<pre>

1.) find offset to return address
2.) construct rop chain to leak libc address (__libc_start_main@got)
3.) return to main to use bof vuln again.
4.) calculate system address and
5.) construct rop chain to pop /bin/sh address into rdi and return to system

</pre>
But I haven't got an idea on how to find the main function address as the binary is stripped.

This forced me to use buffer overflow vuln only once.<br>
The restriction is that we have to construct all our rop chain in the first iteration only and we don't
know any libc address before returing to our first rop chain.<br>
My idea is to write "/bin/sh" in a known address (.bss section) and overwrite one of functions GOT entry with <br>
system function address and return to that functions plt with "/bin/sh" address in rdi.<br>
We can use gets function as the write primitive.It is the best choice as we can give input after calculating the system address.
<br>
<pre>

1.) find offset to return address
2.) construct rop chain to leak libc address (__libc_start_main@got) and to ask for input twice.
3.) calculate system address and
4.) overwrite puts@got with system address
5.) write "/bin/sh" in .bss section 
6.) return to puts@plt with bss section adress in rdi register.

</pre>

See the exploit.py file for code.
