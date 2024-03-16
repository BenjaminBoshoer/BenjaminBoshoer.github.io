---
layout: single
title: "Input - Pwnable.kr"
excerpt: "Input is a pwn challenge under \"Toddler Bottle\" category in the wargame site pwnable.kr.
unlike other pwn challenges under \"Toddler's Bottle\", this challenge is very straightforward 
and has 5 steps. In this challenge we will use pwntools, a CTF python library that makes all types of I/O a lot easier, and get to know pipes a little better."
show_excerpt: true
date: 2024-03-14
classes: wide
header:
  teaser: /assets/images/avatarpng.png
  teaser_home_page: true
  icon: /assets/images/avatarpng.png
related: true
categories:
  - CTF
tags:
  - Python
  - Binary Exploitation
  - C
---

Input is a pwn challenge under "Toddler Bottle" category in the wargame site pwnable.kr.
unlike other pwn challenges under "Toddler's Bottle", this challenge is very straightforward 
and has 5 steps. In this challenge we will use pwntools, a CTF python library that makes all types of I/O a lot easier, and get to know pipes a little better.

In this writeup I will discuss the 5 stages seperatly and in the end reveal the final code solution.

<h1 style="font-family:quirell;"><font color="#9C7A97">Starting point</font></h1>

Login credentials for this challenge are:
> Username: **input2**\
> Password: **guest**

Using ssh we log into the machine
```sh
beny@Air:~ % ssh input2@pwnable.kr -p 2222
input2@pwnable.krs password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@khu.ac.kr
- irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Thu Mar 14 13:02:06 2024 from 77.139.116.129
input2@pwnable:~$
```

Let's see what files are in the home directory

```bash
input2@pwnable:~$ ls
flag  input  input.c
```

Since this is a pwn challenge, there are three files in the home directory. file, input and input.c\
flag is a text file that contains the flag for this challenge. input.c is the source code of 'input' which we must pwn.

<h1 style="font-family:quirell;"><font color="#9C7A97">The Code</font></h1>

```c
int main(int argc, char* argv[], char* envp[]){
	printf("Welcome to pwnable.kr\n");
	printf("Let's see if you know how to give input to program\n");
	printf("Just give me correct inputs then you will get the flag :)\n");

	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");	

	// stdio
	char buf[4];
	read(0, buf, 4);
	if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
	read(2, buf, 4);
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
	printf("Stage 2 clear!\n");
	
	// env
	if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
	printf("Stage 3 clear!\n");

	// file
	FILE* fp = fopen("\x0a", "r");
	if(!fp) return 0;
	if( fread(buf, 4, 1, fp)!=1 ) return 0;
	if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
	fclose(fp);
	printf("Stage 4 clear!\n");	

	// network
	int sd, cd;
	struct sockaddr_in saddr, caddr;
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1){
		printf("socket error, tell admin\n");
		return 0;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons( atoi(argv['C']) );
	if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		printf("bind error, use another port\n");
    		return 1;
	}
	listen(sd, 1);
	int c = sizeof(struct sockaddr_in);
	cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
	if(cd < 0){
		printf("accept error, tell admin\n");
		return 0;
	}
	if( recv(cd, buf, 4, 0) != 4 ) return 0;
	if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
	printf("Stage 5 clear!\n");

	// here's your flag
	system("/bin/cat flag");	
	return 0;
}
```

<h1 style="font-family:quirell;"><font color="#9C7A97">Stage 1</font></h1>

For stage one, we must give the program 100 parameters where the parameters at location 'A' and 'B' are equal to the specific bytes value. This can be done simply with python lists.

```python
argv = [str(i) for i in range(0, 100)]

argv[65] = b'\x00'
argv[66] = b'\x20\x0a\x0d'
```

<h1 style="font-family:quirell;"><font color="#9C7A97">Stage 2</font></h1>

In this stage, the program calls the read() function 2 times and reads four bytes into the buf variable. The first read() reads from file descriptor 0, which is the standard input. The second read() reads from file descriptor 2 which is the standard error.

To tackle this, we will use a python library called pwntools. which is a grab-bag of tools to make exploitation during CTFs as painless as possible.

We will create a pipe, and write the data into it. Then, using pwntools we will create the process and point the stdin and stderr to the newly created pipes.

> Learn more about pwntools here [pwntools github](https://github.com/Gallopsled/pwntools-tutorial/tree/master)\
> Read more about [python pipes](https://www.tutorialspoint.com/python/os_pipe.htm)

```python
import os

argv = [str(i) for i in range(0, 100)]

argv[65] = b'\x00'
argv[66] = b'\x20\x0a\x0d'

r1, w1 = os.pipe()
r2, w2 = os.pipe()

os.write(w1, b'\x00\x0a\x00\xff')
os.write(w2, b'\x00\x0a\x02\xff')

io = process(executable = '/home/input2/input', argv = argv, stdin=r1, stderr=r2)
```

<h1 style="font-family:quirell;"><font color="#9C7A97">Stage 3</font></h1>

In this part we need to create an envirmonment variable with a specific value. Luckily enough, pwntools enables us to create proccess with custom environment variables.\
All we need to do, is to call pwntools's process fucntion with the env argument.
It should like this:
```python
io = process(executable = '/home/input2/input', argv = argv, stdin=r1, stderr=r2, env={"\xde\xad\xbe\xef":"\xca\xfe\xba\xbe"})
```

<h1 style="font-family:quirell;"><font color="#9C7A97">Stage 4</font></h1>

In this part, the program opens a file called "\x0a" for reading. Since we manually name our files by byte names, we will use python to do so.\
The user input2 does not have writing permissions in the home directory, thats why ew will create a folder under the /tmp/ directory. This will allow us to create the file and run our script there.

```bash
mkdir /tmp/rwxBeny
cd /tmp/rwxBeny
```

And this will be the code added to our python script:
```python
with open("\x0a", 'w') as f:
    f.write("\x00\x00\x00\x00")
```

<h1 style="font-family:quirell;"><font color="#9C7A97">Stage 5</font></h1>

For this stage the program binds a socket on localhost with the port specified in argv['C'].
We will use pwntools's remote() function to easily connect to localhost on the needed port.

```python
argv[67] = '4444'
s = remote('localhost', 4444)
s.sendline(b"\xde\xad\xbe\xef")

```

<h1 style="font-family:quirell;"><font color="#9C7A97">Full Solution</font></h1>

Now before creating the python file with our full solution in /tmp/rwxBeny/ , we need to create a symbolic link to the flag that is located in the home directory. That's because the binary tries to read the flag file in the local directory, and if we work under /tmp/ we need to get the file here.

```bash
ln -s ~/flag flag
```

Great! now all that's left is to create the complete python script.

```python
from pwn import *
import os

argv = [str(i) for i in range(0, 100)]

argv[65] = b'\x00'
argv[66] = b'\x20\x0a\x0d'
argv[67] = '4444'

r1, w1 = os.pipe()
r2, w2 = os.pipe()

os.write(w1, b'\x00\x0a\x00\xff')
os.write(w2, b'\x00\x0a\x02\xff')

with open("\x0a", 'w') as f:
    f.write("\x00\x00\x00\x00")

io = process(executable = '/home/input2/input', argv = argv, stdin=r1, stderr=r2, env={"\xde\xad\xbe\xef":"\xca\xfe\xba\xbe"})

s = remote('localhost', 4444)
s.sendline(b"\xde\xad\xbe\xef")

io.interactive()
```

```bash
input2@pwnable:/tmp/rwxBeny$ python sol.py
[+] Starting local process '/home/input2/input': pid 88861
[+] Opening connection to localhost on port 4444: Done
[*] Switching to interactive mode
Welcome to pwnable.kr
Let's see if you know how to give input to program
Just give me correct inputs then you will get the flag :)
Stage 1 clear!
Stage 2 clear!
Stage 3 clear!
Stage 4 clear!
Stage 5 clear!
Mommy! I learned how to pass various input in Linux :)
```
