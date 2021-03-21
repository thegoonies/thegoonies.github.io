---
layout: post
title: Securinet CTF Quals 2021 - MiTM [crypto]
author: yo_yo_yo_jbo (0x3d5157636b525761)
tags: [crypto, Securinet CTF, MiTM]
---

 * Competition: [Securinet CTF Quals 2021](https://www.ctfsecurinets.com/challenges)
 * Challenge Name: MiTM
 * Type: Crypto
 * Points: 559 pts
 * Description: 
 > You managed to get in the middle and control the entire discussion between Alice, Bob and Carol. What are they saying ?

The file `app.py` contains an implementation of Diffie-Hellman (`DHx` class), with fingerprinting too.
Assuming `Alice`, `Bob` and `Carol` have private keys `a`, `b` and `c` respectively, the following desrbies the key-exchange scheme:
1. `Alice` sends `g^a (mod p)` to `Bob`.
2. `Bob` raises by `b`, generating `g^ab (mod p)` and sends that to `Carol`.
3. `Carol` receives, raises by `c` and keeps that as the secret: `g^abc (mod p)`.

If we denote this chain as `A --> B --> C` then similar chains happen to get everyone synced to the same secret:
1. `A --> B --> C` (which we just described)
2. `B --> C --> A`
3. `C --> A --> B`

<!--more-->

As the name suggests, the attacker is a MiTM (man-in-the-middle) and can interfere with all comms, but there is a catch: after all of the exchanges, everyone compares their secrets (as fingerprinting), and `Alice` will only send the encrypted flag if this check passes.
This is kind of equivalent to the QR code option inside WhatsApp to ensure key exchange hasn't been tampered.

So, as an attacker, I didn't find any way to break the d-log problem, but I do note that the key exchange has a weekness, as the receiving party still trusts the sending party to follow the "correct" key exchange schema.
For example, if as an attacker I send to `Carol` some number `x` instead of `g^ab (mod p)`, then `Carol` blindly trusts it and calculates the secret `x^c (mod p)`. There is a limitation, however, as the code checks that the input is stricly larger than 1 and strictly smaller than `p`.

Therefore, I have decided to supply `x = -1 = p-1 (mod p)`. Note that raising `-1` to any power results in either `1` or `-1` (which is again, `p-1`). So, supplying `Carol`, for instacne, with `p-1` results in her saving the joint key as either `1` or `p-1`, randomly.
This needs to be done to each party, and each of them "randomly" generates either `1` or `p-1`.
What are the chances of all parties to agree on a key? Well, there are `2^3=8` possibilities and only in `2` of them there is an agreement, so the chances are `2/8 = 25%`, which are pretty good odds.

After a successful run, we only need to guess the shared secret out of 2 possibilities (`1` or `p-1`), which is easy to do.

The solution will therefore attempt until successful, and will normally succeed after 4 attempts.
The AES decryption is straightforward, and the flag that I got is: `Securinets{monkey-in-the-middle_efa8cf7dad56f238cc1ff49473da3ae3}`

The solution is therefore:
```python
from pwn import *

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes

p = 0xf18d09115c60ea0e71137b1b35810d0c774f98faae5abcfa98d2e2924715278da4f2738fc5e3d077546373484585288f0637796f52b7584f9158e0f86557b320fe71558251c852e0992eb42028b9117adffa461d25c8ce5b949957abd2a217a011e2986f93e1aadb8c31e8fa787d2710683676f8be5eca76b1badba33f601f45

minus_one = p-1

output = ''
while True:

    print('Starting attempt...')
    conn = remote('crypto1.q21.ctfsecurinets.com', 1337)

    for i in range(3):
        conn.recvline()
        conn.recvuntil(': ')
        conn.sendline(str(minus_one))
        conn.recvline()
        conn.recvuntil(': ')
        conn.sendline(str(minus_one))

    conn.recvline().decode('ascii') # "Alice says"
    output = conn.recvline().decode('ascii')
    if 'ABORT MISSION' in output:
        print('Attempt failed, rerying...')
        continue
    print('Success %s' % (output,))
    break

crypt_bytes = bytes.fromhex(output.strip())
iv = crypt_bytes[:16]
encrypted = crypt_bytes[16:]

# Try key=p-1
key = hashlib.sha1(long_to_bytes(minus_one)).digest()[:16]
print(AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted))

# Try key=1
key = hashlib.sha1(long_to_bytes(1)).digest()[:16]
print(AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted))
```
