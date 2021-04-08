---
layout: post
title: ångstrom CTF 2021 - Oracle of Blair [crypto]
author: jbo and lanjelot
tags: [ctf, ångstrom CTF, crypto]
---

 * Competition: [ångstrom CTF 2021](https://ctftime.org/event/1265)
 * Challenge Name: Oracle of Blair
 * Type: Crypto
 * Points: 160 pts
 * Description: 
 > Not to be confused with the ORACLE of Blair. nc crypto.2021.chall.actf.co 21112.
 > Author: lamchcl

AES-CBC decryption oracle where attacker can have the server include the flag at any position in the ciphertext.

<!--more-->

The challenge
==
We are given a very short piece of source code for the server:
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

key = os.urandom(32)
flag = open("flag","rb").read()

while 1:
	try:
		i = bytes.fromhex(input("give input: "))
		if not i:
			break
	except:
		break
	iv = os.urandom(16)
	inp = i.replace(b"{}", flag)
	if len(inp) % 16:
		inp = pad(inp, 16)
	print(
		AES.new(key, AES.MODE_CBC, iv=iv).decrypt(inp).hex()
	)
```

So, we can decrypt any arbitrary content.
Also, `{}` is replaced with the flag, so we can put the flag in the ciphertext in an arbitrary position.
However, decryption happens with a random IV every time.

AES-CBC decryption
==
Consider AES-CBC decryption scheme:

```
                c1         c2         c3                  cn
                |          |          |                   |
                +---+      +---+      +---+               |
                |   |      |   |      |   |               |
               AES  |     AES  |     AES       ...       AES
                |   |      |   |      |                   |
                |   |      |   |      |                   |
       IV ---- XOR  +---- XOR  +---- XOR       ...   --- XOR
                |          |          |                   |
                |          |          |                   |
                p1         p2         p3                  pn
```

If we mark `c0 = IV` then `p[n] = c[n-1] ^ AES(c[n])`.

Mitigating the random IV
==
If we set `c1` all zeros then `p2 = AES(c2)`.
This means we can ignore `p1` and reliably decrypt blocks (starting `c2`) to get consistent plaintext blocks (starting `p2`), just like in `AES-ECB`.

Concluding the flag length
==
Padding is added only when the input size is not a multiple of 16, so we can experiment:
1. When trying `7b7d` (encodes to `{}`) we get `32` bytes.
2. When trying `000000000000007b7d` we still get `32` bytes.
3. When trying `00000000000000007b7d` we still get `48` bytes.

This means `00000000000000` (`7` bytes) is exactly `32` bytes minus the `flag` length, so `flag` is `25` bytes!

Solution
==
At this point jbo tagged lanjelot in and after reading about his progress on our amazing-in-house-made-ctf-note-sharing app [ctfpad](https://github.com/hugsy/ctfpad/), the following solution was found.

If we send a zero-IV and the 17 bytes `b'\x00'*15 + b'{}'` then the server will decrypt `b'\x00'*15` plus the first byte of the flag for us, in `ECB` mode.
We receive the decrypted block `AES-ECB(b'\x00\x00...?')` where `?` is the first byte of the flag. We can guess that byte through bruteforce:
1. Send zero-IV and the 16 bytes `b'\x00'*15 + b'a'`
2. If decrypted block is equal to `AES-ECB(b'\x00\x00...?')` then `? == 'a'`
3. Otherwise, try another character

We can repeat the process to get the next character, revealing the flag one byte at a time.

The solver:
```python
from pwn import *
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

FLAG_FREQ = b'_etaonrishdlfcmugypwbvkjxqz{}ETAONRISHDLFCMUGYPWBVKJXQZ0123456789!?@#%&$-^"\'()*+,./:;<=>[\\]^`|~ '

def chunk(s, bs=16):
  return [s[i:i + bs] for i in range(0, len(s), bs)]

def solve():
    with context.local(log_level='INFO'):
        # uncomment to test remote srv
        # with remote('crypto.2021.chall.actf.co', 21112) as target:
        #     def server(ct):
        #         _ = target.recvuntil(b'give input: ')
        #         target.sendline(ct)
        #         return target.recvline().rstrip().decode()

            def submit(ct):
                print(ct, len(ct))
                ct_hex = ct.hex()
                pt_hex = server('00' * 16 + ct_hex) # prepend with a null IV
                pt = bytes.fromhex(pt_hex)
                return pt

            flag = b''
            zero = b'\x00' * 32 # we manually found out that flag is 25 chars
            while len(flag) < 25:
                off = len(flag) + 1
                ct = zero[:-off]

                pt = submit(ct + b'{}')
                actual = chunk(pt)[2]

                for c in FLAG_FREQ:
                    c = bytes((c,))
                    
                    guess = zero[:-off]
                    guess += flag + c

                    pt = submit(guess)
                    candidate = chunk(pt)[2]

                    if actual == candidate:
                        flag += c
                        print(flag)
                        break

def server(hi):
    if not hi:
        raise Exception('bad input')

    key = b'YELLOW SUBMARINEYELLOW SUBMARINE' #os.urandom(32)
    flag = b'actf{cbc_more_like_ecb_c}' # open("flag","rb").read().strip()
    assert len(key) == 32
    assert len(flag) == 25
    i = bytes.fromhex(hi)
    iv = os.urandom(16)
    inp = i.replace(b"{}", flag)
    if len(inp) % 16:
        inp = pad(inp, 16)
    return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(inp).hex()

if __name__ == '__main__':
    solve()
```

Output:
```
$ python solve_blair.py 
[+] Opening connection to crypto.2021.chall.actf.co on port 21112: Done
b'a'
b'ac'
b'act'
b'actf'
b'actf{'
b'actf{c'
b'actf{cb'
b'actf{cbc'
b'actf{cbc_'
b'actf{cbc_m'
b'actf{cbc_mo'
b'actf{cbc_mor'
b'actf{cbc_more'
b'actf{cbc_more_'
b'actf{cbc_more_l'
b'actf{cbc_more_li'
b'actf{cbc_more_lik'
b'actf{cbc_more_like'
b'actf{cbc_more_like_'
b'actf{cbc_more_like_e'
b'actf{cbc_more_like_ec'
b'actf{cbc_more_like_ecb'
b'actf{cbc_more_like_ecb_'
b'actf{cbc_more_like_ecb_c'
b'actf{cbc_more_like_ecb_c}'
[*] Closed connection to crypto.2021.chall.actf.co port 21112
```

Thanks for reading! :)

[@jbo](https://twitter.com/yo_yo_yo_jbo) & [@lanjelot](https://twitter.com/lanjelot)