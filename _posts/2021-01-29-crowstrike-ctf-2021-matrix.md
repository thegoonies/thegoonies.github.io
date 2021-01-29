---
layout: post
title: CrowdStrike CTF 2021 - Matrix [crypto]
author: yo_yo_yo_jbo (0x3d5157636b525761)
tags: [ctf, crowdstrike, crypto]
---

 * Competition: [Crowdstrike CTF](https://adversary.zone/challenges)
 * Challenge Name: Module wow
 * Type: Crypto, reversing
 * Points: 1 pts
 * Description:
 > With the help of your analysis, we got onto the trail of the group and found their hidden forum on the Deep Dark Web. Unfortunately, all messages are encrypted. While we believe that we have found their encryption tool, we are unsure how to decrypt these messages. Can you assist?

Let's examine the cipher with a black-box approach. Here are some facts:
* The key is composed of 9 bytes.
* The cipher is a block cipher, of block size 3 (`function B` takes key+3 characters and outputs the result as 3 bytes).
* First 9 bytes of a plaintext are always `SPACEARMY`.
* `Function C` is used for encryption and decryption, but the key is either `K` for decryption or `U(K)` for encryption.

<!--more-->

Because `function C` is used for both encryption and decryption but with different key, we conclude that `function U` gets a key and calculates an "anti-key".
The anti-key must adhere to: `C(K, C(U(K), M)) = M`.
This means `function U` is the inverse function of itself: `U(U(K)) = K`.
We can validate this by coming up with a key and debug.

Now, let's take one message (from the flagz) and reverse the bytes that are the result of `U`.
I took `259F8D014A44C2BE8FC50A5A2C1EF0C13D7F2E0E70009CCCB4C2ED84137DB4C2EDE078807E1616C266D5A15DC6DDB60E4B7337E851E739A61EED83D2E06D618411DF61222EED83D2E06D612C8EB5294BCD4954E0855F4D71D0F06D05EE`.

Let's say that the 9 bytes that are the result of `U(K)` are `U1,U2,...,U9`.
Then, following `function C` and using our knowledge of the `SPACEARMY` prefix, we get the following:

```
U1*ord('S')+U2*ord('P')+U3*ord('A') = 0x25
U4*ord('S')+U5*ord('P')+U6*ord('A') = 0x9F
U7*ord('S')+U8*ord('P')+U9*ord('A') = 0x8D
U1*ord('C')+U2*ord('E')+U3*ord('A') = 0x01
U4*ord('C')+U5*ord('E')+U6*ord('A') = 0x4A
U7*ord('C')+U8*ord('E')+U9*ord('A') = 0x44
U1*ord('R')+U2*ord('M')+U3*ord('Y') = 0xC2
U4*ord('R')+U5*ord('M')+U6*ord('Y') = 0xBE
U7*ord('R')+U8*ord('M')+U9*ord('Y') = 0x8F
```

There are 9 unknowns and 9 linear equations, they can be solved (with a Matrix).
Do not forget we are working in `GF(256)` (since everything here is `mod 256`).
The solution gives us:

```
U1 = 0xCF
U2 = 0x1C
U3 = 0x48
U4 = 0x4C
U5 = 0xDF
U6 = 0x8B
U7 = 0x6D
U8 = 0x0B
U9 = 0x46
```

Now, remember `U(U(K)) = K`. Therefore, running the `U function` on these `U bytes` results in the key!
```python
u_bytes = bytes.fromhex('cf1c484cdf8b6d0b46')
k_bytes = U(u_bytes)
key = ''.join(map(chr, k_bytes))
print(key)
```

The key is `SP4evaCES`.
Solving now is easy, we only have to decrypt the flag bytes with the key:

```python
key = bytes('SP4evaCES', 'ascii')
msg='259F8D014A44C2BE8FC50A5A2C1EF0C13D7F2E0E70009CCCB4C2ED84137DB4C2EDE078807E1616C266D5A15DC6DDB60E4B7337E851E739A61EED83D2E06D618411DF61222EED83D2E06D612C8EB5294BCD4954E0855F4D71D0F06D05EE'
flagz=C(key, bytes.fromhex(msg))
print(flagz.decode('ascii'))
```

We get the result `CS{if_computers_could_think_would_they_like_spaces?}`.
