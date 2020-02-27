---
layout: post
title: CSAW QUALS 2016 - Neo [Crypto]
author: lanjelot
tags: [ctf, csaw, crypto]
---

 * Competition: CSAW QUALS CTF 2016
 * Challenge Name: Neo
 * Type: Crypto
 * Points: 200 pts
 * URL: http://crypto.chal.csaw.io:8001/

<!--more-->

**tl;dr: presenting a multithreaded [fork](https://github.com/lanjelot/cryptopal) of [python-paddingoracle](https://github.com/mwielgoszewski/python-paddingoracle) to speed up decryption**

Neo was a classic padding oracle challenge where we had to decrypt some ciphertext to get the flag. Since padding oracle challenges are recurrent in CTFs, I thought it would be great to add multithreading to the awesome [`python-paddingoracle`](https://github.com/mwielgoszewski/python-paddingoracle) project to decrypt each block in parallel.

The Neo challenge presented us with a website that simply consisted of a single form with the POST parameter matrix-id storing some base64-encoded binary blob (80 bytes in total).

![alt](https://i.imgur.com/rQ1LTEV.png)

Let's byte-flip that blob to see if we can detect any discrepancies in the server responses:

```python
from cryptopal import byteflip # https://github.com/lanjelot/cryptopal
from hashlib import md5
import requests

blob = 'JaaEqilpk1W1ZDErYGkUeZQmxwVGQYHHYnfv+G/S+p5FNCyETblM2hWeq5I5r+7QpUv/iuXVlqEwjKvefmMi9ZuCxWEHsFB5kgKwof4y1ZE='.decode('base64')

def flipit():
    def submit(s):
        return requests.post('http://crypto.chal.csaw.io:8001/', proxies={'http': 'http://127.0.0.1:8082'}, data={'matrix-id': s.encode('base64').strip()})

    for i, r in byteflip(blob, submit):
        print '%03d %d %d %s' % (i, r.status_code, len(r.text), md5(r.text).hexdigest())
```

We observe a `Caught exception during AES decryption...` error message in the html response from the 48th byte to the last 80th byte, so we indeed have a CBC padding oracle with blocksize=16:

```
000 200 3833 25fef633e4bcd7c2ada6f7210d132e1d
001 200 3833 25fef633e4bcd7c2ada6f7210d132e1d
...
048 200 3833 25fef633e4bcd7c2ada6f7210d132e1d
049 200 4061 56a6fbca3d2ac12a1bb0487f48044d9e
050 200 4061 3b160cfcc9eaa63449de5a093a7c8865
...
079 200 4061 0b39a68b6c43fc825147df37492963f5
```

Let's now recover the plaintext and use one thread per block to speed up the decryption process:

```python
from cryptopal import PaddingOracle, PaddingException # https://github.com/lanjelot/cryptopal

class PadBuster(PaddingOracle):
    def __init__(self):
        PaddingOracle.__init__(self)
        self.session = requests.Session()

    def oracle(self, data):
        r = self.session.post('http://crypto.chal.csaw.io:8001/', data={'matrix-id': data.encode('base64').strip()})

        print '%s %d %d %d' % (data.encode('hex'), r.status_code, len(str(r.headers)), len(r.text))

        if 'Caught exception during AES decryption' in r.text:
            raise PaddingException
        else:
            return

def decrypt():
    padbuster = PadBuster()
    print 'Decrypted: %r' % padbuster.decrypt(blob, block_size=16)
```

Yay we get the flag:

```
Decrypted: 'flag{what_if_i_told_you_you_solved_the_challenge}\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
```

Thanks CSAW for delivering a great CTF (as usual). This time [TheGoonies](https://ctftime.org/team/10288) ranked 28th! :)

![stocked](https://media.giphy.com/media/FYqf889lXd9Ru/giphy.gif)


