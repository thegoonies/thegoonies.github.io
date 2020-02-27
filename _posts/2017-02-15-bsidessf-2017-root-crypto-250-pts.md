---
layout: post
title: BsidesSF 2017 - []root (crypto, 250 pts)
author: jeremy
tags: [ctf, bsidessf, crypto]
---

 * Competition: https://scoreboard.ctf.bsidessf.com/
 * Challenge Name: []root
 * Type: Crypto
 * Points: 250 pts
 * URL: https://scoreboard.ctf.bsidessf.com/attachment/fd74c568c3bfd6e5fb4f07c03db322f0ace8fd0e68ff4d2c106f1518e2109231

<!--more-->

> Our guy inside e-corp was able to get that packet capture of their backend PKI you asked for. Unfortunately it seems they're using TLS to protect the modulus fetch. Now, I have been told that the best crackers in the world can do this in 60 minutes. Unfortunately I need someone who can do it in 60 seconds.
>
> Note: Flag does not follow the "Flag:" format but is recognizable
>
> [ecorppki.pcapng](https://scoreboard.ctf.bsidessf.com/attachment/fd74c568c3bfd6e5fb4f07c03db322f0ace8fd0e68ff4d2c106f1518e2109231)


We are provided with a packet capture file containing a TLS exchange. Loading it up in Wireshark, we can quickly identify a TLS handshake, with a "server hello" message containing the server certificate, itself containing the RSA public key (modulus + public exponent):

![](https://i.imgur.com/qUVa28T.png)

We need to recover the private key by factoring the modulus. We used [Fermat's factorisation method](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method) to recover the two prime factors with the script below:

```python
import gmpy2

def fermat_factors(n):
    assert n % 2 != 0

    a = gmpy2.isqrt(n)
    b2 = gmpy2.square(a) - n

    while not gmpy2.is_square(b2):
        a += 1
        b2 = gmpy2.square(a) - n

    factor1 = a + gmpy2.isqrt(b2)
    factor2 = a - gmpy2.isqrt(b2)
    return int(factor1), int(factor2)

e = 31337
n = """
726f6f740000000000000000000000
0000000000001b0000000000000000
00000000001ffffb00000000000000
00000000001ffffb00000000000000
00000000001fffff7777777b000000
00000000001ffffffffffffb000000
00000000001ffffffffffb00000000
00000000001ffffffffffb00000000
00000000001ffffffffffffb000000
00000000001fffff2222222b000000
00000000001ffffb00000000000000
00000000001ffffb00000000000000
00000000001ffffb00000000000000
00000000001ffffb00000000000000
00000000001ffffb00000000000000
00000000001ffffb00000000000000
00000000001ffffb00000000000000
265293c4422be3532638feeb2a635e
865e5bccd4862d1491f8e46ed41afd
ab32ab1e913c296c45a723a371cc4a
d218d273a494ac501a1c677576b84d
3a1700b24e38f3d7c8090c952767f8
a9da532eb4496a953fa2b2641f93af
58321e491ad6b3e1f6600ea1757635
a2d47562dff2f245bfc8ed51142093
1de246d56334d8897d6465b227f6c0
95ece1ad994c7551f08dbc21f8b406
91ee51f5f72d052d9352062f90b0e7
c52c2eb18196c2c985101af4eac674
99396c6241ad4f2439ed11f87d67e7
3a239b865c45d65a61cf0f56082de8
31b97fb28ae8222a7195e0ec06c082
81ffc16e7106e77e68b8c4510424be
eb5582fe21cc345f53534682b75c36
8d73c9""".replace('\n', '')

p, q = fermat_factors(int(n, 16))
print "p =", p
print "q =", q
```

This quickly yielded values for p and q. Plugging those values into [rsatool](https://github.com/ius/rsatool), we were able to reconstruct the server's private key:

```bash
$ python ./rsatool.py -p 345709341936068338730678003778405323582109317075021198605451259081268526297654818935837545259489748700537817158904946124698593212156185601832821337576558516676594811692389205842412600462658083813048872307642872332289082295535733483056820073388473845450507806559178316793666044371642249466611007764799781626418800031166072773475575269610775901034485376573476373962417949231752698909821646794161147858557311852386822684705642251949742285300552861190676326816587042282505137369676427345123087656274137257931639760324708350318503061363031086796994100943084772281097123781070811610760735943618425858558459014484742232019973 -q 345709341936068338730678003778405323582109317075021198605451259081268526297654818935837545259489748700537817158904946124698593212156185601832821337576558516676594811692389205842412600462658083813048872307642872332289082295535733483056820073388473845450507806559178316793666044371642249466611007764799781626418800031166072773475575269610775901034485376573476373962417949231752698909821646794161147858557311852386822684705642251949742285300552861190676326816587042282505137369676427345123087656274137257931639760324708350318503061363031086796994100943084772281097123781070811610760735943618425858558459014484742232018933 -e 31337 -o priv.key
[...]
Saving PEM as priv.key
```

The next step was to load this private key back into Wireshark to see decrypted TLS traffic. We could see a GET /modulus HTTP request with some form of ASCII art:



Nice ASCII art key we thought... But then we looked closely to the first non-zero bytes towards the end: 66 6c 61 67. This looks like ASCII for "flag"! And indeed:

```
>>> '66:6c:61:67:3a:77:68:65:6e:5f:73:6f:6c:76:69:6e:67:5f:70:72:6f:62:6c:65:6d:73:5f:64:69:67:5f:61:74:5f:74:68:65:5f:72:6f:6f:74:73:5f:69:6e:73:74:65:61:64:5f:6f:66:5f:6a:75:73:74:5f:68:61:63:6b:69:6e:67:5f:61:74:5f:74:68:65:5f:6c:65:61:76:65:73'.replace(':','').decode('hex')
'flag:when_solving_problems_dig_at_the_roots_instead_of_just_hacking_at_the_leaves
```
