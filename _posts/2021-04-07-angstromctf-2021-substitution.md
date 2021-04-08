---
layout: post
title: ångstrom CTF 2021 - substitution [crypto]
author: yo_yo_yo_jbo (0x3d5157636b525761)
tags: [crypto, ångstrom, substitution]
---

 * Competition: [ångstrom CTF 2021](https://2021.angstromctf.com)
 * Challenge Name: substitution
 * Type: Crypto
 * Points: 130 pts


This challenge involves solving analyzing polynomials over a Galois field.

<!--more-->

Source
==
We get the source:

```python
#!/usr/bin/python

from functools import reduce

with open("flag", "r") as f:
    key = [ord(x) for x in f.read().strip()]

def substitute(value):
    return (reduce(lambda x, y: x*value+y, key))%691

print("Enter a number and it will be returned with our super secret synthetic substitution technique")
while True:
    try:
        value = input("> ")
        if value == 'quit':
            quit()
        value = int(value)
        enc = substitute(value)
        print(">> ", end="")
        print(enc)
    except ValueError:
        print("Invalid input. ")
```

Analysis
==
We note that each `substitute` value forces a linear equation over `GF(691)`, as such:
```
v[0] = k[0] + 0**1 * k[1] + 0**2 * k[2] + ... + 0**689 * k[689] + 0**690 * k[690] (mod 690)
v[1] = k[0] + 1**1 * k[1] + 1**2 * k[2] + ... + 1**689 * k[689] + 1**690 * k[690] (mod 690)
v[2] = k[0] + 2**1 * k[1] + 2**2 * k[2] + ... + 2**689 * k[689] + 2**690 * k[690] (mod 690)
...
v[689] = k[0] + 689**1 * k[1] + 689**2 * k[2] + ... + 689**689 * k[689] + 689**690 * k[690] (mod 690)
v[690] = k[0] + 690**1 * k[1] + 690**2 * k[2] + ... + 690**689 * k[689] + 690**690 * k[690] (mod 690)
```

Note that we can think of the `key` to have `691` values (`k elements here`) - if it has less then the elements would zero-out.

So, we can put everything in a matrix and solve.
We will have a matrix `A` of size `691x691`:
```
    1         0         0    ...           0           0
    1      1**1      1**2    ...      1**689      1**690
    1      2**1      2**2    ...      2**689      2**690
    ...
    1    689**1    689**2    ...    689**689    689**690
    1    690**1    690**2    ...    690**689    690**690
```

And the vector `B` (size = `1x691`) will contain the values.

Solution code
==
I ended up using `pyfinite` which s quite good for solving linear equations over finite fields, and I extracted all the `substitute` values into an array called `values`.
Then:

```python
from pyfinite import genericmatrix

# Implement modinv in case we have Python < 3.8
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

# Build GF(691) operations
add = lambda x, y: (x+y) % 691
sub = lambda x, y: (x-y) % 691
mul = lambda x, y: (x*y) % 691
div = lambda x, y: mul(x, modinv(y, 691))

# Build matrix
A = genericmatrix.GenericMatrix(size=(691, 691), zeroElement=0, identityElement=1, add=add, mul=mul, sub=sub, div=div)
for i in range(len(values)):
    A.SetRow(i, [ pow(i, k) % 691 for k in range(691) ][::-1])

# Build vector
B = genericmatrix.GenericMatrix(size=(691, 1), zeroElement=0, identityElement=1, add=add, mul=mul, sub=sub, div=div)
for i in range(len(values)):
    B.SetRow(i, [ values[i] ])

# Solve linear equation
sol = (A.Inverse()) * B

# Print solution - and get rid of zeros
print(''.join([ chr(i[0]) for i in sol.data ]).replace('\x00', ''))
```

Solution: `actf{polynomials_20a829322766642530cf69}`.
