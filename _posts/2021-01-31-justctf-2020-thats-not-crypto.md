---
layout: post
title: justCTF 2020 - That's not crypto [crypto]
author: yo_yo_yo_jbo (0x3d5157636b525761)
tags: [ctf, justCTF, crypto]
---

 * Competition: [justCTF 2020](http://2020.justctf.team)
 * Challenge Name: That's not crypto
 * Type: Crypto
 * Points: 210 pts
 * Description: 
 > This is very simple RE task, but you may need some other skills as well.

Downloaded `checker.pyc`. Decided to use [https://pypi.org/project/uncompyle6](uncompyle6) for decompilation.

The file consists of the following logic:
* A variable name `a` which is a list of big numbers. It's interpreted as polynomial coefficients.
* Given a flag from the user, it calls function `make_correct_array` which derives an array from the given string.
* Calls `validate(a, flag)`.

<!--more-->

The file itself looks like this:
```python
def make_correct_array(s):
    from itertools import accumulate
    s = map(ord, s)
    s = accumulate(s)
    return [x * 69684751861829721459380039L for x in s]

def validate(a, xs):

    def poly(a, x):
        value = 0
        for ai in a:
            value *= x
            value += ai

        return value

    if len(a) != len(xs) + 1:
        return False
    else:
        for x in xs:
            value = poly(a, x)
            if value != 24196561:
                return False

        return True
		

if __name__ == '__main__':
    a = [1,
     -12036995612853156936286011036665L,
	 ... # truncated for brevity
	]
    a = [ai * 4919 for ai in a]
    flag_str = input('flag: ').strip()
    flag = make_correct_array(flag_str)
    if validate(a, flag):
        print('Yes, this is the flag!')
        print(flag_str)
    else:
        print('Incorrect, sorry. :(')
```

The `validate` function is the most important:
* It gets the array `a` and the flag array `xs`.
* The polynomial with coefficients `a` and point `x` from `xs` must ALWAYS be equal to `24196561`.

Therefore, we can reverse the polynomial easily.
For example, for the first byte we only need:
```python
 [ i for i in range(256) if poly(a, 69684751861829721459380039*i) == 24196561 ]
```
This gives us `106='j'` which corresponds to the flag header in `'justCTF{'`.

Since I'm just lazy, I "bruteforced" the polynomial, note that we only have to check the last element as we add more and more bytes:
```python=
import string
password = 'justCTF{'
while len(password) + 1 != len(a):
	for i in string.printable:
		tmp = password + i
		tmp_s = make_correct_array(tmp)
		value = poly(a, tmp_s[-1])
		if value != 24196561:
			continue
		password = tmp
print(password)
```

Got the result in less than a second: `justCTF{this_is_very_simple_flag_afer_so_big_polynomails}`
