---
layout: post
title: ångstrom CTF 2021 - I'm so random [crypto]
author: yo_yo_yo_jbo (0x3d5157636b525761)
tags: [crypto, ångstrom, I'm so random, PRNG]
---

 * Competition: [ångstrom CTF 2021](https://2021.angstromctf.com)
 * Challenge Name: I'm so random
 * Type: Crypto
 * Points: 100 pts

This challenge involves a very broken PRNG.

<!--more-->

PRNG source code
==
```python
import time
import random
import os

class Generator():
    DIGITS = 8
    def __init__(self, seed):
        self.seed = seed
        assert(len(str(self.seed)) == self.DIGITS)

    def getNum(self):
        self.seed = int(str(self.seed**2).rjust(self.DIGITS*2, "0")[self.DIGITS//2:self.DIGITS + self.DIGITS//2])
        return self.seed

r1 = Generator(random.randint(10000000, 99999999))
r2 = Generator(random.randint(10000000, 99999999))

query_counter = 0
while True:
    query = input("Would you like to get a random output [r], or guess the next random number [g]? ")
    if query.lower() not in ["r", "g"]:
        print("Invalid input.")
        break
    else:
        if query.lower() == "r" and query_counter < 3:
            print(r1.getNum() * r2.getNum())
            query_counter += 1;
        elif query_counter >= 3 and query.lower() == "r":
            print("You don't get more random numbers!")
        else:
            for i in range(2):
                guess = int(input("What is your guess to the next value generated? "))
                if guess != r1.getNum() * r2.getNum():
                    print("Incorrect!")
                    exit()
            with open("flag", "r") as f:
                fleg = f.read()
            print("Congrats! Here's your flag: ")
            print(fleg)
            exit()
```

PRNG analysis
==
1. The class `Generator` is the PRNG. It starts with a seed of 8 digits.
2. `getNum` changes the "seed" according to a deterministic algorithm and returns it.
3. Obviously we can bruteforce 8 digits worth of randomness.

Interaction anslysis
==
1. We initialize with two PRNGs.
2. You have `3` queries to get the next random output, but it'd be the multipication of both PRNGs "next" numbers.
3. You get *one* guess of the next multipication.

Solution
==
The first idea was to build a table and answer accordinly.
It looks like the table would be pretty big, so I decided to just think about factorization.
Since they give us the multipication of the PRNG values, we could make educated guesses.

I ended up factoring the number and hope I have very little factors.
On my 3rd attempt I got the number `4391105936381657` from the server.
Here is the factorization:
```
4391105936381657 = 17*83*684637*4545551
```

So there are only 4 factors!
The second number that I got was `216227383182400`, and experimenting with these I concluded two seed values: `77274367` and `56824871` (just by bruteforcing all possibilities).
From there getting the following numbers was just running their code.
The flag I got: `actf{middle_square_method_more_like_middle_fail_method}`.
