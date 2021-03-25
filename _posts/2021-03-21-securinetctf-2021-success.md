---
layout: post
title: Securinets CTF Quals 2021 - success [pwn]
author: rick2600
tags: [pwn, float, FILE]
date: 2021-03-21 19:38
---

 * Competition: [Securinets CTF Quals 2021](https://www.ctfsecurinets.com/challenges)
 * Challenge Name: success
 * Type: pwn
 * Points: 1000 pts
 * Description: 
 > You have to study hard!
 >

<!--more-->

## Recon

```
./main2_success: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=8aaf072e69365d277b4bfae074c4f22861b0ca2f, not stripped


Canary                        : ✓ (value: 0xbb81c0ff83189f00)
NX                            : ✓ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : Full
```

## Overview
1. It reads student username (name can't be lowercase).
2. It reads the number of subjects.
3. It loops until n_subjects and reads some float numbers.

## Bugs
1. When reading an invalid student username we can leak memory.
2. There's an off-by-one in the array used to store the floats. We can corrupt the lower part of a FILE pointer.

## Leaking addresses
* Sending: "a" * 8 -> leak binary address.
* sending: "a" * 16 -> leak libc address.

## Exploit
1. Create a fake FILE object using the same technique described here: https://krrr-1.tistory.com/124 to bypass libc validations.
2. Overwrite the lower 32bits part of FILE pointer stored at &numbers2 to make it to point to the fake FILE stored at &ch.

The values must be passed as float so you need to proper convert it before sending.

Full exploit [here](https://gist.github.com/rick2600/47369cb0e5f66b2c5e12671d3e727a0a).

![solve-securinetctf-2021-success](https://user-images.githubusercontent.com/2582199/111923363-87dec200-8a7d-11eb-95ea-78dd22004f0f.png)
