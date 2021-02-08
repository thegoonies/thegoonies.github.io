---
layout: post
title: DiceCTF 2021 - Dice is you [rev]
author: @danilonc
tags: [ctf, DiceCTF, rev, wasm, z3]
---

 * Competition: [DiceCTF 2021](https://ctftime.org/event/1236)
 * Challenge Name: Dice is you
 * Type: Reversing
 * Points: 251 pts
 * Description: 
> DICE IS YOU
>
> Controls:
>
> wasd/arrows: movement space: advance a tick without moving q: quit to main menu r: restart current level z: undo a move (only works for past 256 moves and super buggy) Play: dice-is-you.dicec.tf


This challenge is a game inspired by the game `Baba is you`, which is a puzzle game where the player can change "the rules" by interacting with the blocks on the game. 
The `Dice is you` challenge was implemented using HTML + Javascript + WebAssembly (C language game logic + SDL).

## Level 1-4

Levels 1-4 can be easily solved by playing the game, [Youtube Link](http://www.youtube.com/watch?v=Ltl-owf8k1E).
Alternatively, the levels can be skipped by setting the cookie `unlocked` to `5`
![Cookie ](https://i.imgur.com/C7k4Vvc.png)


## Level 5

The level 5 is where the reversing challenge really begins.
The game shows a 5x5 matrix where it appears that the objective is to put the 40 elements in the correct order.

![Dice is you Level 5](https://i.imgur.com/IYiQfKQ.png)

Time to dig into the WebAssembly reversing part.
I decompiled the wasm binary file to rust using the [rewasm tools](https://github.com/benediktwerner/rewasm), the decompiled output was huge (~80M)
 
```console
➜  dice-is-for-you ls -lh app.wasm app.dec.rs                       
-rw-r--r-- 1 user user  79M Feb  6 10:10 app.dec.rs
-rw-r--r-- 1 user user 806K Feb  5 06:32 app.wasm
```

It is important to notice that the [wasm2c from wabt](https://github.com/WebAssembly/wabt/tree/master/wasm2c) was also used to decompile the wasm to c instead of rust. But in the end, I used the rust decompiled version more than the C version.

In total, there were 1118 functions including functions from c stdlib (e.g. memcpy), libsdl and others.

```console
➜  dice-is-for-you rg '^fn.*\(' app.dec.rs | wc -l 
1118
```

### Decompiled code

#### _check_code function

```rust
// Function 306
// Comments added by @danilonc
fn _check_code(i32 arg_0, i32 arg_1, i32 arg_2, i32 arg_3) -> i32 {

    //code chunk removed ...

                        // var_55 contains the result of _code with the 5 bytes argument
                        var_55 = _code(var_50, var_51, var_52, var_53, var_54);
                        store_8<i32>(var_4 + 6, var_55)
                        var_56 = load_8u<i32>(var_4 + 6);

                        // if _code function returned a value different than zero
                        if var_56 & 255 {
                            var_57 = global_0 - 32;
                            var_58 = 0 & 1;
                            // stores 0 at [[global_0 - 32] + 31]
                            store_8<i32>(var_57 + 31, var_58)
                        }

                        // if _code function returned a 0
                        else {
                            var_59 = global_0 - 32;
                            var_60 = load<i32>(var_59 + 16);
                            var_61 = load<i32>(var_60);
                            store_8<i32>(var_61 + 45, 1)
                            var_62 = global_0 - 32;
                            var_63 = load<i32>(var_62 + 16);
                            var_64 = load<i32>(var_63 + 4);
                            store_8<i32>(var_64 + 45, 1)
                            var_65 = global_0 - 32;
                            var_66 = load<i32>(var_65 + 16);
                            var_67 = load<i32>(var_66 + 8);
                            store_8<i32>(var_67 + 45, 1)
                            var_68 = global_0 - 32;
                            var_69 = load<i32>(var_68 + 16);
                            var_70 = load<i32>(var_69 + 12);
                            store_8<i32>(var_70 + 45, 1)
                            var_71 = global_0 - 32;
                            var_72 = load<i32>(var_71 + 16);
                            var_73 = load<i32>(var_72 + 16);
                            store_8<i32>(var_73 + 45, 1)
                            var_74 = global_0 - 32;
                            var_75 = 1 & 1;

                            // stores 1 at [[global_0 - 32] + 31]
                            store_8<i32>(var_74 + 31, var_75)
                        }

    //code chunk removed ...

    var_79 = load_8u<i32>(var_78 + 31);
    var_80 = global_0 - 32 + 32;
    if var_80 <u global_2 {
        __handle_stack_overflow();
    }
    global_0 = var_80;

    // returns 1 if it is a valid code, or 0 if not
    return var_79 & 1;
}
```

#### _code function

the _code function is responsible for calculating an expression based on the 5 provided byte arguments, returning a byte as the result.  

```rust
// Function 308
// Comments added by @danilonc
fn _code(i32 arg_0, i32 arg_1, i32 arg_2, i32 arg_3, i32 arg_4) -> i32 {
    i32 var_5;
    i32 var_6;
    i32 var_7;
    i32 var_8;
    i32 var_9;
    i32 var_10;
    i32 var_11;
    i32 var_12;
    i32 var_13;
    i32 var_14;
    i32 var_15;
    i32 var_16;
    i32 var_17;
    i32 var_18;
    i32 var_19;
    i32 var_20;
    i32 var_21;
    i32 var_22;
    i32 var_23;
    i32 var_24;
    i32 var_25;
    i32 var_26;
    i32 var_27;
    i32 var_28;
    i32 var_29;
    
    var_5 = global_0 - 16;
    store_8<i32>(var_5 + 15, arg_0)
    var_6 = global_0 - 16;
    store_8<i32>(var_6 + 14, arg_1)
    var_7 = global_0 - 16;
    store_8<i32>(var_7 + 13, arg_2)
    var_8 = global_0 - 16;
    store_8<i32>(var_8 + 12, arg_3)
    var_9 = global_0 - 16;
    store_8<i32>(var_9 + 11, arg_4)
    var_10 = global_0 - 16;
    var_11 = load_8u<i32>(var_10 + 15);
    // var11 contains the value of arg_0, this value is multiplied by 42
    var_12 = (var_11 & 255) * 42;
    var_13 = global_0 - 16;
    var_14 = load_8u<i32>(var_13 + 14);
    //var_14 contains the value of arg_1, this value is multiplied by 1337
    var_15 = (var_14 & 255) * 1337;
    var_16 = global_0 - 16;
    var_17 = load_8u<i32>(var_16 + 13);
    var_18 = var_17 & 255;
    // var_19 = (arg_0 * 42) + (arg_1 * 1337) + arg_2
    var_19 = var_12 + var_15 + var_18;
    var_20 = global_0 - 16;
    // var_21 = arg_2
    var_21 = load_8u<i32>(var_20 + 13);
    var_22 = global_0 - 16;
    var_23 = load_8u<i32>(var_22 + 12);
    // var_24 = arg_3
    var_24 = var_23 & 255;
    // var_25 = arg_2 ^ arg_3
    var_25 = var_21 & 255 ^ var_24;
    var_26 = global_0 - 16;
    var_27 = load_8u<i32>(var_26 + 11);
    // var_27 = arg_4
    // var_28 = arg_4 << 1
    var_28 = (var_27 & 255) << 1;

    // ((arg_0 * 42) + (arg_1 * 1337) + arg_2)  + (arg_2 ^ arg_3) + (arg_4 << 1) mod 256
    var_29 = var_19 + var_25 + var_28;
    return var_29 & 255;
}
```

Python equivalent:
```python
def code(n1,n2,n3,n4,n5):
    var19 = ((n1 * 42) + (n2 * 1337) + n3) 
    var25 = n3 ^ n4
    var28 = n5 << 1
    
    return (var19+var25+var28) & 255
```

## Getting the element block values

At that point I had an idea from what to expect from the challenge and I wanted to check what byte value those weird symbols had.
This can be done by setting a break-point at the `_code` function and inspecting the var0..var4 using the Watch expression functionality of Firefox.
![](https://i.imgur.com/u53ij9B.png)

A similar approach was used to create the Symbol Byte Value mapping table below.

### Symbol Mapping table

| Hex Value      | Image                                |
| -------------- | ------------------------------------ |
| d4 c2 bd 78 37 | ![](https://i.imgur.com/JcXtKaM.png) |
| ab a0 c2 d4 bd | ![](https://i.imgur.com/GFUEvox.png) |
| 3d b3 60 b7 37 | ![](https://i.imgur.com/mrTuern.png) |
| 01 12 19 8a 31 | ![](https://i.imgur.com/16AS6H7.png) |
| 05 b7 96 a3 ab | ![](https://i.imgur.com/ytJH3IM.png) |
| f7 a0 b3 94 77 | ![](https://i.imgur.com/hj7e5Ps.png) |
| 8a 31 60 3d 87 | ![](https://i.imgur.com/fiqVIuF.png) |
| 78 37 01 12 19 | ![](https://i.imgur.com/p5b0Ly7.png) |
| 30 78 37 01 12 | ![](https://i.imgur.com/0RMm3UK.png) |
| c0 8a 31 60 3d | ![](https://i.imgur.com/LXMOPkD.png) | 


## Finding the correct order

### First try

My first approach was to brute-force all possible combinations to check if there was only one correct answer with the following code:

```python
def code(n1,n2,n3,n4,n5):
    var19 = ((n1 * 42) + (n2 * 1337) + n3) 
    var25 = n3 ^ n4
    var28 = n5 << 1
    
    return (var19+var25+var28) & 255

def solve(name, n1, n2, n3, n4, n5):
    if code(n1,n2,n3,n4,n5) == 0:
        print(f"{name} n1={hex(n1)} n2={hex(n2)} n3={hex(n3)} n4={hex(n4)}, n5={hex(n5)}")

nums = [0x78, 0x37, 0x01, 0x12, 0x19,
        0x8a, 0x31, 0x60, 0x3d, 0x87,
        0xf7, 0xa0, 0xb3, 0x94, 0x77,
        0x05, 0xb7, 0x96, 0xa3, 0xab]

#row1
for n4 in nums:
    for n5 in nums:
        n1 = 0xd4
        n2 = 0xc2
        n3 = 0xbd
        solve("row1",n1,n2,n3,n4,n5)

#row2
for n2 in nums:
    for n3 in nums:
        for n4 in nums:
            for n5 in nums:
                n1 = 0x30
                solve("row2",n1,n2,n3,n4,n5)

#row3
for n2 in nums:
    for n3 in nums:
        for n4 in nums:
            for n5 in nums:
                n1 = 0xc0
                solve("row3",n1,n2,n3,n4,n5)

#row4
for n2 in nums:
    for n3 in nums:
        for n4 in nums:
            for n5 in nums:
                n1 = 0x60
                solve("row4",n1,n2,n3,n4,n5)
#row5
for n2 in nums:
    for n3 in nums:
        for n4 in nums:
            for n5 in nums:
                n1 = 0x94
                solve("row5",n1,n2,n3,n4,n5)

#col1
for n4 in nums:
    for n5 in nums:
        n1 = 0xd4
        n2 = 0x30
        n3 = 0xc0
        solve("col1",n1,n2,n3,n4,n5)

#col2
for n2 in nums:
    for n3 in nums:
        for n4 in nums:
            for n5 in nums:
                n1 = 0xc2
                solve("col2",n1,n2,n3,n4,n5)

#col3
for n2 in nums:
    for n3 in nums:
        for n4 in nums:
            for n5 in nums:
                n1 = 0xbd
                solve("col3",n1,n2,n3,n4,n5)

#col4
for n2 in nums:
    for n3 in nums:
        for n4 in nums:
            for n5 in nums:
                n1 = 0xa0
                solve("col4",n1,n2,n3,n4,n5)

#col5
for n2 in nums:
    for n3 in nums:
        for n4 in nums:
            for n5 in nums:
                n1 = 0x96
                solve("col5",n1,n2,n3,n4,n5)
```

It turns out that with the exception of the col1 and row1, the other columns and rows had multiple possible solutions when using a pure brute-force approach without restricting that a value can be used only once.

Output:
```console
➜  dice-is-for-you python solve.py | cut -d " " -f 1  | sort | uniq -c 
      1 col1
    601 col2
    527 col3
    789 col4
    882 col5
      1 row1
    637 row2
    740 row3
    850 row4
    728 row5
```



### Z3 FTW

My next approach was to use the Z3 SMT Solver to solve the `"sudoku like"` board with our rules and constraints.

```python
from z3 import *

nums = [0x78, 0x37, 0x01, 0x12, 0x19,
        0x8a, 0x31, 0x60, 0x3d, 0x87,
        0xf7, 0xa0, 0xb3, 0x94, 0x77,
        0x05, 0xb7, 0x96, 0xa3, 0xab,
        0xd4, 0xc2, 0xbd, 0x30, 0xc0]

def code(n1,n2,n3,n4,n5):
    var19 = ((n1 * 42) + (n2 * 1337) + n3) 
    var25 = n3 ^ n4
    var28 = n5 << 1
    
    return (var19+var25+var28) & 255

"""
c00 c01 c02 c03 c04
c10 c11 c12 c13 c14
c20 c21 c22 c23 c24
c30 c31 c32 c33 c34
c40 c41 c42 c43 c44
"""

M = [[
    BitVec(f"c{row}{col}",8)
    for col in range(5)]
    for row in range(5)]

s = Solver()
for row in M:
    n1,n2,n3,n4,n5 = row
    s.add(code(n1,n2,n3,n4,n5) == 0)

for col in zip(*M):
    n1,n2,n3,n4,n5 = col
    s.add(code(n1,n2,n3,n4,n5) == 0)

s.add(M[0][0] == 0xd4)
s.add(M[0][1] == 0xc2)
s.add(M[0][2] == 0xbd)
s.add(M[1][0] == 0x30)
s.add(M[2][0] == 0xc0)

s.add(Distinct(
    [ M[row][col]
    for col in range(5)
    for row in range(5)]
))

for row in range(5):
    for col in range(5):
        block = []

        for n in nums:
            block.append(M[row][col] == n)

        s.add(Or(block))


print(s.check())
print(s.model())
if s.check():
    m = s.model()
    print(m)
    for row in range(5):
        for col in range(5):
            x = m[M[row][col]]
            print(hex(int(x.as_string())), end=" ")
        print()
```

### Output

```
0xd4 0xc2 0xbd 0xa0 0x96 
0x30 0xf7 0x87 0x01 0x8a 
0xc0 0xb3 0x77 0xb7 0x37 
0x60 0xab 0x19 0x3d 0x78 
0x94 0x31 0x05 0xa3 0x12 
```


## Final board and flag

Now it was only a matter of using the Symbol Mapping table to get the flag


![Final Board](https://i.imgur.com/3pXATDj.png)
![Flag](https://i.imgur.com/O2IyjSp.png)

Flag:
`dice{d1ce_1s_y0u_is_th0nk_73da6}`

## Final Notes

The DiceCTF was fun with some very cool challenges, looking forward next editions of this CTF. :-)
Only 19 teams solved this challenge, I wonder if that is related to the tooling for debugging WebAssembly code.

### WebAssembly Debbuging Tooling

Although this write-up shows a linear approach to solved this challenge, my approach during the competition was not that straightforward. 

At first, I tried to use Chromium to debug the wasm code. Which would not allow me to insert breakpoints with the following error message:
![](https://i.imgur.com/OO7YmRZ.png)

Which later I discovered that I could enable the WebAssembly Debugging: Enable DWARF support as a workaround.
![](https://i.imgur.com/JQcPMqU.png)

I changed between Chrome and Firefox multiple times and it seems each of them has advantages and disadvantages for debugging WebAssembly.

One really cool feature present in Chrome that I don't think is present in Firefox is the ability to show the internal stack variables. 
![](https://i.imgur.com/2niULBc.png)

Meanwhile Firefox exposes the internal WebAssembly memory as variable `memory0` while on Chrome I had to open the dev tools, insert a breakpoint, go to `Module` -> `env-memory` -> `store object as global variable`

This and other nuances made me write a lot of javascript helper functions such as full wasm memory dump, hexdump of memory pointers stored on variables among other things. Some of this terrible code are present [here](https://gist.github.com/DaniloNC/2b4babe72ee8481563a09ed3bbd8943e).

