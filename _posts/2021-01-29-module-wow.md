---
layout: post
title: CrowdStrike CTF 2021 - Module Wow [crypto, reversing]
author: yo_yo_yo_jbo (0x3d5157636b525761)
tags: [ctf, crowdstrike, crypto, reversing]
---

 * Competition: [https://adversary.zone/challenges)
 * Challenge Name: Module wow
 * Type: Crypto, reversing
 * Points: 1 pts
 * Description: Diving deeper into CATAPULT SPIDER's malware, we found that it also supports handing off tasks to external modules. We identified one such module that looks like it might be used to validate a key or password of some sorts, but we're really not sure. Can you validate our assumption, and, if possible, extract the key?

Downloading module.wow file reveals it's ELF64.
Code is pretty straightforward, it does the following:
* It gets a password from `argv[1]` (command-line argument).
* It sets the same signal handler to various signals to just output a message and quit (to gracefully handle execution errors).
* It decrypts a payload of length `196` by cyclinc-XORing one byte at a time with the password.

Obviously the important part of the payload XORing:
```
  mem_mapped = (code *)mmap((void *)0x0,payload_len,7,0x22,-1,0);
  if (mem_mapped == (code *)0xffffffffffffffff) {
    perror("[!] mmap() failed");
    result = 0xffffffff;
  }
  else {
    memcpy(mem_mapped,payload,payload_len);
    counter = 0;
    while (counter < payload_len) {
      curr_byte = mem_mapped[counter];
      password_len = strlen(password);
      *(byte *)(mem_mapped + counter) = password[counter % password_len] ^ (byte)curr_byte;
      counter = counter + 1;
    }
    (*mem_mapped)(password);
    munmap(mem_mapped,payload_len);
    result = 0;
  }
  return result;
```

The XOR-encrypted payload is given here as a whole: `161bf2863afa9c6478d61c967ce73c8b79fa98d8435f6330edf49543537b632731f99178dc8d7ebd1185f8748f17a826d6a478a3f34143537b6c77f23588b99889b4cb93862679faba78edb34378ed4e95841687637279703cbb1a8926bd29899838f01acc6f17e075943235c8168b6cc479f4b445b3ea3bc824f236d93bd6f6d15e633064db7f43537baab12c38fdd5d61c827ce50c93b826b7bb2bb32ba82cbaba0bd83e833af0b6ff75b729f67ce5bb3bf6b35e306e5f6c35edf3f406aff0268e24b3`

Since this is x86_64, we can expect certain patterns, such as:
* REX prefix (```0x48```)
* Function prologue:
```
PUSH RBP               0x55
MOV RBP, RSP           0x48 0x89 0xe5
SUB RSP, XXXXX         0x48 0x83 0xec XXXXX
```
* Function epilogue #1:
```
LEAVE                  0xc9
RET                    0xc3
```
* Function epilogue #2:
```
POP RBP                0x5d
RET                    0xc3
```

Guessing payload starts with a function prologue, we get the expected bytes of `554889e54883ec`.
This gives us a few of the password's first bytes:
```
Payload:    16 1b f2 86 3a fa 9c
Expected:   55 48 89 e5 48 83 ec
XOR result: 43 53 7b 63 72 79 70
XOR char:   C  S  {  c  r  y  p
```

The XOR result gives us `CS{cryp`, which looks like the format of the CTF's flag.
Continueing logically, I assumed the next byte is 't', which made sense when decoding the payload.
The next character could be 'o', 'O' or '0', and I noticed '0' gives me a `REX prefix (0x48)` so I bet on '0'.
This means the password starts with `CS{crypt0`.
For the next byte I tried 'g' but it gave me an invalid opcode, so I decided to try 'G' and '_' as well:
```
Password char option:   g  G  _
Password byte option:   67 47 5f
Payload byte:           d6 d6 d6
XOR result:             b1 91 89
```
Since this is a beginning of a new opcode, I noticed only `0x89 (MOV)` makes sense, the result decode to invalid opcodes.
For this you can use any Intel opcode referece, such as this: [http://ref.x86asm.net/coder32.html].

After I got the password prefix `CS{crypt0_` I got stuck for a moment, as continuing this guessing game is hard.
I decided to attack the payload from its last byte, which I expect to be `RET (0xc3)`:
```
Payload:    b3
Expected:   c3
XOR result: 70
XOR char:   p
```

Now I made another guess. As the password is used in a cyclic fashion, I guessed that the last 'p' I just retireved was the 'p' I already got in the prefix.
If that's the case then I could use that information to conclude several options for the password's length.
Since the payload is `196` bytes long, and since our 'p' is the `7th` byte in the prefix, it means that our password length must divide `196-7=189`.
Factoring `189` gives us: `189=3*3*3*7`, which gives us several password length options:
```
Length   Remarks
======   =======
     1   Too short
     3   Too short
     7   Too short
     9   Too short
    21   Probable
    27   Probable
    63   Perhaps too long?
   189   Hopefully too long!
```
We now have two probable options: `21` and `27`. At this point I want to see if I could favor one over the other.
I could do so by using the partial password I got (the prefix) and see how it affects the resulting code.
While I could do this by hand, I decided to use [http://www.capstone-engine.org] which has really cool Python support.
I coded a short Python script that tests a prefix, a postfix and key length and shows the result.
For "unfinished" instructions I simply put `NOP (0x90)` which might screw-up some instructions but it's better than nothing.

```python
#!/usr/bin/python3

from capstone import *

def f(payload, key_prefix, key_suffix, expected_keylen, base = 0x001040a0):
    code = b''
    for i in range(len(payload)):
        curr = i % expected_keylen
        if curr < len(key_prefix):
            code += bytes([payload[i] ^ key_prefix[curr]])
            continue
        if curr >= expected_keylen - len(key_suffix):
            code += bytes([payload[i] ^ key_suffix[-(expected_keylen - curr)]])
            continue
        code += b'\x90'
    g(code, base)

def g(code, base):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    tot = 0
    for i in md.disasm(code, base):
        print("0x%x:\t%s\t%s\t\t%s" %(i.address, i.mnemonic, i.op_str, i.bytes.hex()))
        tot += len(i.bytes)
    print('Total bytes: %d from %d' % (tot, len(code)))
    print('=' * 30)
    while tot < len(code):
        tot += 1
        for i in md.disasm(code[tot:], base+tot):
            print("0x%x:\t%s\t%s\t\t%s" %(i.address, i.mnemonic, i.op_str, i.bytes.hex()))
            tot += len(i.bytes)

payload = bytes.fromhex('161bf2863afa9c6478d61c967ce73c8b79fa98d8435f6330edf49543537b632731f99178dc8d7ebd1185f8748f17a826d6a478a3f34143537b6c77f23588b99889b4cb93862679faba78edb34378ed4e95841687637279703cbb1a8926bd29899838f01acc6f17e075943235c8168b6cc479f4b445b3ea3bc824f236d93bd6f6d15e633064db7f43537baab12c38fdd5d61c827ce50c93b826b7bb2bb32ba82cbaba0bd83e833af0b6ff75b729f67ce5bb3bf6b35e306e5f6c35edf3f406aff0268e24b3')

# EXPERIMENT STATS HERE
keylen = 21
key_suffix = b'}'
key_prefix = b'CS{crypt0_'

print(key_prefix)
print(key_suffix)
f(payload, key_prefix, key_suffix, keylen)
```

Note how we can control `keylen` and see how it affects the decoded payload.
For a length of `21` I get weird instructions that don't make logical sense, for instance:
```
0x1040f4:       and     byte ptr [rcx], ah              2021
0x1040f6:       add     dl, byte ptr [rbx]              0213
0x1040f8:       ret     0xfd6a          4ec26afd
0x1040fd:       loop    0x10408f                e290
```
However, for length of `27` I get another `function prologue`:
```
0x1040ba:       call    0x1040bf                e800000000
0x1040bf:       push    rbp             55
0x1040c0:       mov     rbp, rsp                4889e5
0x1040c3:       adc     qword ptr [rax - 0x6f6f6f70], -0x70             4883909090909090
```

So, from this point on, I concluded that the password length is `27` characters long.
This means I only have `16` bytes to go.
From this point on I tried getting sane opcodes and logically correct code.
For instance, decoding with the current prefix I get:
```
0x1040d4:       nop                     90
0x1040d5:       cmp     al, 0           3c00
0x1040d7:       add     byte ptr [rax], al              0000
0x1040d9:       syscall                 0f05
```
If the syscall is correct then the bytes before it do not make sense, but `0x3c` corresponds to `syscall 60 = exit`.
You can use any reference to syscall numbers, such as [https://filippo.io/linux-syscall-table].
This makes a lot of sense, so `3c000000` is really an immidiate 32-bit value, and I am really expecting to see RAX being set:
```
0x1040d2:       mov     rax, 0x3c               48c7c03c000000
0x1040d9:       syscall          0f05```
This gave me:
```
Payload:    78 a3 f3 41 43 53 7b 6c 77
Expected:   48 c7 c0 3c 00 00 00 0f 05
XOR result: 30 64 33 7d 43 53 7b 63 72
XOR char:   0  d  3  }  C  S  {  c  r
```

We can even guess that the postfix is `_c0d3`. From here, guessing onward became easier as more and more bytes get revealed.
For example, now we get:
```
0x104154:       nop                     90
0x104155:       nop                     90
0x104156:       nop                     90
0x104157:       add     byte ptr [rdi], cl              000f
0x104159:       add     eax, 0x4589c089         0589c08945
```
Obviously the `0f05` is another `syscall`, so we expect `RAX` to be set again.
Eventually, after all the bytes are decoded, we get the flag: `CS{crypt0_an4lys1s_0n_c0d3}`.
Interestingly, the entire decoded payload simply prints out the password.
