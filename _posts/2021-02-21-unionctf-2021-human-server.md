---
layout: post
title: Union CTF 2021 - Human server [crypto]
author: yo_yo_yo_jbo (0x3d5157636b525761)
tags: [ctf, Union CTF, crypto]
---

 * Competition: [Union CTF 2021](https://ctf.cr0wn.uk)
 * Challenge Name: Human server
 * Type: Crypto
 * Points: 100 pts
 * Description: 
 > Ever since everyone left WhatsApp, we've been overwhelmed by new users. We've teamed up with UnionCTF to get some humans working while our servers take a break.
 > You'll be helping our users send flags to each other, but as we've ensured messages are E2E encrypted with state-of-the-art military-grade encryption, their messages will be private. Our customers have nothing to worry about.
 > nc 134.122.111.232 54321
 > Author: Jack & hyperreality

The challenge
=============
Code is pretty straighforward:
```python
import os, random, hashlib, textwrap, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, long_to_bytes

from fastecdsa.curve import secp256k1
from fastecdsa.point import Point

FLAG = b'union{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}'

CURVE = secp256k1
ORDER = CURVE.q
G = CURVE.G

class EllipticCurveKeyExchange():
    def __init__(self):
        self.private = random.randint(0,ORDER)
        self.public = self.get_public_key()
        self.recieved = None
        self.nonce = None
        self.key = None

    def get_public_key(self):
        A = G * self.private
        return A

    def send_public(self):
        return print(json.dumps({"Px" : self.public.x, "Py" : self.public.y}))

    def receive_public(self, data):
        """
        Remember to include the nonce for ultra-secure key exchange!
        """
        Px = int(data["Px"])
        Py = int(data["Py"])
        self.recieved = Point(Px, Py, curve=secp256k1)
        self.nonce = int(data['nonce'])

    def get_shared_secret(self):
        """
        Generates the ultra secure secret with added nonce randomness
        """
        assert self.nonce.bit_length() > 64
        self.key = (self.recieved * self.private).x ^ self.nonce

    def check_fingerprint(self, h2: str):
        """
        If this is failing, remember that you must send the SAME
        nonce to both Alice and Bob for the shared secret to match
        """
        h1 = hashlib.sha256(long_to_bytes(self.key)).hexdigest()
        return h1 == h2

    def send_fingerprint(self):
        return hashlib.sha256(long_to_bytes(self.key)).hexdigest()

def print_header(title: str):
    print('\n\n'+'*'*64+'\n'+'*'+title.center(62)+'*\n'+'*'*64+'\n\n')

def input_json(prompt: str):
    data = input(prompt)
    try:
        return json.loads(data)
    except:
        print({"error": "Input must be sent as a JSON object"})
        exit()

def encrypt_flag(shared_secret: int):
    iv = os.urandom(16)
    key = hashlib.sha1(long_to_bytes(shared_secret)).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))

    data = {}
    data['iv'] = iv.hex()
    data['encrypted_flag'] = ciphertext.hex()
    return print(json.dumps(data))


Alice = EllipticCurveKeyExchange()
Bob = EllipticCurveKeyExchange()

print_header('Welcome!') 
message = "Hello! Thanks so much for jumping in to help. Ever since everyone left WhatsApp, we've had a hard time keeping up with communications. We're hoping by outsourcing the message exchange to some CTF players we'll keep the load down on our servers... All messages are end-to-end encrypted so there's no privacy issues at all, we've even rolling out our new ultra-secure key exchange with enhanced randomness! Again, we really appreciate the help, feel free to add this experience to your CV!"
welcome = textwrap.fill(message, width=64)          
print(welcome)

print_header('Alice sends public key')
Alice.send_public()

print_header("Please forward Alice's key to Bob")
alice_to_bob = input_json('Send to Bob: ')		# Bob.received=G, nonce=NONCE, key=Bob.public ^ NONCE
Bob.receive_public(alice_to_bob)

print_header('Bob sends public key')
Bob.send_public()

print_header("Please forward Bob's key to Alice")
bob_to_alice = input_json('Send to Alice: ')
Alice.receive_public(bob_to_alice)				# Alice.received=
            
Alice.get_shared_secret()
Bob.get_shared_secret()

print_header('Key verification in progress')
alice_happy = Alice.check_fingerprint(Bob.send_fingerprint())
bob_happy = Bob.check_fingerprint(Alice.send_fingerprint())
if not alice_happy or not bob_happy:
    print({"error": "Alice and Bob panicked: Potential MITM attack in progress!!"})
    exit()

print_header('Alice sends encrypted flag to Bob')
encrypt_flag(Alice.key)
```

Highlevel details
=================
1. Using the `secp256k1` curve, the `EllipticCurveKeyExchange` class has a private key (```random.randint``` to get an integer in the order of the curve) and a public key (which is a known point `G` multiplied by the private key).
2. The `send_public` method simply outputs the public key's coordinates.
3. The `receive_public` method receives JSON data representing a point and then saves the point as the `recieved` member. It will also extract a nonce integer from the JSON and will keep the nonce as the `nonce` member.
4. The `get_shared_secret` method validates the nonce is at least 65-bit wide, and then calculates the key: `(received*private).x ^ nonce`.
5. The `send_fingerprint` method publishes SHA256 of the shared key.
6. The `check_fingerprint` gets a fingerprint and validates that it's equal to own's key SHA256.
7. Finally, the `encrypt_flag` method does an AES-CBC cipher. It uses random 16 bytes as the IV (from `os.urandom`) and the first 16 bytes from the SHA1 digest of the shared key as the AES key.

Obviously, the goal is abusing the `nonce` and the `received` point to get a known key.
The shared secret is calculated as such:
```
shared_secret = (received * private).x ^ nonce
```

So, if we set `received = G`, we effectively set the shared secret to `public.x ^ nonce` (due to the multiplication of the point with `private`).
We can control difference `nonce` values for Alice and Bob to coordinate the secret.

Sending to Bob
==============
1. At this point we do not know Bob's public key.
2. Set `recevied=G` and `Nonce` to be `2**65` (just to be over 64 bits).
3. This makes the shared secret: `bob.public.x ^ 2**65`.

Sending to Alice
================
1. At this point we know everyone's public keys.
2. Set `received=G`, so now we must satisfy: `alice.public.x ^ n = bob.public.x ^ 2**65`, where `n` is the Nonce sent to Alice from Bob.
3. The solution is `n = bob.public.x ^ alice.public.x ^ 2**65`.

Solution code
=============
```python
import json, hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, long_to_bytes

from fastecdsa.curve import secp256k1
from fastecdsa.point import Point

CURVE = secp256k1
ORDER = CURVE.q
G = CURVE.G

DUMMY_NONCE = 2**65

alice_pub = json.loads(input('alice.pub?'))
print('{"Px": %d, "Py": %d, "nonce": %d}' % (G.x, G.y, DUMMY_NONCE))

bob_pub = json.loads(input('bob.pub?'))
shared_secret = bob_pub['Px'] ^ DUMMY_NONCE
alice_nonce = bob_pub['Px'] ^ alice_pub['Px'] ^ DUMMY_NONCE
print('{"Px": %d, "Py": %d, "nonce": %d}' % (G.x, G.y, alice_nonce))

aes_key = hashlib.sha1(long_to_bytes(shared_secret)).digest()[:16]
aes_data = json.loads(input('aes.data?'))
aes_iv = bytes.fromhex(aes_data['iv'])
cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
ciphertext = bytes.fromhex(aes_data['encrypted_flag'])
print(cipher.decrypt(ciphertext))
```
I ended up with the flag: `union{https://buttondown.email/cryptography-dispatches/archive/cryptography-dispatches-the-most-backdoor-looking/}`
