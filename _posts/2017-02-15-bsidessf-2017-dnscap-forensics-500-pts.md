---
layout: post
title: BsidesSF 2017 - Dnscap (forensics, 500 pts)
author: jeremy
tags: [ctf, bsidessf, forensics]
---

 * Competition: https://scoreboard.ctf.bsidessf.com/
 * Challenge Name: dnscap
 * Type: Forensics
 * Points: 500 pts
 * URL: https://scoreboard.ctf.bsidessf.com/attachment/ * 2913744793e3b95676d0713aef7c7df42ddbb2f8ffece2b022c7ee727b833f59

<!--more-->

> Found this packet capture. Pretty sure there's a flag in here. Can you find it!?
>
> [dnscap.pcap](https://scoreboard.ctf.bsidessf.com/attachment/2913744793e3b95676d0713aef7c7df42ddbb2f8ffece2b022c7ee727b833f59)



We get a packet capture containing DNS traffic. Only queries and replies for A, MX and TXT records. We thought about an exchange over a DNS tunnel but didn't really know where to start. We simply started by decoding the hostnames in the DNS queries and see what it looked like:

```python
from scapy.all import rdpcap, DNSQR, DNSRR

for p in rdpcap('dnscap.pcap'):

    # Look at queries only
    if p.haslayer(DNSQR) and not p.haslayer(DNSRR):

        qry = p[DNSQR].qname.replace('.skullseclabs.org.', '').split('.')
        qry = ''.join(_.decode('hex') for _ in qry)

        print '%r' % qry

```

The data in the hostnames towards the end contained this:

```
'\xa0W\x00\xe6\xda\x83Q\x00\x01console (sirvimes)\x00'
'\xb5A\x01\xe6\xda\x83Qn\xa2'
'1s\x01\xe6\xda\x83Qn\xa2'
'\xac\xe3\x01\xe6\xda\x83Qn\xa2Good luck! That was dnscat2 traffic on a flaky connection with lots of re-transmits. Seriously, '
'd[\x01\xe6\xda\x83\xb1n\xa2good luck. :)\n'
'3z\x01\xe6\xda\x83\xbfn\xa2'
'T[\x01\xe6\xda\x83\xbfn\xa2'
```

From the message above we deducted that we were probably looking at the right place, and the first 9 bytes of each request was probably some dnscat specific data, useless for us. So we ran the script again, skipping the first 9 bytes and could observe the following:

```
'\x00\x00,\xed\x80\x01\x00\x03\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00\x00\x00\x01\x00\x08\x04\x00\x00\x00\xf6{`\xed\x00\x00\x00\x04gAMA\x00\x01\x86\xa01\xe8\x96_\x00\x00\x00\x02bKGD\x00\xff\x87\x8f\xcc\xbf\x00\x00\x00\tpHYs\x00\x00\x0b\x13\x00\x00\x0b\x13\x01\x00\x9a\x9c\x18\x00\x00\x00\x07'
"tIME\x07\xe1\x02\x02\x05\r5$\xd3\x81\xe9\x00\x00,\x08IDATx\xda\xed\x9dw\x9c\x1b\xd5\xd5\xf7\xbf\xa3\xae\x95V\xdb\xab\xd7\xde]{w\xedu\xb7q\xc1\xd8\x98f\xc08&\xc6\x80\xc1\x0f\t\x84\x04HBBH\xf2R\x9e\x87\x84'\xa4@\xeaCxRH!\x8d\xbc@HB\x89C1%t\xb0\x81`\x03."
```

We can clearly recognise the signature for a PNG file being transmitted! We adapted our script to skip the first 9 bytes of each decoded hostname in the queries, and take only the lines between this PNG file header and the one that contained the 'IEND' chunk:

```python
    if 15 < qry_nb < 194:
        out += qry[9:]

    qry_nb += 1

open('out.png', 'wb').write(out)
```


At this point, the file was ineligible. After mucking around trying to fix it, we remembered the phrase that we saw before: _"That was dnscat2 traffic on a flaky connection with lots of re-transmits."_

That would mean that a lot of queries were actually the same as the previous ones? Let's try and fix the script. We also need to remove another 9 bytes of garbage in the first query that contains the PNG header. Finally our script below solved it!

```python
from scapy.all import rdpcap, DNSQR, DNSRR

last_qry = ''
out = ''
q_nb = 0

for p in rdpcap('dnscap.pcap'):

    if p.haslayer(DNSQR) and not p.haslayer(DNSRR):

        qry = p[DNSQR].qname.replace('.skullseclabs.org.', '').split('.')
        qry = ''.join(_.decode('hex') for _ in qry)[9:]

        if qry == last_qry:
            continue

        last_qry = qry
        q_nb += 1

        if q_nb == 7: # packet with PNG header
            out += qry[8:]

        if 7 < q_nb < 127: # All packets up to IEND chunk
            out += qry

open('flag.png', 'wb').write(out)
```

Running it yields a valid PNG:

![](https://raw.githubusercontent.com/jrmdev/ctf-writeups/master/bsidessf-2017/dnscap/flag.png)