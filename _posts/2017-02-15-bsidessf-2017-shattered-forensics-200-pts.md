---
layout: post
title: BsidesSF 2017 - shattered (forensics, 200 pts)
author: jeremy
tags: [ctf, bsidessf, forensics]
---

 * Competition: https://scoreboard.ctf.bsidessf.com/
 * Challenge Name: shattered
 * Type: Forensics
 * Points: 200 pts
 * URL: https://scoreboard.ctf.bsidessf.com/attachment/e6b6a3706e015298b8227f56e33d8cc5cb379a9c45a7eeee08c1f193c578ca1b

<!--more-->

We think we found how they're exfiltrating our data. One of the network engineers located a bizzare flow that looks designed to bypass our DLP system. Can you figure out what they were leaking this time?

[shattered.pcapng](https://scoreboard.ctf.bsidessf.com/attachment/e6b6a3706e015298b8227f56e33d8cc5cb379a9c45a7eeee08c1f193c578ca1b)

The file we get is a packet capture file full of retransmitted packets, the traffic looks scrambled, and the sequence numbers are mixed up. There is a great tool called [tcpflow](http://www.circlemud.org/jelson/software/tcpflow/) that can be used to recontruct it. After loading the PCAP in Wireshark to convert it to a native tcpdump PCAP:

```bash
$ tcpflow -d2 -r shattered.pcap
tcpflow: retrying_open ::open(fn=004.005.006.007.12345-008.009.010.011.02355,oflag=xc2,mask:x1b6)=5
tcpflow: Open FDs at end of processing:      1
tcpflow: demux.max_open_flows:               1
tcpflow: Flow map size at end of processing: 1
tcpflow: Flows seen:                         1
tcpflow: Total flows processed: 1
tcpflow: Total packets processed: 1821

$ file 004.005.006.007.12345-008.009.010.011.02355
004.005.006.007.12345-008.009.010.011.02355: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, progressive, precision 8, 564x572, frames 3
```
