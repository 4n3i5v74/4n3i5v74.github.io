---
title: CheatSheet - Gobuster
author: 4n3i5v74
date: 2020-12-01 08:00:00 +0530
categories: [CheatSheet, Gobuster]
tags: [cheatsheet, gobuster, pentest]
pin: true
---


## Gobuster options

Modes
- dir - directory/file enumeration
- dns - DNS subdomain enumeration
- s3 - AWS S3 bucket enumeration
- vhost - VHOST enumeration

Global options
- `--no-error` - Do not display errors
- `-q` - Do not print the banner and other noise
- `-t` - Number of concurrent threads (default 10)
- `-w` - Path to the wordlist

DIR mode options
- `-u` - URL to be used
- `-s` - Status code to be checked, instead of all positive status codes
- `-x` - File extension to be scanned
- `-e` - Print full URL
- `-r` - Follow redirects
- `-a` - Set the User-Agent string (default "gobuster/3.1.0")
- `--random-agent` - Use random User-Agent string
- `--wildcard` - Continue when wildcard found

DNS mode options
- `-d` - Domain to be used
- `-r` - Use custom DNS server
- `-c` - Show CNAMEs
- `-i` - Show IPs
- `-k` - Skip SSL verification
- `--wildcard` - Continue when wildcard found


## Gobuster examples

Scan url for certain file extensions using **dir** mode
{% capture code %}{% raw %}gobuster dir -u http://scanme.nmap.org -w /usr/share/wordlists/rockyou.txt -x php,php3,html,htm,xhtml{% endraw %}{% endcapture %} {% include code.html code=code%}

Scan sub-domains using **vhost** mode
{% capture code %}{% raw %}gobuster vhost -u http://scanme.nmap.org -w /usr/share/wordlists/rockyou.txt -o output.txt{% endraw %}{% endcapture %} {% include code.html code=code%}

Scan sub-domains using **dns** mode
{% capture code %}{% raw %}gobuster dns -d scanme.nmap.org -w /usr/share/wordlists/rockyou.txt -k -i{% endraw %}{% endcapture %} {% include code.html code=code%}

