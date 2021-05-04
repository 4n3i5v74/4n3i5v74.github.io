---
title: CheatSheet - Hydra
author: 4n3i5v74
date: 2020-12-01 08:10:00 +0530
categories: [CheatSheet, Hydra]
tags: [cheatsheet, hydra, pentest]
pin: true
---


## Hydra Options

- `-l <name>` - username
- `-L <file>` - multiple usernames
- `-p <pass>` - single known password
- `-P <file>` - wordlist
- `-s <port>` - custom port
- `-f` - exit if one login and password combination is found, per host
- `-F` - exit if one login and password combination is found, global
- `-t` - number of connects in parallel, per target (default 16)
- `-T` - number of connects in parallel, global (default 64)
- `-w` - wait time for response (default 32)
- `-q` - ignore errors
- `-S` - ssl connect
- `-u` - loop around users and not passwords (effective with -x)
- `-v` - verbose
- `-V` - show login+pass for each attempt
- `-d` - debug mode


## Bruteforce Common services

- `hydra -f -l <user> -P <wordlist> <ip> -t 10 <protocol>`
- Protocols - `ssh` `mysql` `ftp` `smb` `rdp` `snmp`


## Bruteforce HTTP

- HTTP POST - `hydra -f -l <user> -P <wordlist> <ip> -t 10 http-post-form "<login-page>:<request-body>:<error-message>"`
- Example POST - `hydra -f -l <user> -P <wordlist> <ip> -t 10 http-post-form "/login.php:username=^USER^&password=^PASS^:Login Failed"`
- Wordpress Bruteforce - `hydra -f -l <user> -P <wordlist> <ip> -t 10 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location"

