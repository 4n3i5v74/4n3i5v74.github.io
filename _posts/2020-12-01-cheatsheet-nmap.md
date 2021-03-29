---
title: CheatSheet - NMAP
author: 4n3i5v74
date: 2020-12-01 00:00:00 +0530
categories: [CheatSheet, NMAP]
tags: [cheatsheet, nmap, pentest]
pin: true
---


## NMAP options

Scan Types
- `-sn` - Probe only (host discovery)
- `-sV` - Version scan
- `-O` - OS detection
- `-sT` - TCP scan
- `-sU` - UDP scan
- `-sS` - SYN scan
- `-sR` - RPC scan
- `--scanflags` - Custom list of TCP using URGACKPSHRSTSYNFIN, in any order
- `-v` - Verbose scan
- `-vv` - more verbose scan

Script Scan
- `-sC` - Default NSE script scan
- `--script=http` - Specify script
- `--script=http*,banner` - Specify multiple scripts
- `--script=snmp-sysdescr --script-args snmpcommunity=admin` - Specify script arguments

Probe Options
- `-Pn` - No probe (assume target is up)
- `-PB` - Default probe (TCP 80,445 and ICMP)
- `-PS80,443` - Probe specific ports
- `-PE` - ICMP echo request
- `-PP` - ICMP timestamp request
- `-PM` - ICMP netmask request

Timing Options
- `-T0` - Very Slow, for IDS evasion
- `-T1` - Quite Slow, for IDS evasion
- `-T2` - Slow, to consume less bandwidth, 10 times slower than normal
- `-T3` - Normal, dynamic timing based on target response
- `-T4` - Aggressive, assume fast network
- `-T5` - Insane, likely miss ports

Target Ports
- `-r` - Scan in linear fashion and not random
- `-F` - Scan most 100 popular ports
- `--top-ports 1000` - Scan most 1000 popular ports
- `-p80-100` - Scan from ports 80 to 100
- `-p80,100,120` - Scan ports 80,100,120
- `-pU:53,U:110,T:443-445` - Specify TCP/UDP ports
- `-p-` - Scan ports 1-65535
- `-phttp,https` - Scan using service names

Firewall Evasion
- `-f` - Use tiny fragmented IP packets
- `--mtu` - Set packet size
- `--scan-delay` - Add delay in ms between packets
- `-D decoy1,decoy1,ME` - Use decoys and own IP
- `-D RND:10` - Use random 10 addresses as decoy
- `-sI` - zombie scan
- `--source-port` - Specify source port
- `--data-length` - Append random data
- `--spoof-mac` - Spoof MAC address
- `--badsum` - Send bad checksums, usually to check presence of firewall
More information on firewall evasion can be seen [here](https://nmap.org/book/man-bypass-firewalls-ids.html){:target="_blank"}

Script Execution
- `--script` - Execute single of multiple scripts
- Script categories - all, auth, default, discovery, external, intrusive, malware, safe, vuln
- `--script banner --script trace` - Troubleshoot script
- `--script-updatedb` - Update script database
- `--script-help=ssl-heartbleed` - Help on script

Output Format
- `-oN out.txt` - Standard NMAP format
- `-oG grep.txt` - Greppable format
- `-oX out.xml` - XML format
- `-oA out` - NMAP, Greppable and XML formats
- `-oG -` - Greppable format to screen. `-oN -` and `-oX -` can also be used
- `--append-output` - Append output to previous scan result
- `-d` - Increase debug level. Use `-dd` for more debug result

MISC Options
- `-n` - Disable reverse lookup
- `-A` - Use additional features like OS detection, Version detection, script scanning and traceroute
- `--reason` - Display reason for port open, close or filtered
- `--open` - Show only open ports
- `--packet-trace` - Show sent/received packets
- `--dns-servers` - Query DNS server for target hosts
- `--send-eth` - Send raw ethernet packets
- `--send-ip` - Send IP packets

Target Specification
- IP Address - 192.168.1.1 or AABB:CC::DD%eth0 [specify multiple targets using space delimiter]
- IP Range - 192.168.0-255.0-255
- CIDR Block - 192.168.1.0/24
- Hostname - test-machine or scanme.nmap.org
- File with list of targets - `-iL hosts-file`


## Scan Info

Scans and their responses happen as per the [RFC Guideline](https://tools.ietf.org/html/rfc793){:target="_blank"}.


### TCP Connect Scan `-sT`

Perform TCP Connect Scan on all ports mentioned.
- If 3 way handshake works - `SYN -> SYN + ACK -> ACK + RST` - port is open
- If server sends reset packet - `SYN -> RST` - port is closed
- If packet is dropped or no response is received - `SYN` - port is blocked or filtered

Configure linux firewall to send reset packet.
{% capture code %}{% raw %}iptables -I INPUT -p tcp --dport <port> -j REJECT --reject-with tcp-reset{% endraw %}{% endcapture %} {% include code.html code=code %}

### TCP SYN Scan `-sS` - half open or stealth scan

This scan requires root access, as instead of ACK, RST packet is sent to server (create raw packet instead of ACK). This can also be made to run by setting capabilities like `CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`, but scripts will not work as intended.
This type is faster, and also stealthy, as most applications and firewalls logs only established connection, and this type resets before connetion is fully established.
Results are finalized using same conditions as TCP Connect Scan.

### UDP Scan `-sU`

As there is no acknowledgement for packets, UDP scan is more time consuming than TCP scans.
- If response is received, port is marked open (rare scenario)
- If response is not received, second packet is sent, even if response is not received, port is marked open or filtered
- If response is received by ICMP packet containing `port is unreachable` message, port is marked as closed

### Other TCP Scans

- TCP Null Scan `-sN`
Sends packet with no flags set. Expects reset response if port is closed. `NULL -> RST`

- TCP Fin Scan `-sF`
Instead of sending NULL packet, FIN is sent. Expects reset response if port is closed. `FIN -> RST`

- TCP XMas Scan `-sX`
Sends a malformed packet, FIN, PSH and URG. Expects reset response if port is closed. `FIN, PSH, URG -> RST`

These scans finalizes on open ports similar to UDP scan.
- If port is open, no response is received
- If port is closed, reset response is received

These scans are generally used for firewall evasion.
Windows and network devices are known to respond with RST packet for all malformed TCP packets.


## NMAP Script Engine

NMAP Scripts are written in LUA programming language, used for reconnaisance, vulnerability scanning or automatically exploiting them.
Major categories of NSE,
- safe - target wont be affected
- intrusive - target likely to be affected
- vuln - scan for vulnerabilities
- exploit - attempt to scan vulnerabilities
- auth - try to bypass authentication, like anonymous ftp server login
- brute - try to bruteforce credentials for login
- discovery - try to query running service

More information and categories can be found in the [NSE Usage](https://nmap.org/book/nse-usage.html){:target="_blank"} and [NSE Documentation](https://nmap.org/nsedoc/){:target="_blank"}

To search for available ftp scripts,
{% capture code %}{% raw %}grep ftp /usr/share/nmap/scripts/script.db{% endcapture %} {% include code.html code=code lang="bash" %}
{% capture code %}{% raw %}ls -l /usr/share/nmap/scripts/*ftp*{% endcapture %} {% include code.html code=code lang="bash" %}

To check dependencies for the script,
{% capture code %}{% raw %}grep dependencies /usr/share/nmap/scripts/<script>{% endcapture %} {% include code.html code=code lang="bash" %}


## NMAP Examples

Network sweep
{% capture code %}{% raw %}nmap -sn 192.168.1.0/24{% endraw %}{% endcapture %} {% include code.html code=code %}

ARP discovery
{% capture code %}{% raw %}nmap -PR 192.168.1.0/24{% endraw %}{% endcapture %} {% include code.html code=code %}

Version intensity
0-9, higher number gives more accurate result
{% capture code %}{% raw %}nmap -sV --version-intensity 8 192.168.1.100{% endraw %}{% endcapture %} {% include code.html code=code %}

Light mode - 0. Faster
{% capture code %}{% raw %}nmap -sV --version-light 192.168.1.100{% endraw %}{% endcapture %} {% include code.html code=code %}

Intense mode - 9. Slower
{% capture code %}{% raw %}nmap -sV --version-all 192.168.1.100{% endraw %}{% endcapture %} {% include code.html code=code %}

Limit OS scan. If atleast one open and closed TCP ports are not found, OS detection will not be done
{% capture code %}{% raw %}nmap -O --osscan-limit 192.168.1.100{% endraw %}{% endcapture %} {% include code.html code=code %}

Timeout. Giveup after some time. 1s, 2m, 3h
{% capture code %}{% raw %}nmap --host-timeout 10m 192.168.1.100{% endraw %}{% endcapture %} {% include code.html code=code %}

Firewall/IDS Evasion and Spoofing
Use tiny fragmented IP packets which is harder for packet filters to trace
{% capture code %}{% raw %}nmap -f 192.168.1.100{% endraw %}{% endcapture %} {% include code.html code=code %}

Send scans from spoofed IPs
Any IP from the list can be our own IP
{% capture code %}{% raw %}nmap -D 192.168.1.101,192.168.1.111,192.168.1.121,192.168.1.131 192.168.1.100{% endraw %}{% endcapture %} {% include code.html code=code %}

Scan target from other host
{% capture code %}{% raw %}nmap -e eth0 -Pn -S decoy 192.168.1.100{% endraw %}{% endcapture %} {% include code.html code=code %}

Use source port number
{% capture code %}{% raw %}nmap -g 53 192.168.1.100{% endraw %}{% endcapture %} {% include code.html code=code %}

Append ramdom data
Useful for IDS evasion
{% capture code %}{% raw %}nmap -f -T0 -n -Pn --data-length 200 -D 192.168.1.101,192.168.1.111,192.168.1.121,192.168.1.131 192.168.1.100{% endraw %}{% endcapture %} {% include code.html code=code %}

Whois query
{% capture code %}{% raw %}nmap --script whois* scanme.nmap.org{% endraw %}{% endcapture %} {% include code.html code=code %}

Information on target
{% capture code %}{% raw %}nmap --script asn-query,whois*,ip-geolocation-maxmind 192.168.1.100{% endraw %}{% endcapture %} {% include code.html code=code %}

HTTP site map generator
{% capture code %}{% raw %}nmap -Pn --script=http-sitemap-generator scanme.nmap.org{% endraw %}{% endcapture %} {% include code.html code=code %}

Run SMB scripts
{% capture code %}{% raw %}nmap -n -Pn -vv -O -sV --script smb-enum*,smb-ls,smb-mbenum,smb-os-discovery,smb-s*,smb-vuln*,smbv2* 192.168.1.100{% endraw %}{% endcapture %} {% include code.html code=code %}

Check XSS vulnerabilities
{% capture code %}{% raw %}nmap -p80 --script http-unsafe-output-escaping scanme.nmap.org{% endraw %}{% endcapture %} {% include code.html code=code %}

Check SQL injection
{% capture code %}{% raw %}nmap -p80 --script http-sql-injection scanme.nmap.org{% endraw %}{% endcapture %} {% include code.html code=code %}

Compare scan outputs
{% capture code %}{% raw %}ndiff scan1.xml scan2.xml{% endraw %}{% endcapture %} {% include code.html code=code %}

Convert scan result to html
{% capture code %}{% raw %}xsltproc nmap.xml -o nmap.html{% endraw %}{% endcapture %} {% include code.html code=code %}


## Common enumeration usage

{% capture code %}{% raw %}nmap -Pn -n -F 192.168.1.100
nmap -Pn -n -p- --open -A -T4 192.168.1.100{% endraw %}{% endcapture %} {% include code.html code=code %}

