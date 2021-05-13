---
title: Writeup for TryHackMe room - John The Ripper
author: 4n3i5v74
date: 2021-01-04 00:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, crypto, john]
pin: false
---


<div class="flex-container">
  <script src="https://tryhackme.com/badge/34685"></script>
</div>


## [John The Ripper](https://tryhackme.com/room/johntheripper0){:target="_blank"}

This room contains info about hashing and methods to crack them using `John The Ripper`.

For complete tryhackme path, refer the [link](https://4n3i5v74.github.io/posts/getting-started-with-cybersecurity-tryhackme/){:target="_blank"}. Refer the [link](https://4n3i5v74.github.io/posts/cheatsheet-john-the-ripper/){:target="_blank"} for more information on `john`.


## Task 4 - Cracking Basic Hashes

### Hash 1

Check the hash identifier and mode from [HashID](https://pypi.org/project/hashID/){:target="_blank"} for hash `2e728dd31fb5949bc39cac5a9f066498`.
{% capture code %}{% raw %}python3 hash-id.py 2e728dd31fb5949bc39cac5a9f066498{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username))){% endraw %}{% endcapture %} {% include code.html code=code %}

Crack the hash `2e728dd31fb5949bc39cac5a9f066498` using `john`.
{% capture code %}{% raw %}.\run\john.exe --format=raw-md5 --wordlist=wordlists\rockyou.txt hash\hash1.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
<password>          (?)
1g 0:00:00:00 DONE (2021-04-10 11:42) 8.130g/s 21853p/s 21853c/s 21853C/s skyblue..nugget
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed{% endraw %}{% endcapture %} {% include code.html code=code %}


### Hash 2

Check the hash identifier and mode from [HashID](https://pypi.org/project/hashID/){:target="_blank"} for hash `1A732667F3917C0F4AA98BB13011B9090C6F8065`.
{% capture code %}{% raw %}python3 hash-id.py 1A732667F3917C0F4AA98BB13011B9090C6F8065{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Possible Hashs:
[+] SHA-1
[+] MySQL5 - SHA-1(SHA-1($pass)){% endraw %}{% endcapture %} {% include code.html code=code %}

Crack the hash `1A732667F3917C0F4AA98BB13011B9090C6F8065` using `john`.
{% capture code %}{% raw %}.\run\john.exe --format=raw-sha1 --wordlist=wordlists\rockyou.txt hash\hash2.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
<password>         (?)
1g 0:00:00:00 DONE (2021-04-10 12:39) 8.403g/s 984403p/s 984403c/s 984403C/s karate2..kalvin1
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed{% endraw %}{% endcapture %} {% include code.html code=code %}


### Hash 3

Check the hash identifier and mode from [HashID](https://pypi.org/project/hashID/){:target="_blank"} for hash `D7F4D3CCEE7ACD3DD7FAD3AC2BE2AAE9C44F4E9B7FB802D73136D4C53920140A`.
{% capture code %}{% raw %}python3 hash-id.py D7F4D3CCEE7ACD3DD7FAD3AC2BE2AAE9C44F4E9B7FB802D73136D4C53920140A{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Possible Hashs:
[+] SHA-256
[+] Haval-256(SHA-1($pass)){% endraw %}{% endcapture %} {% include code.html code=code %}

Crack the hash `D7F4D3CCEE7ACD3DD7FAD3AC2BE2AAE9C44F4E9B7FB802D73136D4C53920140A` using `john`.
{% capture code %}{% raw %}.\run\john.exe --format=raw-sha256 --wordlist=wordlists\rockyou.txt hash\hash3.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<password>       (?)
1g 0:00:00:00 DONE (2021-04-10 12:42) 11.11g/s 1456Kp/s 1456Kc/s 1456KC/s 123456..kovacs
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed{% endraw %}{% endcapture %} {% include code.html code=code %}


### Hash 4

Check the hash identifier and mode from [HashID](https://pypi.org/project/hashID/){:target="_blank"} for hash `c5a60cc6bbba781c601c5402755ae1044bbf45b78d1183cbf2ca1c865b6c792cf3c6b87791344986c8a832a0f9ca8d0b4afd3d9421a149d57075e1b4e93f90bf`.
{% capture code %}{% raw %}python3 hash-id.py c5a60cc6bbba781c601c5402755ae1044bbf45b78d1183cbf2ca1c865b6c792cf3c6b87791344986c8a832a0f9ca8d0b4afd3d9421a149d57075e1b4e93f90bf{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Possible Hashs:
[+] SHA-512
[+] Whirlpool{% endraw %}{% endcapture %} {% include code.html code=code %}

Check the relevant formats to be used in `john`.
{% capture code %}{% raw %}.\run\john.exe --list=formats | findstr "whirlpool"{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}tc_sha512, tc_whirlpool, vdi, OpenVMS, vmx, VNC, vtp, wbb3, whirlpool,
whirlpool0, whirlpool1, wpapsk, wpapsk-pmk, xmpp-scram, xsha, xsha512, ZIP,{% endraw %}{% endcapture %} {% include code.html code=code %}

Crack the hash `c5a60cc6bbba781c601c5402755ae1044bbf45b78d1183cbf2ca1c865b6c792cf3c6b87791344986c8a832a0f9ca8d0b4afd3d9421a149d57075e1b4e93f90bf` using `john`.
{% capture code %}{% raw %}.\run\john.exe --format=whirlpool --wordlist=wordlists\rockyou.txt hash\hash4.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Using default input encoding: UTF-8
Loaded 1 password hash (whirlpool [WHIRLPOOL 32/64])
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<password>         (?)
1g 0:00:00:00 DONE (2021-04-10 12:48) 2.770g/s 1906Kp/s 1906Kc/s 1906KC/s davita1..blah2007
Use the "--show" option to display all of the cracked passwords reliably
Session completed{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 5 - Cracking Windows Authentication Hashes

Check the hash identifier and mode from `hashid` or [HashID](https://pypi.org/project/hashID/){:target="_blank"} for hash `5460C85BD858A11475115D2DD3A82333`.
{% capture code %}{% raw %}hashid -m 5460C85BD858A11475115D2DD3A82333{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Analyzing '5460C85BD858A11475115D2DD3A82333'
[+] MD2
[+] MD5 [Hashcat Mode: 0]
[+] MD4 [Hashcat Mode: 900]
[+] Double MD5 [Hashcat Mode: 2600]
[+] LM [Hashcat Mode: 3000]
[+] RIPEMD-128
[+] Haval-128
[+] Tiger-128
[+] Skein-256(128)
[+] Skein-512(128)
[+] Lotus Notes/Domino 5 [Hashcat Mode: 8600]
[+] Skype [Hashcat Mode: 23]
[+] Snefru-128
[+] NTLM [Hashcat Mode: 1000]
[+] Domain Cached Credentials [Hashcat Mode: 1100]
[+] Domain Cached Credentials 2 [Hashcat Mode: 2100]
[+] DNSSEC(NSEC3) [Hashcat Mode: 8300]
[+] RAdmin v2.x [Hashcat Mode: 9900]{% endraw %}{% endcapture %} {% include code.html code=code %}

Check the relevant formats to be used in `john`.
{% capture code %}{% raw %}.\run\john.exe --list=formats | findstr "ntlm"{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}mysql-sha1, mysql, net-ah, nethalflm, netlm, netlmv2, net-md5, netntlmv2,
netntlm, netntlm-naive, net-sha1, nk, notes, md5ns, nsec3, NT, o10glogon,
ntlmv2-opencl, o5logon-opencl, ODF-opencl, office-opencl,{% endraw %}{% endcapture %} {% include code.html code=code %}

Crack the hash `5460C85BD858A11475115D2DD3A82333` using `john`.
{% capture code %}{% raw %}.\run\john.exe --format=NT --wordlist=wordlists\rockyou.txt hash\ntlm.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
<password>         (?)
1g 0:00:00:00 DONE (2021-04-10 18:44) 9.345g/s 28710p/s 28710c/s 28710C/s skater1..dangerous
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 6 - Cracking /etc/shadow Hashes

Using `unshadow`, an inbuild utility with john, create hash input file using the entries in /etc/passwd and /etc/shadow. Complete files can be used or selected entries from them can be used.

An example to create hash input file.
{% capture code %}{% raw %}unshadow local_passwd local_shadow > unshadowed.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

The file contents will be similar to below.
{% capture code %}{% raw %}root:x:0:0::/root:/bin/bash
root:$6$Ha.d5nGupBm29pYr$yugXSk24ZljLTAZZagtGwpSQhb3F2DOJtnHrvk7HI2ma4GsuioHp8sm3LJiRJpKfIf7lZQ29qgtH17Q/JDpYM/:18576::::::{% endraw %}{% endcapture %} {% include code.html code=code %}

Crack the hash `$6$Ha.d5nGupBm29pYr$yugXSk24ZljLTAZZagtGwpSQhb3F2DOJtnHrvk7HI2ma4GsuioHp8sm3LJiRJpKfIf7lZQ29qgtH17Q/JDpYM/` using `john`.
{% capture code %}{% raw %}.\run\john.exe --format=sha512crypt --wordlist=wordlists\rockyou.txt hash\etchashes.txt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<password>             (root)
1g 0:00:00:00 DONE (2021-04-10 19:06) 1.280g/s 2622p/s 2622c/s 2622C/s kucing..lovers1
Use the "--show" option to display all of the cracked passwords reliably
Session completed{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 7 - Single Crack Mode

In this mode, John uses only the information provided in the username, to try and work out possible passwords heuristically, by slightly changing the letters and numbers contained within the username.


### Word Mangling

John builds it's own dictionary based on the information that it has been fed and uses a set of rules called "mangling rules" which define how it can mutate the word it started with to generate a wordlist based off of relevant factors for the target.


### Gecos

John can take information stored in GECOS records, the fields seperated by : in /etc/passwd files, such as full name and home directory name to add in to the wordlist it generates when cracking /etc/shadow hashes with single crack mode.


Prepend the file with username before hash.
{% capture code %}{% raw %}Joker:7bf6d9bb82bed1302f331fc6b816aada{% endraw %}{% endcapture %} {% include code.html code=code %}

Check the hash identifier and mode from [HashID](https://pypi.org/project/hashID/){:target="_blank"} for hash `7bf6d9bb82bed1302f331fc6b816aada`.
{% capture code %}{% raw %}python3 hash-id.py 7bf6d9bb82bed1302f331fc6b816aada{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username))){% endraw %}{% endcapture %} {% include code.html code=code %}

Crack the hash `7bf6d9bb82bed1302f331fc6b816aada` using `john`.
{% capture code %}{% raw %}.\run\john.exe --single --format=raw-md5 hash\hash7.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 2 candidates buffered for the current salt, minimum 24 needed for performance.
Warning: Only 21 candidates buffered for the current salt, minimum 24 needed for performance.
Warning: Only 5 candidates buffered for the current salt, minimum 24 needed for performance.
<password>            (Joker)
1g 0:00:00:00 DONE (2021-04-10 19:16) 10.98g/s 2153p/s 2153c/s 2153C/s j0ker..J0k3r
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 8 - Custom Rules

### References
- [John Custom Rules](https://www.openwall.com/john/doc/RULES.shtml){:target="_blank"}

The following are the rules definitions to be used.
- Az - Takes the word and appends it with the characters you define
- A0 - Takes the word and prepends it with the characters you define
- c - Capitalises the character positionally
- [0-9] - Will include numbers 0-9
- [0] - Will include only the number 0
- [A-z] - Will include both upper and lowercase
- [A-Z] - Will include only uppercase letters
- [a-z] - Will include only lowercase letters
- [a] - Will include only a
- [!£$%@] - Will include the symbols !£$%@

An example of custom rule.
{% capture code %}{% raw %}[List.Rules:PoloPassword]
cAz"[0-9] [!£$%@]"{% endraw %}{% endcapture %} {% include code.html code=code %}

The above example can be described as,
- c - Capitalise the first  letter
- Az - Append to the end of the word
- [0-9] - A number in the range 0-9
- [!£$%@] - Followed by a symbol


## Task 9 - Cracking Password Protected Zip Files

Using `zip2john`, an inbuild utility with john, create hash input file for the password protected `zip` file.
{% capture code %}{% raw %}.\run\zip2john.exe hash\secure.zip > hash\secure.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}ver 1.0 efh 5455 efh 7875 secure.zip/zippy/flag.txt PKZIP Encr: 2b chk, TS_chk, cmplen=38, decmplen=26, crc=849AB5A6{% endraw %}{% endcapture %} {% include code.html code=code %}

The file contents will be similar to below.
{% capture code %}{% raw %}secure.zip/zippy/flag.txt:$pkzip2$1*2*2*0*26*1a*849ab5a6*0*48*0*26*849a*b689*964fa5a31f8cefe8e6b3456b578d66a08489def78128450ccf07c28dfa6c197fd148f696e3a2*$/pkzip2$:zippy/flag.txt:secure.zip::secure.zip{% endraw %}{% endcapture %} {% include code.html code=code %}

Crack the zip file password using `john`.
{% capture code %}{% raw %}.\run\john.exe --wordlist=wordlists\rockyou.txt hash\secure.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<password>          (secure.zip/zippy/flag.txt)
1g 0:00:00:00 DONE (2021-04-10 22:41) 9.615g/s 156038p/s 156038c/s 156038C/s 123456..cocoliso
Use the "--show" option to display all of the cracked passwords reliably
Session completed{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 10 - Cracking Password Protected RAR Archive

Using `rar2john`, an inbuild utility with john, create hash input file for the password protected `rar` archive.
{% capture code %}{% raw %}.\run\rar2john.exe hash\secure.rar > hash\secure.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

The file contents will be similar to below.
{% capture code %}{% raw %}secure.rar:$rar5$16$b7b0ffc959b2bc55ffb712fc0293159b$15$4f7de6eb8d17078f4b3c0ce650de32ff$8$ebd10bb79dbfb9f8{% endraw %}{% endcapture %} {% include code.html code=code %}

Crack the rar archive password using `john`.
{% capture code %}{% raw %}.\run\john.exe --wordlist=wordlists\rockyou.txt hash\secure.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Warning: detected hash type "RAR5", but the string is also recognized as "RAR5-opencl"
Use the "--format=RAR5-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (RAR5 [PBKDF2-SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<password>         (secure.rar)
1g 0:00:00:00 DONE (2021-04-10 22:46) 1.262g/s 323.2p/s 323.2c/s 323.2C/s 123456..freedom
Use the "--show" option to display all of the cracked passwords reliably
Session completed{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 11 - Cracking SSH Keys with John

Using `ssh2john`, an inbuild utility with john, create hash input file for the password protected `id_rsa` ssh key.
{% capture code %}{% raw %}./run/ssh2john.py hash/idrsa.id_rsa > hash/idrsa.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

The file contents will be similar to below.
{% capture code %}{% raw %}hash/idrsa.id_rsa:$sshng$1$16$3A98F468854BB3836BF689310D864CE9$1200$08ca19b68bc606b07875701174131b9220d23ef968befc1230eeff0d7c0f904e6734765fe562e8671972e409091f32c80b754ab248976228a5f2c38e8ac63572d7452e75669aeda932275989ce4c077d43287ed227b8f9053e53f2b1c9bb9dfe876378a32e87e7be4e91a845ae8ee4073bf7ac5aad8414253c97cfb73b083107712907da8c704678f46d0b006f7a77b13a04305a988c8e17d83abd2449ed5c3defc8203d7c5f70cef3470b0bbe3fa5a2e957ac55a57ea08b1de4d3fa5436c6160a14b461ac7bc4a3052ddf858de657ecb210989507beb96f7219ac3c3790e89f3af71f7f61ebe23570284a482b1504b067fb1e03ed62201c6db71dab65e5f1577751ddb006fe14ceed4525965fce19f8141373094d1aedbb58cb903f58f6d80695be0382c31e61baaf366d4f2e722316e91ff4dcb3df15702008b5be3c0b2a81b3f452ef3257c425dd26119324b4de3652e90b91afd87ca2bc41c70abd0d97557d4037952b63c0a0d7c7ab6ed538c3d76bdf488683213e8d8e897ab51c4990b137d04e5044ccbf8cadbdce9eeec5e50f3d487b1f21e86a2b2785caedbf9503d2d8585b2138d82b35e70d1da03c9c574962cdb6e4d2de761a594ab8c082d88b43a027649012feb28b6a022c0ab49cf05e8b91e36bda935f188c1bb05925da2168dd15af917ba20a8532010892853da5cb1a8ff80cc5d3aa1dd3fe66543bf14d9b44d082261fd61976718bb5eea1d911ddb7fb0cc0505b39cec36ef7bd8e8d9d826eda5f7e1a5a51067ead2f78cf69f85de97be5a8f371174356788554b6bf134072b93bf6728ec26fe19c2485be9e7428208a66cc1e79329ac16f3034605c63550a424ed8cac39f965b6ffe83240c6709607eaef99b189100ef33e000b4195e07ec5c67bdaf2ca1acbd08327f0c4dcfae322883f7be964cb22393541e883c8c5b748237a900aab709b6286cea66a214a9fe4e3a1203f999fd995aa049767355e2658828c4a82d58ca15343f0abe6b2779e880ed2682b4730103a84a3410e6c822098d82b04d665b8bf98bc3b69cae0c8d8c9d140dc99056279d5f330bc439bfdceaf38a56fd1362ce78e96deb49a9f6756ec9b64eeba8f4725ec056ab206e37823d052d539d38016abf792858a169cbbe0f6f0d0049c6d49228833aa8ec10ede0c183ac737e54346949485e5ffc1bc3105e5686c8b1f6fb8cdb14949aa97b833757d02b970e96cb1281c472a5cb26cfa7cfda0be5bd45cf14d4bc28ccd2be4dd09c6a2ce0cf668035d2aa39a8345ea154543491436bf8f5e605d86e266d40227f48684e696a225877624ddddf0afe05d0aeec29ad28edb0f8cda0f341ddbbd454bd3c238d1c499effa6bf6f796dae0983182f36fae4781552cb8d9426fc57132c27a735c5365a5d355a4c4f21d5d7ed2ea11bb2ed856156390673545418f47359fd1092767f6dfb3321ee14a0043352fdbaa5cb0e75fde2ec5909c0533251f30bd56ad7e34a8a31b009b53c64e9f2de9fd57a0f561564e6a961158cc0b54fcfc43046d9641788ac5e25b89bdb7890c4e6532d1bfabd4d49ae7d3740506c4ecb6bc5cb6a12bc24ed2e0f913338c7dfa08ada66a6128e7de56794d1d2170d6324af0cd72bc8abcff177f0942d9df5d99d48c8f946fd856d9ccb424966835aa06c94996abcc169aef6f246bbbd7489ec026a{% endraw %}{% endcapture %} {% include code.html code=code %}

Crack the ssh key password using `john`.
{% capture code %}{% raw %}.\run\john.exe --wordlist=wordlists\rockyou.txt hash\idrsa.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Warning: detected hash type "SSH", but the string is also recognized as "ssh-opencl"
Use the "--format=ssh-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
<password>            (hash/idrsa.id_rsa)
Warning: Only 2 candidates left, minimum 8 needed for performance.
1g 0:00:00:33 DONE (2021-04-10 23:12) 0.02964g/s 425228p/s 425228c/s 425228C/sa6_123..♦*♥7¡Vamos!♥
Session completed{% endraw %}{% endcapture %} {% include code.html code=code %}

