---
title: Writeup for TryHackMe room - Hashing - Crypto 101
author: 4n3i5v74
date: 2021-01-01 00:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, crypto, hash]
pin: false
---


<div class="flex-container">
  <script src="https://tryhackme.com/badge/34685"></script>
</div>


## [Hashing - Crypto 101](https://tryhackme.com/room/hashingcrypto101){:target="_blank"}

This room contains info about hashing and methods to crack them.

For complete tryhackme path, refer the [link](https://4n3i5v74.github.io/posts/getting-started-with-cybersecurity-tryhackme/){:target="_blank"}


## Task 1 - Key Terms

- Ciphertext - The result of encrypting a plaintext, encrypted data.
- Cipher - A method of encrypting or decrypting data. Modern ciphers are cryptographic, but there are many non cryptographic ciphers like Caesar.
- Plaintext - Data before encryption or hashing, often text but it could be a photograph or other file instead.
- Encryption - Transforming data into ciphertext, using a cipher.
- Encoding - This is NOT a form of encryption, just a form of data representation like base64 or hexadecimal. Immediately reversible.
- Hash - A hash is the output of a hash function. Hashing can also be used as a verb, "to hash", meaning to produce the hash value of some data.
- Key - Some information that is needed to correctly decrypt the ciphertext and obtain the plaintext.
- Passphrase - Separate to the key, a passphrase is similar to a password and used to protect a key.
- Asymmetric encryption - Uses different keys to encrypt and decrypt.
- Symmetric encryption - Uses the same key to encrypt and decrypt.
- Brute force - Attacking cryptography by trying every different password or every different key.
- Cryptoanalysis - Attacking cryptography by finding a weakness in the underlying maths.


## Task 2 - What is hash function?

### References
- [MD5 collission](https://www.mscs.dal.ca/~selinger/md5collision/){:target="_blank"}
- [SHA1 collission](https://shattered.io/){:target="_blank"}

A hash function takes some input data of any size, and creates a summary or "digest" of data. It will be hard to predict what the output will be for any input and vice versa.

Hash collision is when 2 different inputs give the same output. In pigeonhole effect, there are set number of different output values for the hash function, but any size input can be given. As there are more inputs than outputs, some of the inputs must give the same output.

Default `MD5` hashing is `128 bits` or `16 bytes` long.

An `8-bit` output hash would have `2^8` or `256` possible inputs.


## Task 3 - Uses for hashing

Use `firefox` to open [Dcode](https://www.dcode.fr/hash-function){:target="_blank"} to crack the hash `5b31f93c09ad1d065c0491b764d04933`.

Alternatively the hash `5b31f93c09ad1d065c0491b764d04933` can also be cracked using offline tools. Use [hash-id.py](https://gitlab.com/kalilinux/packages/hash-identifier){:target="_blank"} or `hashid` to find possible hash algorithms.
{% capture code %}{% raw %}python3 hash-id.py 5b31f93c09ad1d065c0491b764d04933{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username))){% endraw %}{% endcapture %} {% include code.html code=code %}

Use `john` or `hashcat` to crack the hash.
{% capture code %}{% raw %}.\run\john.exe --format=raw-md5 --wordlist=wordlists\rockyou.txt hash\hash1.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
<password>          (?)
1g 0:00:00:00 DONE (2021-04-10 11:42) 8.130g/s 21853p/s 21853c/s 21853C/s skyblue..nugget
Session completed{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 4 - Recognising password hashes

### References
- [Python HashID](https://pypi.org/project/hashID/){:target="_blank"}
- [Hashcat hash examples](https://hashcat.net/wiki/doku.php?id=example_hashes){:target="_blank"}
- [Hashing Passwords](https://blog.michael.franzl.name/2016/09/09/hashing-passwords-sha512-stronger-than-bcrypt-rounds/){:target="_blank"}


## Task 5 - Password Cracking

### References
- [Hashnet hash examples](https://hashcat.net/wiki/doku.php?id=example_hashes){:target="_blank"}

Use `firefox` to check the hash identifier and mode from [Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes){:target="_blank"}.


### Hash 1

Check the hash identifier and mode from [Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes){:target="_blank"} for hash `$2a$06$7yoU3Ng8dHTXphAg913cyO6Bjs3K5lBnwq5FJyA6d01pMSrddr1ZG`.

Crack the hash `$2a$06$7yoU3Ng8dHTXphAg913cyO6Bjs3K5lBnwq5FJyA6d01pMSrddr1ZG` using `hashcat`.
{% capture code %}{% raw %}hashcat64.exe -m3200 -a0 -O "$2a$06$7yoU3Ng8dHTXphAg913cyO6Bjs3K5lBnwq5FJyA6d01pMSrddr1ZG" wordlists/rockyou.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}hashcat (v5.1.0) starting...

OpenCL Platform #1: NVIDIA Corporation
* Device #1: NVIDIA GeForce GTX 1050 Ti, 1024/4096 MB allocatable, 6MCU

OpenCL Platform #2: Intel(R) Corporation
* Device #2: Intel(R) UHD Graphics 630, skipped.
* Device #3: Intel(R) Core(TM) i5-8300H CPU @ 2.30GHz, skipped.

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Single-Hash
* Single-Salt

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Watchdog: Temperature abort trigger set to 90c

Dictionary cache built:
* Filename..: wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

$2a$06$7yoU3Ng8dHTXphAg913cyO6Bjs3K5lBnwq5FJyA6d01pMSrddr1ZG:<password>

Session..........: hashcat
Status...........: Cracked
Hash.Type........: bcrypt $2*$, Blowfish (Unix)
Hash.Target......: $2a$06$7yoU3Ng8dHTXphAg913cyO6Bjs3K5lBnwq5FJyA6d01p...ddr1ZG
Time.Started.....: Fri Apr 09 09:02:47 2021 (9 secs)
Time.Estimated...: Fri Apr 09 09:02:56 2021 (0 secs)
Guess.Base.......: File (wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     1707 H/s (3.27ms) @ Accel:4 Loops:2 Thr:8 Vec:1
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 14784/14344385 (0.10%)
Rejected.........: 0/14784 (0.00%)
Restore.Point....: 14592/14344385 (0.10%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:62-64
Candidates.#1....: chato -> terri
Hardware.Mon.#1..: Temp: 54c Util: 93% Core:1493MHz Mem:3504MHz Bus:16

Started: Fri Apr 09 09:02:19 2021
Stopped: Fri Apr 09 09:02:56 2021{% endraw %}{% endcapture %} {% include code.html code=code %}


### Hash 2

Check the hash identifier and mode from `hashid` for hash `9eb7ee7f551d2f0ac684981bd1f1e2fa4a37590199636753efe614d4db30e8e1`.
{% capture code %}{% raw %}hashid -m "9eb7ee7f551d2f0ac684981bd1f1e2fa4a37590199636753efe614d4db30e8e1"{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}Analyzing '9eb7ee7f551d2f0ac684981bd1f1e2fa4a37590199636753efe614d4db30e8e1'
[+] Snefru-256
[+] SHA-256 [Hashcat Mode: 1400]
[+] RIPEMD-256
[+] Haval-256
[+] GOST R 34.11-94 [Hashcat Mode: 6900]
[+] GOST CryptoPro S-Box
[+] SHA3-256 [Hashcat Mode: 5000]
[+] Skein-256
[+] Skein-512(256){% endraw %}{% endcapture %} {% include code.html code=code %}

Crack the hash `9eb7ee7f551d2f0ac684981bd1f1e2fa4a37590199636753efe614d4db30e8e1` using `hashcat`.
{% capture code %}{% raw %}hashcat64.exe -m1400 -a0 -O "9eb7ee7f551d2f0ac684981bd1f1e2fa4a37590199636753efe614d4db30e8e1" wordlists/rockyou.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}hashcat (v5.1.0) starting...

OpenCL Platform #1: NVIDIA Corporation
* Device #1: NVIDIA GeForce GTX 1050 Ti, 1024/4096 MB allocatable, 6MCU

OpenCL Platform #2: Intel(R) Corporation
* Device #2: Intel(R) UHD Graphics 630, skipped.
* Device #3: Intel(R) Core(TM) i5-8300H CPU @ 2.30GHz, skipped.

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Optimized-Kernel
* Zero-Byte
* Precompute-Init
* Precompute-Merkle-Demgard
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 31

Watchdog: Temperature abort trigger set to 90c

Dictionary cache hit:
* Filename..: wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

9eb7ee7f551d2f0ac684981bd1f1e2fa4a37590199636753efe614d4db30e8e1:<password>

Session..........: hashcat
Status...........: Cracked
Hash.Type........: SHA2-256
Hash.Target......: 9eb7ee7f551d2f0ac684981bd1f1e2fa4a37590199636753efe...30e8e1
Time.Started.....: Fri Apr 09 15:39:57 2021 (1 sec)
Time.Estimated...: Fri Apr 09 15:39:58 2021 (0 secs)
Guess.Base.......: File (wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 10805.9 kH/s (2.56ms) @ Accel:1024 Loops:1 Thr:256 Vec:1
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 1572911/14344385 (10.97%)
Rejected.........: 47/1572911 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 123456 -> lindakay2
Hardware.Mon.#1..: Temp: 46c Util: 19% Core:1493MHz Mem:3504MHz Bus:16

Started: Fri Apr 09 15:39:41 2021
Stopped: Fri Apr 09 15:39:59 2021{% endraw %}{% endcapture %} {% include code.html code=code %}


### Hash 4

Check the hash identifier and mode from [Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes){:target="_blank"} for hash `$6$GQXVvW4EuM$ehD6jWiMsfNorxy5SINsgdlxmAEl3.yif0/c3NqzGLa0P.S7KRDYjycw5bnYkF5ZtB8wQy8KnskuWQS3Yr1wQ0`.

Crack the hash `$6$GQXVvW4EuM$ehD6jWiMsfNorxy5SINsgdlxmAEl3.yif0/c3NqzGLa0P.S7KRDYjycw5bnYkF5ZtB8wQy8KnskuWQS3Yr1wQ0` using `hashcat`.
{% capture code %}{% raw %}hashcat64.exe -m1800 -a0 -O "$6$GQXVvW4EuM$ehD6jWiMsfNorxy5SINsgdlxmAEl3.yif0/c3NqzGLa0P.S7KRDYjycw5bnYkF5ZtB8wQy8KnskuWQS3Yr1wQ0" wordlists/rockyou.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}hashcat (v5.1.0) starting...

OpenCL Platform #1: NVIDIA Corporation
* Device #1: NVIDIA GeForce GTX 1050 Ti, 1024/4096 MB allocatable, 6MCU

OpenCL Platform #2: Intel(R) Corporation
* Device #2: Intel(R) UHD Graphics 630, skipped.
* Device #3: Intel(R) Core(TM) i5-8300H CPU @ 2.30GHz, skipped.

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Optimized-Kernel
* Zero-Byte
* Single-Hash
* Single-Salt
* Uses-64-Bit

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 16

Watchdog: Temperature abort trigger set to 90c

Dictionary cache hit:
* Filename..: wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$6$GQXVvW4EuM$ehD6jWiMsfNorxy5SINsgdlxmAEl3.yif0/c3NqzGLa0P.S7KRDYjycw5bnYkF5ZtB8wQy8KnskuWQS3Yr1wQ0:<password>

Session..........: hashcat
Status...........: Cracked
Hash.Type........: sha512crypt $6$, SHA512 (Unix)
Hash.Target......: $6$GQXVvW4EuM$ehD6jWiMsfNorxy5SINsgdlxmAEl3.yif0/c3...Yr1wQ0
Time.Started.....: Fri Apr 09 15:59:56 2021 (1 sec)
Time.Estimated...: Fri Apr 09 15:59:57 2021 (0 secs)
Guess.Base.......: File (wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    36548 H/s (8.21ms) @ Accel:128 Loops:64 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 24582/14344385 (0.17%)
Rejected.........: 6/24582 (0.02%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4992-5000
Candidates.#1....: 123456 -> 240991
Hardware.Mon.#1..: Temp: 53c Util: 98% Core:1493MHz Mem:3504MHz Bus:16

Started: Fri Apr 09 15:59:36 2021
Stopped: Fri Apr 09 15:59:59 2021{% endraw %}{% endcapture %} {% include code.html code=code %}


### Hash 4

Use `firefox` to open the url [Dcode](https://www.dcode.fr/hash-function){:target="_blank"} to crack the hash `b6b0d451bbf6fed658659a9e7e5598fe`


## Task 6 - Hashing for integrity checking

HMAC is a method of using a cryptographic hashing function to verify the authenticity and integrity of data. A HMAC can be used to ensure that the person who created the HMAC is who they say they are (authenticity), and that the message hasn’t been modified or corrupted (integrity). They use a secret key, and a hashing algorithm in order to produce a hash.

