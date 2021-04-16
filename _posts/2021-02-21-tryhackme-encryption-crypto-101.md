---
title: Writeup for TryHackMe room - Encryption - Crypto 101
author: 4n3i5v74
date: 2021-02-21 00:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, crypto, encrypt]
pin: false
---


<div class="flex-container">
  <script src="https://tryhackme.com/badge/34685"></script>
</div>


## [Encryption - Crypto 101](https://tryhackme.com/room/encryptioncrypto101){:target="_blank"}

This room contains info about encryption and methods to crack them.

For complete tryhackme path, refer the [link](https://4n3i5v74.github.io/posts/getting-started-with-cybersecurity-tryhackme/){:target="_blank"}


## Task 2 - Key terms

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


## Task3 - Why is Encryption important?

Use these links as references.
- [PCI DSS Standard](https://www.pcisecuritystandards.org/documents/PCI_DSS_for_Large_Organizations_v1.pdf){:target="_blank"}


## Task 4 - Crucial Crypto Maths

Crypto algorithms use `Modulo operator - %` for calculations. The non-zero outputs of modulo operators are taken for outputs, as seen below.
{% capture code %}{% raw %}30 % 5 - 0
25 % 7 - 4{% endraw %}{% endcapture %} {% include code.html code=code %}


* Task 5 - Types of Encryption

Use these links as references.
- [DES Standard](https://en.wikipedia.org/wiki/Data_Encryption_Standard){:target="_blank"}


* Task 6 - Rivest Shamir Adleman

Use these links as references.
- [RSA CTF Tool](https://github.com/Ganapati/RsaCtfTool){:target="_blank"}
- [RSA Tool](https://github.com/ius/rsatool){:target="_blank"}
- [RSA Encryption](https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/){:target="_blank"}


The `RSA` algorithm is mainly dependent on using two prime numbers to generate public and private keys for encrypting and decrypting the data. The difficulty in cracking the algorithm is due to the fact that the prime numbers cannot be correctly calculated in reverse with just the public and private keys.

Given a set of prime numbers, `p = 11` and `q = 13`, the value of n and phi can be determined as, `n = ( p * q )` and `phi = ( p - 1 ) * ( q - 1 )`.

To calculate value of `e`, `GCD` calculation is done between `n and phi` and `e`. The resulting value should be `1`. Any resulting value can be taken as value of `e`.

Similarly, to calculate value of `d`, calculation is done like `d * e % phi = 1`. Any resulting value can be taken as value of `d`.

Public key can be calculated as `(e, phi)` and private key can be calculated as `(d, phi)`.

Encrypted message can be generated using `(ascii character) ** e % phi`. And the message can be decrypted using `(encrypted character) ** d % phi`

The word `Hello` can be encrypted as `019 062 004 004 045` and decrypted as `072 101 108 108 111`, when the following values are chosen.
{% capture code %}{% raw %}p = 11
q = 13
n = 143
phi = 120
e = 7
d = 223
public key = (7, 143)
private key = (223, 143){% endraw %}{% endcapture %} {% include code.html code=code %}

A sample code to demonstrate encoded and decoded message can be as below.
{% capture code %}{% raw %}import random

def gcd( a, b ):
  if b == 0:
    return a
return gcd( b, a%b )

def prime_finder():
  test_number = random.randrange( 10, 31 )
  for i in range( 2, test_number ):
    if test_number % i == 0:
    return prime_finder()
  return test_number

p = prime_finder()
q = prime_finder()
n = p * q
phi = ( p-1 ) * ( q-1 )

pub_keys = []
for i in range( 2, phi ):
  if gcd( i, phi ) == 1 and gcd( i, n ) == 1:
    pub_keys.append( i )

e = random.choice( pub_keys )
del( pub_keys )

priv_keys = []
i = 2
while len( priv_keys ) < 10:
  if i * e % phi == 1:
    priv_keys.append( i )
  i += 1

while True:
a = random.choice( priv_keys )
  if len( str( a ) ) == len( str( phi ) ) and a <= ( phi * 2 ):
    d = a
    break
del( priv_keys )

print( f"Value of p: {p}\nValue of q: {q}\nValue of n: {n}\nValue of phi: {phi}\nValue of e: {e}\nValue of d: {d}\nPublic Key: ({e}, {n}\nPrivate Key: ({d}, {n})\n" )

hel = [ "072", "101", "108", "108", "111" ]
ehel = []
dhel = []
res = []

for char in hel:
  res = ( int( char ) ** e ) % phi
  ehel.append( '{:03}'.format( res ) )
  emsg = " ".join( map( str, ehel ) )

res = []
for char in ehel:
  res = ( int ( char ) ** d ) % phi
  dhel.append( '{:03}'.format( res ) )
  dmsg = " ".join( map( str, dhel ) )

print( f'Encrypted message for "Hello" is "{emsg}"\n' )
print( f'Decrypted message for "Hello" is "{dmsg}"\n' ){% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 7 - Establishing Keys Using Asymmetric Cryptography

Use these links as references.
- [How HTTPS works](https://robertheaton.com/2014/03/27/how-does-https-actually-work/){:target="_blank"}


## Task 9 - SSH Authentication

Using `ssh2john`, an inbuild utility with john, create hash input file for the password protected `id_rsa` ssh key.
{% capture code %}{% raw %}./run/ssh2john.py hash/idrsa.id_rsa > hash/idrsa.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

The file contents will be similar to below.
{% capture code %}{% raw %}idrsa:$sshng$1$16$0B5AB4FEB69AFB92B2100435B42B7949$1200$8dce3420285b19a7469a642278a7afab0ab40e28c865ce93fef1351bae5499df5fbf04ddf510e5e407246e4221876b3fbb93931a5276281182b9baf38e0c38a56548f30e7781c77e2bf5940ad9f77265102ab328bb4c6f7fd06e9a3153191dfcddcd9672256608a5bff044fbf33901849aa2c3464e24bb31d6d65160df61848952a79ce660a97b3123fa539754a0e5ffbfba796c98c17b4ca45eeeee1e1c7a45412e26fef9ba8ed48a15c2b60e23a5a525ee2451e03c85145d03b7129740b7ec3babda2f012f1ad21ea8c9ccae7e8eaf95e58fe73159db31785f838de9d960d3d2a528abddad0337490caa73565042ff8c5dc672d2e58402e3449cf0500b0e467300220cee35b528e718eb25fdc7d265042d3dbbe39ed52a445bdd78ad4a9462b374f6ce87c1bd28f1154b52c59db6028187c22cafa5b02eabe27f9a41733a35b6cfc73d83c65febafe8e7568d15b5a5a3340472794a2b6da5cff593649b35299ede7e8a2294ce5812bb5bc9396cc4ae5525620f4e83442c7e181317082e5fd93b29773dd7203e22947b960b2fedbd089ffb88793533dcf195281207e05ada2d284dc69b475e7d561a47d43470d490ec9d847d820eb9db7943dcf133350b6e8b6513ed2deeca6a5105eb496170fd2367b3637e7375891a483511168fe1f3292bcd64e252682865e7da1f1f06ae261a62a0155d3a932cc1976f45c1feaaf183ad86c7ce91795fe45395a73268d3c0e228e24d025c997a936fcb27bb05992ff4b23e050edaaae748b14a80c4ff3145f75436100fc840d107eb97e3da3b8114879e373053f8c4431ffc6feecd167f29a75152ad2e09b8bcaf4eaf92ae7155684c9175e32fe2141b67681c37fa41e791bd71872d49ea52bdea6f54ae6c41eb539ad2ed0c7dedf525ee20460a193a70501d9bc18f42347a4dd62d94e9cac504abb02b7a294efb7e1946014de9051d988c3e23fffcf00f4f5beb3b191f9d01557079cb45e992199d13770060e53f09389caa062cfc675aba02c693ef2c4326a1443aef1987e4c8fa10e11e6d2995faf1f8aa991efffcacea28967f24eabac5467e702d3a2e07a4c56f67801870f7cdb34d9d80116d6ce26b3cfbba9b06d06957911b6c13e37b879593af0c3cb29d2f5a388966876b0a26cadd94e79d97868f9464df6cd67433748f3dabbe5e9ac0eb6dacdfd0cc4219cbbf3bb0fe87fce5b907611bcd1e91a64b1cdab3f26b89f70397e5ddd58e921db7ad69871a6705170b58573eaca996d6cb987210e4d1ea2e098978525be38d8b0717671d651abea0521768a03c1028570a78514727812d7d17946cef6aaca0dddd1e5885f0f7feacfe7a3f70911a6f422f855bac2fd23105114898fe44b532992d841a51e08111be2caa66ab30aa3e89cd99177a53271e9400c79944c2406d605a084875c8b4730f108e2a2cce6251bb4fc27a6f3afd03c289745fb17630a8b0f520ba770ca1455c63ad1db7b21272fc9a5d25fadfdf23a7b021f6d8069e9ca8631dd0e81b182521e7b9efc4632643ac123c1bf8e2ce84576ae0cfc24730d051705bd68958d34a232b11742bce05d2db83029bd631913392fc565e6d8accedf1f9c2ba90c48a773bcc627f99ab1a44897280c2d945a0d8a1270206515dd2fa08f8c34a4150a0ba35ff0d3dbc2c21cd00e09f774a0741d28534eec64ea3{% endraw %}{% endcapture %} {% include code.html code=code %}

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
<password>        (idrsa)
Warning: Only 2 candidates left, minimum 8 needed for performance.
1g 0:00:00:38 DONE (2021-04-11 18:27) 0.02581g/s 370299p/s 370299c/s 370299C/sa6_123..♦*♥7¡Vamos!♥
Session completed{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 10 - Explaining Diffie Hellman Key Exchange

Use these links as references.
- [Diffie Hellman Algorithm working](https://www.youtube.com/watch?v=NmM9HA2MQGI){:target="_blank"}


## Task 11 - PGP, GPG and AES

Use these links as references.
- [GPG Wiki](https://gnupg.org/){:target="_blank"}
- [GPG Usage](https://www.gnupg.org/gph/de/manual/r1023.html){:target="_blank"}
- [GPG Working](https://www.youtube.com/watch?v=O4xNJsjtN6E){:target="_blank"}


PGP stands for Pretty Good Privacy. It’s a software that implements encryption for encrypting files, performing digital signing and more.

GnuPG or GPG is an Open Source implementation of PGP from the GNU project. This passphrase can be cracked using gpg2john from jumbo john.


Using `gpg` tool, import the key.
{% capture code %}{% raw %}gpg --import tryhackme.key{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}gpg: /root/.gnupg/trustdb.gpg: trustdb created
gpg: key FFA4B5252BAEB2E6: public key "TryHackMe (Example Key)" imported
gpg: key FFA4B5252BAEB2E6: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1{% endraw %}{% endcapture %} {% include code.html code=code %}

Decode the file.
{% capture code %}{% raw %}gpg message.gpg{% endraw %}{% endcapture %} {% include code.html code=code %}

An output similar to below will be obtained.
{% capture code %}{% raw %}gpg: WARNING: no command supplied.  Trying to guess what you mean ...
gpg: encrypted with 1024-bit RSA key, ID 2A0A5FDC5081B1C5, created 2020-06-30
      "TryHackMe (Example Key)"{% endraw %}{% endcapture %} {% include code.html code=code %}

Read the decoded file `message` to get the `flag`.


* Task 12 - The Future - Quantum Computers and Encryption

Use these links as references.
- [Quantum Computing Reference](https://doi.org/10.6028/NIST.IR.8105){:target="_blank"}

