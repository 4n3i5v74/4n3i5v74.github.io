---
title: CheatSheet - John The Ripper
author: 4n3i5v74
date: 2020-12-01 08:00:00 +0530
categories: [CheatSheet, John]
tags: [cheatsheet, john, johntheripper, pentest]
pin: true
---


## John Resources

- [John jumbo dev release](https://github.com/openwall/john-packages/releases/tag/jumbo-dev){:target="_blank"}
- [John binaries](https://download.openwall.net/pub/projects/john/contrib/){:target="_blank"}
- [John docs](https://nrupentheking.blogspot.com/search/label/Password%20Cracker){:target="_blank"}
- [John docs](https://reusablesec.blogspot.com/){:target="_blank"}
- [Password Analysis and Cracking Kit](https://thesprawl.org/projects/pack/){:target="_blank"}
- [Mangling Rules Generation](http://www.openwall.com/presentations/Passwords12-Mangling-Rules-Generation/)


## John Installation

{% capture code %}{% raw %}git clone https://github.com/openwall/john -b bleeding-jumbo /data/tools/john ; cd /data/tools/john/src/ ; ./configure && make -s clean && make -sj4 ; cd ~{% endraw %}{% endcapture %} {% include code.html code=code%}


## John Modes

- Wordlist mode (dictionary attack) - `john --wordlist=<wordlist> <hash>`
- Mangling rules mode - `john --wordlist=<wordlist> --rules:<rulename> <hash>`
- Incremental mode - `john --incremental <hash>`
- External mode - `john --external:<rulename> <hash>`
- Loopback mode (use .pot files) - `john --loopback <hash>`
- Mask mode - `john --mask=?1?1?1?1?1?1?1?1 -1=[A-Z] -min-len=8 <hash>`
- Markov mode - `calc_stat <wordlist> markovstats` `john -markov:200 -max-len:12 --mkv-stats=markovstats <hash>`
- Prince mode - `john --prince=<wordlist> <hash>`

Refer the [link](https://4n3i5v74.github.io/posts/tryhackme-john-the-ripper/){:target="_blank"} for more examples.


## CPU and GPU options

- List opencl devices - `john --list=opencl-devices`
- List formats supported by opencl - `john --list=formats --format=opencl`
- Use multiple CPU - `john hashes --wordlist:<wordlist> --rules:<rulename> --dev=2 --fork=4`
- Use multiple GPU - `john hashes --format:<openclformat> --wordlist:<wordlist> --rules:<rulename> --dev=0,1 --fork=2`


## Rules

- Single
- wordlist
- Extra
- Jumbo (Single, wordlist and Extra)
- KoreLogic
- All (Single, wordlist, Extra and KoreLogic)


## Incremental modes

- Lower (26 char)
- Alpha (52 char)
- Digits (10 char)
- Alnum (62 char)


## New rule

{% capture code %}{% raw %}[List.Rules:Tryout]
l                       [convert to lowercase]
u                       [convert to uppercase]
c                       [capitalize]
l r                     [lowercase and reverse (palindrome)]
l Az"2015"              [lowercase and append "2015" at end of word]
l A0"2015"              [lowercase and prepend "2015" at end of word]
d                       [duplicate]
A0"#"Az"#"              [append and prepend "#"]{% endraw %}{% endcapture %} {% include code.html code=code%}

- Display password candidates - `john --wordlist=<wordlist> --stdout --rules:Tryout`
- Generate password candidates - `john --wordlist=<wordlist> --stdout=8 --rules:Tryout`


## Other rules

{% capture code %}{% raw %}C     [lowercase first char, uppercase rest]
t     [toggle case of all chars]
TN    [toggle case of char in position N]
r     [reverse word - test123 -> 321tset]
d     [duplicate word - test123 -> test123test123]
f     [reflect word - test123 -> test123321tset]
{     [rotate word left - test123 -> est123t]
}     [rotate word right - test123 -> 3test12]
$X    [append word with X]
^X    [prefix word with X]
[     [remove first char]
]     [remove last char]
DN    [delete char in posision N]
xNM   [extract from position N till M chars]
iNX   [insert X in place of N and shift rest right]
oNX   [overwrite N with X]
S     [shift case - test123 -> TEST!@#]
V     [lowercase vowels, uppercase consonents - test123 -> TeST123]
R     [shift each char right, using keyboard key - test123 -> yrdy234]
L     [shift each char left, using keyboard key - test123 -> rwar012]
<N    [reject words unless less than length N]
>N    [reject words unless greater than length N]
N     [truncate to length N]{% endraw %}{% endcapture %} {% include code.html code=code%}


## New charset

{% capture code %}{% raw %}john --make-charset=set.char{% endraw %}{% endcapture %} {% include code.html code=code%}

Create `john.conf` with character set config.
{% capture code %}{% raw %}# Incremental modes
[Incremental:charset]
File = $JOHN/set.char
MinLen = 0
MaxLen = 30
CharCount = 80{% endraw %}{% endcapture %} {% include code.html code=code%}

{% capture code %}{% raw %}john --incremental=charset <hash>{% endraw %}{% endcapture %} {% include code.html code=code%}


## Wordlists

- Sort wordlist - `tr A-Z a-z < <wordlist> | sort -u > <new-wordlist>`
- Generate wordlist using POT - `cut -d: -f2 john.pot | sort -u > pot.dict`
- Generate candidate pwd for slow hash - `john --wordlist=<wordlist> --stdout --rules:Jumbo | unique -mem=25 <unique-wordlist>`


## External mode

- Create complex password list - [link](http://www.lanmaster53.com/2011/02/creating-complex-password-lists-with-john-the-ripper/){:target="_blank"}
- Generate wordlist according to complexity filter - `./john --wordlist=<wordlist> --stdout --external:<filter> > <filtered-wordlist>`
- Use adjacent keys on `keyboard` - `john --external:Keyboard <hash>`


## Misc Options

- Hidden options - `john --list=hidden-options`
- Display guesses - `john --incremental:Alpha -stdout -session=s1`
- Generate guesses with external programs - `crunch 1 6 abcdefg | ./john hashes -stdin -session=s1`
- Save session - `john hashes -session=name`
- Restore session - `john --restore:name`
- Show cracked passwords - `john hashes --pot=<pot> --show`


## Dictionaries

- Generate wordlist from wikipedia - `wget https://raw.githubusercontent.com/zombiesam/wikigen/master/wwg.py ; python wwg.py -u http://pt.wikipedia.org/wiki/Fernando_Pessoa -t 5 -o fernandopessoa -m3`
- Aspell dictionary - `apt-get install aspell-es` `aspell dump dicts` `aspell -d es dump master | aspell -l es expand | awk 1 RS=" |\n" > aspell.dic`

