---
title: Writeup for TryHackMe room - Active Directory Basics
author: 4n3i5v74
date: 2021-03-21 00:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, AD]
pin: false
---


<div class="flex-container">
  <script src="https://tryhackme.com/badge/34685"></script>
</div>


## [Active Directory Basics](https://tryhackme.com/room/activedirectorybasics){:target="_blank"}

This room contains info about Windows Active Directory and tools to enumerate them.

For complete tryhackme path, refer the [link](https://4n3i5v74.github.io/posts/getting-started-with-cybersecurity-tryhackme/){:target="_blank"}


## Task 8 - Hands-On Lab

Use these links as references.
- [PowerView Source](https://github.com/PowerShellMafia/PowerSploit/){:target="_blank"}
- [SharpHound Source](https://github.com/BloodHoundAD/BloodHound){:target="_blank"}
- [PowerView Usage](https://github.com/PowerShellMafia/PowerSploit/){:target="_blank"}

Open `powershell` as admin user and execute the following to load a powershell shell with execution policy bypassed.
{% capture code %}{% raw %}powershell -ep bypass{% endraw %}{% endcapture %} {% include code.html code=code %}

The following are few example commands to retrieve information from domain members.
{% capture code %}{% raw %}get-netcomputer -fulldata | select operatingsystem
get-netuser | select cn
get-netuser | where {$_.name -match "SQL"}
get-netgroup{% endraw %}{% endcapture %} {% include code.html code=code %}

