---
title: Writeup for TryHackMe room - Web Fundamentals
author: 4n3i5v74
date: 2021-02-01 20:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, web]
pin: false
---


<div class="flex-container">
  <script src="https://tryhackme.com/badge/34685"></script>
</div>


## [Web Fundamentals](https://tryhackme.com/room/webfundamentals){:target="_blank"}

For complete tryhackme path, refer the [link](https://4n3i5v74.github.io/posts/getting-started-with-cybersecurity-tryhackme/){:target="_blank"}


## Task 5 - CTF

### References
- [Curl Reference](https://catonmat.net/cookbooks/curl){:target="_blank"}
- [HTTP Status Codes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status){:target="_blank"}


## Intro

The course is well designed and we would need less help. However, if some things are not clear or need some hints, proceed further.

There are four tasks,
- To use curl GET reqest
- To use curl POST request
- To use curl and get cookie
- To use curl and set cookie


### GET request

Deploy the machine and use curl to get the result.
{% capture code %}{% raw %}curl http://<ip>:8081{% endraw %}{% endcapture %} {% include code.html code=code %}

Check if the web page response is obtained. This would be similar to ,
{% capture code %}{% raw %}<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Page Title</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" type="text/css" media="screen" href="main.css">
    <script src="main.js"></script>
</head>
<body>
    <h1>Flags:</h1>
    <ul>
        <li>GET request. /ctf/get</li>
        <li>POST request. /ctf/post</li>
        <li>Get a cookie. /ctf/getcookie</li>
        <li>Set a cookie. /ctf/sendcookie</li>
    </ul>
</body>
</html>{% endraw %}{% endcapture %} {% include code.html code=code %}

Use the following curl command to get the flag.
{% capture code %}{% raw %}curl http://<ip>:8081/ctf/get{% endraw %}{% endcapture %} {% include code.html code=code %}


### POST request

Use the following curl command to send a POST request.
{% capture code %}{% raw %}curl --data "flag_please" http://<ip>:8081/ctf/post{% endraw %}{% endcapture %} {% include code.html code=code %}


### Get cookie

Use the following curl command to get cookie.
{% capture code %}{% raw %}curl -c cookie.txt http://<ip>:8081/ctf/getcookie{% endraw %}{% endcapture %} {% include code.html code=code %}

The downloaded cookie in cookie.txt contains the flag, similar to,
{% capture code %}{% raw %}# Netscape HTTP Cookie File
# https://curl.haxx.se/docs/http-cookies.html
# This file was generated by libcurl! Edit at your own risk.
<ip>     FALSE   /       FALSE   0       flag    <flag>{% endraw %}{% endcapture %} {% include code.html code=code %}


### Send cookie

Use the following curl command to send custom cookie.
{% capture code %}{% raw %}curl -b "flagpls=flagpls" http://<ip>:8081/ctf/sendcookie{% endraw %}{% endcapture %} {% include code.html code=code %}
The response contains the flag.

