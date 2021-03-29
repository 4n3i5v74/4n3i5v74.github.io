---
title: Writeup for TryHackMe room - OHSINT
author: 4n3i5v74
date: 2020-12-24 23:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, ohsint]
pin: true
---


## [OHSINT](https://tryhackme.com/room/ohsint){:target="_blank"}

Download the image and read the embedded information in it.
{% capture code %}{% raw %}exiftool /data/WindowsXP.jpg{% endraw %}{% endcapture %} {% include code.html code=code %}
We see GPS coordinates, and user information from copyright.
{% capture code %}{% raw %}ExifTool Version Number         : 11.16
File Name                       : WindowsXP.jpg
Directory                       : /data
File Size                       : 229 kB
File Modification Date/Time     : 2020:12:22 02:27:01+05:30
File Access Date/Time           : 2020:12:22 02:27:22+05:30
File Inode Change Date/Time     : 2020:12:26 03:45:44+05:30
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
XMP Toolkit                     : Image::ExifTool 11.27
GPS Latitude                    : 54 deg 17' 41.27" N
GPS Longitude                   : 2 deg 15' 1.33" W
Copyright                       : OWoodflint
Image Width                     : 1920
Image Height                    : 1080
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
GPS Latitude Ref                : North
GPS Longitude Ref               : West
Image Size                      : 1920x1080
Megapixels                      : 2.1
GPS Position                    : 54 deg 17' 41.27" N, 2 deg 15' 1.33" W{% endraw %}{% endcapture %} {% include code.html code=code %}

A google search on owoodflint gives twitter, github and wordpress results in the top 3 search results.
- [Twitter](https://twitter.com/owoodflint?lang=en){:target="_blank"}
- [GitHub](https://github.com/OWoodfl1nt/people_finder){:target="_blank"}
- [Wordpress](https://oliverwoodflint.wordpress.com/author/owoodflint/){:target="_blank"}

![Google search result for OWoodflint!](/assets/img/tryhackme/ohsint/ohsint-1.JPG "Google search result for OWoodflint"){: width="600"}

The image in Twitter url is first flag.

![OWoodflint twitter image!](/assets/img/tryhackme/ohsint/ohsint-2.JPG "OWoodflint twitter image"){: width="400"}

The information in GitHub url shows a location, which is second flag, and a mail id, which is fourth flag. The source of this information is fifth flag.

![OWoodflint location mail source!](/assets/img/tryhackme/ohsint/ohsint-3.JPG "OWoodflint location mail source"){: width="600"}

The Wordpress url shows a holiday location, which is sixth flag.

![OWoodflint holiday location!](/assets/img/tryhackme/ohsint/ohsint-4.JPG "OWoodflint holiday location"){: width="300"}

The seventh flag is the most tricky part. Select all contents in the Wordpress url, which will reveal a hidden text, aka., the seventh flag.

![OWoodflint password!](/assets/img/tryhackme/ohsint/ohsint-5.JPG "OWoodflint password"){: width="250"}

To get third flag, check the remaining clue, the GPS coordinates, in the [link](https://wigle.net/).
As we got the MAC address from twitter, and location in GitHub, we can search for BSSID in the wigle url, and see if there is a result in location.

![OWoodflint BSSID location!](/assets/img/tryhackme/ohsint/ohsint-6.JPG "OWoodflint BSSID location"){: width="500"}

Zoom in fully to get the BSSID of the MAC address, which is the third flag.

![OWoodflint BSSID!](/assets/img/tryhackme/ohsint/ohsint-7.JPG "OWoodflint BSSID"){: width="500"}

