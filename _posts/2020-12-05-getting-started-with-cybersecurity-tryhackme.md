---
title: Getting Started with Cybersecurity with TryHackMe
author: 4n3i5v74
date: 2020-12-05 00:00:00 +0530
toc: true
categories: [TryHackMe, CyberSecurity]
tags: [tryhackme, ctf, cybersecurity, beginning]
pin: true
---


<div class="flex-container">
  <script src="https://tryhackme.com/badge/34685"></script>
</div>

<div>
  <h2 id="introduction">Introduction</h2>

  <p>This post is a good place to start with CyberSecurity. There is an existing path available at <a href="https://blog.tryhackme.com/free_path/" target="_blank">TryHackMe Free Path</a>. I enhanced the list and this can be used to start learning about CyberSecurity, with very minimal knowledge on IT.</p>

    {% assign links_grouped = site.data.links.tryhackme | sort: 'order' | group_by: 'category' %}
    {% for category in links_grouped %}
    <h2 id="{{ category.name | slugify }}">{{ category.name }}</h2>

    <div class="flex-container">

      {% for link in category.items | sort: 'suborder' %}
      <div>
        <p>{{ link.title | markdownify }}</p>
        <hr class="flex-hr">
        <a href="{{ link.url }}" target="_blank">{{ link.description | markdownify }}</a>
      </div>
      {% endfor %}

    </div>

    {% endfor %}

</div>

