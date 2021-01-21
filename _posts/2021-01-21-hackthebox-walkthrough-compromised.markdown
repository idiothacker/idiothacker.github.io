---
layout: single
title: Compromised Walkthrough - Hack The Box
excerpt: "Compromised is a Hard rated Linux machine from Hack the Box. This machine was created to run like an already compromised machine. We will be challenged to thoroughly enumerate the system, looking for clues of how the previous attacker compromised the machine, and mimicking each step along the way. We will first find a backup of the website that includes credentials to an admin account to the LiteCart application. We are then able to upload a PHP command shell.  Using the command shell, we find database credentials. We then create a MySQL command shell to enumerate the MySQL database where we find that there is a user defined function that allows for executing commands on the machine. We use this function to add our SSH public key to the mysql user’s authorized_keys file, and we are then able to ssh to the machine as a user. From here we find additional credentials on the system for a more privileged user and are able to ssh using these credentials. We then find a modified package on the machine that contains a backdoor that we take advantage of to gain root access."
classes: wide
header:
  teaser: /assets/images/htb-compromised/compromised_logo.jpg
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - Hack the Box
  - Linux
  - CTF
tags:  
  - Hack the Box
  - Linux
  - PHP 7
  - Arbitrary Upload
  - LiteCart
  - MySQL
  - User Defined Functions
  - Ghidra
---

![](/assets/images/htb-compromised/compromised_logo.jpg)

## Summary
Compromised is a Hard rated Linux machine from Hack the Box. This machine was created to run like an already compromised machine. We will be challenged to thoroughly enumerate the system, looking for clues of how the previous attacker compromised the machine, and mimicking each step along the way. We will first find a backup of the website that includes credentials to an admin account to the LiteCart application. We are then able to upload a PHP command shell.  Using the command shell, we find database credentials. We then create a MySQL command shell to enumerate the MySQL database where we find that there is a user defined function that allows for executing commands on the machine. We use this function to add our SSH public key to the mysql user’s authorized_keys file, and we are then able to ssh to the machine as a user. From here we find additional credentials on the system for a more privileged user and are able to ssh using these credentials. We then find a modified package on the machine that contains a backdoor that we take advantage of to gain root access.

## Available January 23, 2021
The [Hack the Box](https://hackthebox.eu) machine Compromised will be retired on January 23, 2021. This is a placeholder link for my walkthrough. It will be updated the morning of Jan 23rd. Check back in then!
