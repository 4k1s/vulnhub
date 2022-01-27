# Attack on the box ""The Planets: Earth"

Target box: [click here](https://www.vulnhub.com/entry/the-planets-earth,755/)

OS: **Nix type*

File format: *.OVA*

Difficulty: *easy*

Goals: *Capture the user and root flag*

Description: 

Earth is an easy box though you will likely find it more challenging than "Mercury" in this series and on the harder side of easy.

---
### Introduction

First, we must find the IP of the target machine. In real world this is known beforehand or it can be found by an nslookup. Just *dig \<url\> A* returns the A record of the domain name. Here the machines are running in VirtualBox. Network configuration is "NAT network" for all machines (attacking machine and targets) with network CIDR set to **10.0.2.0/24**. Consequently, machine's IP is in the range of **10.0.2.0-255**. From our machine we can scan this range only for host discovery:

```
$ nmap 10.0.2.0-255 -sL | grep \(
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-27 02:42 EST
Nmap scan report for earth.local (10.0.2.7)
Nmap done: 256 IP addresses (0 hosts up) scanned in 1.70 seconds
```
-sL flag stands for Scan List. It just scans for which hosts are up for the IPs. The ""| grep \()" part is used to filter out the useless lines. If a host is up then its line while contain parentheses(right parenthesis can also do).Of course, backslash is for escaping.

As we can see, at IP 10.0.2.7 there is a host with name earth.local. This is our target. By the way, if we want to check for our IP address, because it belongs to our LAN we can do an 

```
$ ip a
```
and under the -enpxsx- we can check the *inet*. In our machine is 10.0.2.4, but in your machine should be some other IP.

Before we start, it will be a good idea to set the target's IP in a global variable. So we set it to TRG (target):

```
$ TRG=10.0.2.7
$ echo $TRG
10.0.2.7
```

Perfect. We are ready to start. As always, there are four basic "steps". Enumeration, Foothold, User access and finally root/admin access (or privileges escalation).

### Enumeration

Let's start with a basic port scan.

```
$ sudo nmap $TRG -sS
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-27 03:16 EST
Nmap scan report for earth.local (10.0.2.7)
Host is up (0.00048s latency).
Not shown: 997 filtered ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
MAC Address: 08:00:27:80:91:15 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 5.22 seconds

```

*sudo* is needed because flag -sS does a TCP SYN port scan, which needs root privileges. If you don't have root privileges(vary rare, as you usually fully own the attacking machine) you can port scan using the *-sT* flag. SYN port scan is faster though, as it does not attempt a complete TCP connection but sends raw packages(that's why it needs root privileges).

By default, 1000 ports were scanned. 3 open ports found, while 997 are filtered. This means that a firewall is running on the target machine. For these 997 filtered ports we don't know if a daemon is running at some of them or they are really closed. There are techniques to find out but better to start spending our time on the open ports first.

### Foothold


 