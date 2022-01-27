# Attack on the box "The Planets: Earth"

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

It is time to start exploring the open ports and see what other information we can get to set a foot on the target. It will be wise to forget about ssh(port 22), as we don't have any credentials. Http and https are open for as though. Let's try to access http service using our browser. We type 'http://10.0.2.7' in our favorite browser but we get a 400 error code (but request). Another way is to use *wget* or *curl* to access the $TRG ip but the result will be, of course, the same. Not a good start.

Trying the same on https port (https://10.0.2.7) we get a Fedora Webserver Test Page, as it can be seen:

 ![](img/image1.png)

That means that a webserver is running(expected because of the open ports) and is misconfigured. It shouldn't show any kind of data to the public. That's good news for the bad guys(us, the red team). It is reasonable to assume that at least a virtual host exists. We are going to use *nmap* again with standard NSE Scripts (*-sC* flag). We also use the *-vv* flag to get more details:

```
$ nmap -p443 10.0.2.7 -sC -vv
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-27 04:14 EST
NSE: Loaded 121 scripts for scanning.
............
```

We don't provide the output here. The output contains an SSL certificate and other info about two domain names. Let's rerun the command without *-vv* flag.

```
$ nmap -p443 10.0.2.7 -sC
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-27 04:15 EST
Nmap scan report for earth.local (10.0.2.7)
Host is up (0.0012s latency).

PORT    STATE SERVICE
443/tcp open  https
|_http-title: Earth Secure Messaging
| ssl-cert: Subject: commonName=earth.local/stateOrProvinceName=Space
| Subject Alternative Name: DNS:earth.local, DNS:terratest.earth.local
| Not valid before: 2021-10-12T23:26:31
|_Not valid after:  2031-10-10T23:26:31
| tls-alpn: 
|_  http/1.1

Nmap done: 1 IP address (1 host up) scanned in 1.39 seconds

```

We have two domain names, "earth.local" and "terratest.earth.local". Obviously, these are temporal domain names and DNS records do not exist for them. An SSL certificate has been taken for them, so they meant to be used in the future in public. We can be almost sure that the web server has configured with two virtual hosts by using these domain names. Or one virtual host with a domain name and the other as an alias.
 
As there are no DNS records for these domains we can fool the browser by providing A records only for our machine. before a DNS lookup linux systems search the */etc/hosts* file. We can open it as root with an editor and add the following line:

```
10.0.2.7		earth.local	terratest.earth.local
```

Let's try again to browse the two domains. They both show the same webpage for http, while for https the subdomain (terratest.earth.local) shows a "Test site, please ignore." text message. Lets focus on http://earth.local:

![](img/image2.png)

