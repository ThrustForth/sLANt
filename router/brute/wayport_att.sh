# #!/bin/bash
# 
# 
# # Wayport_access ATT
# 
# # Nmap 6.25 scan initiated Tue Dec 18 17:54:54 2012 as: nmap -A -Pn -oN /tmp/menu/scans/192.168.5.1 192.168.5.1


# Nmap scan report for 192.168.5.1
# Host is up (0.0035s latency).
# Not shown: 985 filtered ports
# PORT     STATE  SERVICE     VERSION
# 22/tcp   open   ssh         OpenSSH 5.1p1 Debian 5 (protocol 2.0)
# | ssh-hostkey: 1024 07:ef:90:bd:d9:2e:94:2f:23:62:7e:3e:6f:d2:7b:85 (DSA)
# |_2048 e9:3c:a3:29:6d:b5:28:43:31:19:31:92:70:ca:6d:8a (RSA)
# 53/tcp   open   domain      ISC BIND Up oh.
# | dns-nsid: 
# |_  bind.version: Up oh.
# 80/tcp   open   http-proxy  Squid http proxy 2.7.STABLE3
# |_http-methods: No Allow or Public header in OPTIONS response (status code 404)
# |_http-open-proxy: Proxy might be redirecting requests
# | http-robots.txt: 1 disallowed entry 
# |_/
# |_http-title: Site doesn't have a title (text/html; charset=UTF-8).
# 139/tcp  closed netbios-ssn
# 443/tcp  open   ssl/http    AOLserver httpd 4.5.0
# |_http-methods: No Allow or Public header in OPTIONS response (status code 404)
# | http-robots.txt: 1 disallowed entry 
# |_/
# |_http-title: Site doesn't have a title (text/html; charset=UTF-8).
# | ssl-cert: Subject: commonName=nmd.wayport.net/organizationName=AT&T Services, Inc./stateOrProvinceName=Texas/countryName=US
# | Not valid before: 2011-05-05T15:47:11+00:00
# |_Not valid after:  2013-05-04T15:47:11+00:00
# |_ssl-date: 2012-12-19T01:55:17+00:00; 0s from local time.
# |_sslv2: server still supports SSLv2
# 444/tcp  open   ssl/http    AOLserver httpd 4.5.0
# |_http-methods: No Allow or Public header in OPTIONS response (status code 404)
# | http-robots.txt: 1 disallowed entry 
# |_/
# |_http-title: Site doesn't have a title (text/html; charset=UTF-8).
# | ssl-cert: Subject: commonName=nmd.mcd01353.sjc.wayport.net/organizationName=ATT Services Inc/countryName=US
# | Not valid before: 2012-12-14T02:51:08+00:00
# |_Not valid after:  2012-12-24T02:51:08+00:00
# |_ssl-date: 2012-12-19T01:55:18+00:00; -1s from local time.
# |_sslv2: server still supports SSLv2
# 544/tcp  open   kshell      Solaris kerberised rsh
# 2105/tcp open   klogin      Kerberized rlogin
# 3128/tcp open   http-proxy  Squid http proxy 2.7.STABLE3
# |_http-methods: No Allow or Public header in OPTIONS response (status code 504)
# |_http-open-proxy: Proxy might be redirecting requests
# |_http-title: ERROR: The requested URL could not be retrieved
# 8000/tcp open   http-proxy  Squid http proxy 2.7.STABLE3
# |_http-methods: No Allow or Public header in OPTIONS response (status code 504)
# |_http-title: ERROR: The requested URL could not be retrieved
# 8002/tcp open   http-proxy  Squid http proxy 2.7.STABLE3
# |_http-methods: No Allow or Public header in OPTIONS response (status code 504)
# |_http-open-proxy: Proxy might be redirecting requests
# |_http-title: ERROR: The requested URL could not be retrieved
# 8080/tcp open   http-proxy  Squid http proxy 2.7.STABLE3
# |_http-methods: No Allow or Public header in OPTIONS response (status code 504)
# |_http-open-proxy: Proxy might be redirecting requests
# |_http-title: ERROR: The requested URL could not be retrieved
# 8084/tcp open   http-proxy  Squid http proxy 2.7.STABLE3
# |_http-methods: No Allow or Public header in OPTIONS response (status code 504)
# |_http-open-proxy: Proxy might be redirecting requests
# |_http-title: ERROR: The requested URL could not be retrieved
# 8086/tcp open   http-proxy  Squid http proxy 2.7.STABLE3
# |_http-methods: No Allow or Public header in OPTIONS response (status code 400)
# | http-open-proxy: Potentially OPEN proxy.
# |_Methods supported:  GET HEAD
# |_http-title: ERROR: The requested URL could not be retrieved
# 8088/tcp open   http-proxy  Squid http proxy 2.7.STABLE3
# |_http-methods: No Allow or Public header in OPTIONS response (status code 504)
# |_http-open-proxy: Proxy might be redirecting requests
# |_http-title: ERROR: The requested URL could not be retrieved
# MAC Address: 00:90:FB:37:87:B6 (Portwell)
# Device type: general purpose
# Running: Linux 2.6.X
# OS CPE: cpe:/o:linux:linux_kernel:2.6
# OS details: Linux 2.6.17 - 2.6.36
# Network Distance: 1 hop
# Service Info: OSs: Linux, Solaris; CPE: cpe:/o:linux:linux_kernel, cpe:/o:sun:sunos
# 
# TRACEROUTE
# HOP RTT     ADDRESS
# 1   3.48 ms 192.168.5.1
# 
# OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
# # Nmap done at Tue Dec 18 17:55:39 2012 -- 1 IP address (1 host up) scanned in 45.48 seconds
# [1]+  Done                    kate default_pass_list1
