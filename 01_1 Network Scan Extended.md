
```

nmap -sV -sC -oA auenland 10.0.68.0-255 --open --min-rate=300 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-10 17:21 EST
Stats: 0:02:32 elapsed; 0 hosts completed (64 up), 64 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 32.11% done; ETC: 17:28 (0:04:45 remaining)
Stats: 0:02:32 elapsed; 0 hosts completed (64 up), 64 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 32.15% done; ETC: 17:28 (0:04:47 remaining)
Nmap scan report for 10.0.68.1
Host is up (0.051s latency).
Not shown: 998 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9 (protocol 2.0)
| ssh-hostkey: 
|   256 1120e98ce3f0d615e0c079581bdad48f (ECDSA)
|_  256 1012d346d5bc82ff5c6c387c1566de0e (ED25519)
80/tcp open  http    OPNsense
|_http-server-header: OPNsense
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 301 Moved Permanently
|     Location: https:///nice%20ports%2C/Trinity.txt.bak
|     Content-Length: 0
|     Connection: close
|     Date: Fri, 10 Nov 2023 22:28:56 GMT
|     Server: OPNsense
|   GenericLines: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/html
|     Content-Length: 345
|     Connection: close
|     Date: Fri, 10 Nov 2023 22:28:56 GMT
|     Server: OPNsense
|     <?xml version="1.0" encoding="iso-8859-1"?>
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
|     "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
|     <head>
|     <title>400 Bad Request</title>
|     </head>
|     <body>
|     <h1>400 Bad Request</h1>
|     </body>
|     </html>
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 301 Moved Permanently
|     Location: https:///
|     Content-Length: 0
|     Connection: close
|     Date: Fri, 10 Nov 2023 22:28:51 GMT
|     Server: OPNsense
|   RTSPRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/html
|     Content-Length: 345
|     Connection: close
|     Date: Fri, 10 Nov 2023 22:28:51 GMT
|     Server: OPNsense
|     <?xml version="1.0" encoding="iso-8859-1"?>
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
|     "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
|     <head>
|     <title>400 Bad Request</title>
|     </head>
|     <body>
|     <h1>400 Bad Request</h1>
|     </body>
|_    </html>
|_http-title: Did not follow redirect to https://10.0.68.1/
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.93%I=7%D=11/10%Time=654EAEA3%P=x86_64-pc-linux-gnu%r(Get
SF:Request,94,"HTTP/1\.0\x20301\x20Moved\x20Permanently\r\nLocation:\x20ht
SF:tps:///\r\nContent-Length:\x200\r\nConnection:\x20close\r\nDate:\x20Fri
SF:,\x2010\x20Nov\x202023\x2022:28:51\x20GMT\r\nServer:\x20OPNsense\r\n\r\
SF:n")%r(HTTPOptions,94,"HTTP/1\.0\x20301\x20Moved\x20Permanently\r\nLocat
SF:ion:\x20https:///\r\nContent-Length:\x200\r\nConnection:\x20close\r\nDa
SF:te:\x20Fri,\x2010\x20Nov\x202023\x2022:28:51\x20GMT\r\nServer:\x20OPNse
SF:nse\r\n\r\n")%r(RTSPRequest,1ED,"HTTP/1\.0\x20400\x20Bad\x20Request\r\n
SF:Content-Type:\x20text/html\r\nContent-Length:\x20345\r\nConnection:\x20
SF:close\r\nDate:\x20Fri,\x2010\x20Nov\x202023\x2022:28:51\x20GMT\r\nServe
SF:r:\x20OPNsense\r\n\r\n<\?xml\x20version=\"1\.0\"\x20encoding=\"iso-8859
SF:-1\"\?>\n<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\
SF:x20Transitional//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\"http://www
SF:\.w3\.org/TR/xhtml1/DTD/xhtml1-transitional\.dtd\">\n<html\x20xmlns=\"h
SF:ttp://www\.w3\.org/1999/xhtml\"\x20xml:lang=\"en\"\x20lang=\"en\">\n\x2
SF:0<head>\n\x20\x20<title>400\x20Bad\x20Request</title>\n\x20</head>\n\x2
SF:0<body>\n\x20\x20<h1>400\x20Bad\x20Request</h1>\n\x20</body>\n</html>\n
SF:")%r(FourOhFourRequest,B3,"HTTP/1\.0\x20301\x20Moved\x20Permanently\r\n
SF:Location:\x20https:///nice%20ports%2C/Trinity\.txt\.bak\r\nContent-Leng
SF:th:\x200\r\nConnection:\x20close\r\nDate:\x20Fri,\x2010\x20Nov\x202023\
SF:x2022:28:56\x20GMT\r\nServer:\x20OPNsense\r\n\r\n")%r(GenericLines,1ED,
SF:"HTTP/1\.0\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\nCo
SF:ntent-Length:\x20345\r\nConnection:\x20close\r\nDate:\x20Fri,\x2010\x20
SF:Nov\x202023\x2022:28:56\x20GMT\r\nServer:\x20OPNsense\r\n\r\n<\?xml\x20
SF:version=\"1\.0\"\x20encoding=\"iso-8859-1\"\?>\n<!DOCTYPE\x20html\x20PU
SF:BLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20Transitional//EN\"\n\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-t
SF:ransitional\.dtd\">\n<html\x20xmlns=\"http://www\.w3\.org/1999/xhtml\"\
SF:x20xml:lang=\"en\"\x20lang=\"en\">\n\x20<head>\n\x20\x20<title>400\x20B
SF:ad\x20Request</title>\n\x20</head>\n\x20<body>\n\x20\x20<h1>400\x20Bad\
SF:x20Request</h1>\n\x20</body>\n</html>\n");
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

Nmap scan report for 10.0.68.54
Host is up (0.18s latency).
Not shown: 740 filtered tcp ports (no-response), 258 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 843dcbd9be71d74c29c92508dfb24de2 (RSA)
|   256 c28cab84dfa3573c9bf17b59eb0846bc (ECDSA)
|_  256 58219beb4c40f4eaa88eec818f275a4a (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/
| http-title: Login :: Damn Vulnerable Web Application (DVWA) v1.10 *Develop...
|_Requested resource was login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 10.0.68.100
Host is up (0.0048s latency).
Not shown: 682 filtered tcp ports (no-response), 316 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 df05e57e6628ae2dabe147e1f9a239ba (RSA)
|   256 eb99133c87ef0036853d93fe7d7bafdc (ECDSA)
|_  256 a69567a45808e2ef04606394b90ef355 (ED25519)
80/tcp open  http    Apache httpd 2.4.46 ((Ubuntu))
|_http-server-header: Apache/2.4.46 (Ubuntu)
|_http-title: Tobolds Pfeifenkrautshop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 10.0.68.101
Host is up (0.28s latency).
Not shown: 958 filtered tcp ports (no-response), 40 filtered tcp ports (host-unreach)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 99bd85b29d5f5a0182c072ed2e783705 (RSA)
|   256 12bf193872fa652aa8680679d42c3686 (ECDSA)
|_  256 3d635b5e10eac16488659515b81c0f3a (ED25519)
80/tcp open  http    Apache httpd (PHP 7.4.6)
|_http-server-header: Apache
|_http-title: Pedik\xC3\xBCre-Salon Stolzf\xC3\xBC\xC3\x9Fe \xE2\x80\x94 Home

Nmap scan report for 10.0.68.102
Host is up (0.0038s latency).
Not shown: 672 filtered tcp ports (no-response), 326 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 c16a4bea069895ad7bbd0880804fb228 (RSA)
|   256 074f466e24120eef6c06dc5de912eeaa (ECDSA)
|_  256 d9da4738b081896840bf3cdb10afc016 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.38 (Debian)
| http-robots.txt: 1 disallowed entry 
|_/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 10.0.68.105
Host is up (0.0047s latency).
Not shown: 690 filtered tcp ports (no-response), 308 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 31859c785145d9fe1e922a1698448276 (RSA)
|   256 492b7283237bf4dc5b8c28f0f69e71fe (ECDSA)
|_  256 4ac9f5221b0e8d374aefac1e74162893 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-title: Login
|_Requested resource was login.php
| http-git: 
|   10.0.68.105:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Remotes:
|_      https://github.com/haxxorsid/food-ordering-system
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 10.0.68.106
Host is up (0.0050s latency).
Not shown: 682 filtered tcp ports (no-response), 316 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 515aa85f83b44d5c3970dce1425068e4 (RSA)
|   256 73d2c9aa2ad8704b49b571cba11fcf16 (ECDSA)
|_  256 6ef7f8136c8e16439f92647cc279b5e0 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-git: 
|   10.0.68.106:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Remotes:
|_      https://github.com/Harsh-Ajudia/Online-Auction-System.git
|_http-title: Auction
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 10.0.68.107
Host is up (0.0046s latency).
Not shown: 673 filtered tcp ports (no-response), 325 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 843dcbd9be71d74c29c92508dfb24de2 (RSA)
|   256 c28cab84dfa3573c9bf17b59eb0846bc (ECDSA)
|_  256 58219beb4c40f4eaa88eec818f275a4a (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 10.0.68.108
Host is up (0.0091s latency).
Not shown: 676 filtered tcp ports (no-response), 321 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 843dcbd9be71d74c29c92508dfb24de2 (RSA)
|   256 c28cab84dfa3573c9bf17b59eb0846bc (ECDSA)
|_  256 58219beb4c40f4eaa88eec818f275a4a (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
3306/tcp open  mysql   MySQL 5.7.34-0ubuntu0.18.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.34-0ubuntu0.18.04.1
|   Thread ID: 11
|   Capabilities flags: 65535
|   Some Capabilities: ODBCClient, Support41Auth, LongPassword, Speaks41ProtocolOld, SupportsTransactions, SupportsLoadDataLocal, SupportsCompression, IgnoreSigpipes, SwitchToSSLAfterHandshake, InteractiveClient, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolNew, FoundRows, DontAllowDatabaseTableColumn, LongColumnFlag, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: \x01t7P*Qezyb\x024_j]T4\x11\x07Q
|_  Auth Plugin Name: mysql_native_password
| ssl-cert: Subject: commonName=MySQL_Server_5.7.31_Auto_Generated_Server_Certificate
| Not valid before: 2020-10-04T15:11:03
|_Not valid after:  2030-10-02T15:11:03
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 10.0.68.110
Host is up (0.0048s latency).
Not shown: 676 filtered tcp ports (no-response), 322 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 dfa27a142fceb4bfca346eeed914febc (RSA)
|   256 e64d1d44c6296facbd26174a7a2cb94d (ECDSA)
|_  256 e77b3d877084e21ace3fb81e7ee1e6d9 (ED25519)
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u2 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u2-Debian
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 10.0.68.122
Host is up (0.0052s latency).
Not shown: 687 filtered tcp ports (no-response), 311 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 843dcbd9be71d74c29c92508dfb24de2 (RSA)
|   256 c28cab84dfa3573c9bf17b59eb0846bc (ECDSA)
|_  256 58219beb4c40f4eaa88eec818f275a4a (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Drupal 8 (https://www.drupal.org)
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.txt /web.config /admin/ 
| /comment/reply/ /filter/tips/ /node/add/ /search/ /user/register/ 
| /user/password/ /user/login/ /user/logout/ /index.php/admin/ 
|_/index.php/comment/reply/
|_http-title: Home | Maggot&#039;s Pilz-Almanach
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Post-scan script results:
| ssh-hostkey: Possible duplicate hosts
| Key 2048 843dcbd9be71d74c29c92508dfb24de2 (RSA) used by:
|   10.0.68.54
|   10.0.68.107
|   10.0.68.108
|   10.0.68.122
| Key 256 c28cab84dfa3573c9bf17b59eb0846bc (ECDSA) used by:
|   10.0.68.54
|   10.0.68.107
|   10.0.68.108
|   10.0.68.122
| Key 256 58219beb4c40f4eaa88eec818f275a4a (ED25519) used by:
|   10.0.68.54
|   10.0.68.107
|   10.0.68.108
|_  10.0.68.122
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 256 IP addresses (256 hosts up) scanned in 1906.88 seconds

```