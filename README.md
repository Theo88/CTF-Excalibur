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

nmap -v -p- --min-rate 5000 -sV -sC 10.129.136.91

curl -v http://{ip}
return 302 not found
