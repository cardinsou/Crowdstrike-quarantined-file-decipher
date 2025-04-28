# Crowdstrike quarantined file decipher

During an assignment we noticed from Crowdstrike falcon web console that the agent on a ransomware patient zero machine quarantined some files before infection start. Unfortunately the agent was not configured to send quarantined file to the web console. We already DDed the patient 0 so we tried to find an alternative way to recover that data.

Crowdstrike agent quarantined file on a Windows host are placed in the following path:

*C:\\Windows\\System32\\Drivers\\CrowdStrike\\Quarantine\\*

Every quarantine action lead to two file:
* a ciphered version of the original file named **<file_sha256>_quarantine**
  
* a CSQ file that contains the original path of the quarantined file named **<file_sha256>_quarantine.csq**

In order to see the original path of the quaranted file you can open the .csq file with any program, cat, hexeditor, nano, vi, etc..

The quaratined file instead is ciphered with a bitwise XOR with an hex single character (eg. 0x6a). The attached script (decipher_CS_quarantined.py) can decipher the file. We use it against only one test case so we dont'n know if the key is uniqe or it depends by tenant, zone, customer, CID or something else but, if you don't know the key the script can bruteforce it for you.

Usage:

```
user$ python3 decipher_CS_quarantined.py -h
usage: decipher_CS_quarantined.py [-h] -i  -o  [-k] -s

options:
  -h, --help  show this help message and exit
  -i          File to decipher
  -o          Deciphered file
  -k          Decipher Key
  -s          Quarantined file SHA256
```

After deciphering a file the script check if inserted hash SHA256 (-s parameter) match with deciphered file hash SHA256 so you can check if the key is correct.

Example, key known:
```
user$ python3 decipher_CS_quarantined.py -i eaa9dc1c9dc8620549fee5f1399488292s49d2c8767b58b7d0356564fd43e6_er3484cb_quarantine -k 0x6a -o decphered_file -s eaa9dc1c9dc8620549fee5f1399488292s49d2c8767b58b7d0356564fd43e6
[+] Deciphering file ...
[+] Deciphering key inserted by user: 0x6a
[+] Deciphering successfully
user$ 
```
Example, key not known:
```
user$ python3 decipher_CS_quarantined.py -i eaa9dc1c9dc8620549fee5f1399488292s49d2c8767b58b7d0356564fd43e6_er3484cb_quarantine -o decphered_file -s eaa9dc1c9dc8620549fee5f1399488292s49d2c8767b58b7d0356564fd43e6
[+] Deciphering file ...
[+] Bruteforcing key ...
[+] Deciphering key found: 0x6a
[+] Deciphering successfully
user$ 
```
