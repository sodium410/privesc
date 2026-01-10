**Online resources**:  
https://github.com/TCM-Course-Resources/Linux-Privilege-Escalation-Resources  
Basic Linux Privilege Escalation - https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/  
Linux Privilege Escalation - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md  
Checklist - Linux Privilege Escalation - https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist  
Sushant 747's Guide - may need VPN - https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html  

**Automation tools**:  
LinPeas https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS  
LinEnum https://github.com/rebootuser/LinEnum  //very similar to linpeas  
Linux Priv Checker - https://github.com/sleventyeleven/linuxprivchecker  
Teddybears picnic  //linpeas first then others  
Linux Exploit Suggester - https://github.com/mzet-/linux-exploit-suggester  
Try run this if nothing on linpeas !!  suggests potential cve's – meterpreter can auto exploit - load suggester !  

## Enumeration/Info Gathering/Password hunting  
Check teddy  
history  
su root  //password123  
try exposed ssh keys  

## Permission based privesc  
### 1. Basic  
Ls –la /etc/passwd        //check if we can read write user password files    
Ls –la /etc/shadow          //we could update or insert our pass in passwd or shadow    
Unshadow passwd.file shadow.file   //places hashes into x of passwd file //delete no hash users and crack it. Copy just the hashes for users and crack it  
Check hashcat hash examples and find module to run. 
Hashcat –m 1800 creds.file /usr/share/wordlists/rockyou.txt  

### 2. Sudo Rights Abuse: 
When the sudo command is issued, the system will check if the user issuing the command has the appropriate rights, as configured in /etc/sudoers.  
always check to see if the current user has any sudo privileges.  
If NOPASSWD - then no password, otherwise user pass required to run sudo rights  
sudo -l   //sudo el to list sudp privs  //use gtfobins to check if any can be exploited to escape to shell  
#### Via Intended functionality  
if nothing on gtfobins for sudo listed binaries, its still possible to escalate with thier intended functionalities  
examples: wget to read/post shadow file, apache2 to read shadow file  -- just google  
#### Via LD_PRELOAD  
sudo –l shows env_keep+=LD_PRELOAD is enabled  //if enabled  
!! Loads malicious library before all libraries !!  
https://medium.com/@amaraltohami30/ld-preload-privilege-escalation-linux-priv-escalation-c8abdf1a9bec  
#### Outdated sudo  
CVE-2019-14287: sudo before 1.8.28 vulnerable to  if allowed to execute all except for root  
hacker ALL=(ALL,!root) /bin/bash  //can run bash except as root  
– user can trick sudo to still run as root !! Check https://www.exploit-db.com/exploits/47502  
CVE-2019-18634: Sudo versions prior to 1.8.26  – buffer overflow vulnerabilty  
asterisk * as we type password - only when pwfeedback is enabled   
check if pwfeedback enabled in /etc/sudoers - then can be exploited !! if cat't read /etc/sudoers still ok to give a shot       
https://github.com/saleemrashid/sudo-cve-2019-18634  
#### Sudoers best practice:  
Always specify absolute path to any binaries, otherwise PATH abuse.  

## Kernel Exploits:  Kernel is an interface between software and hardware.  
Note: Kernel exploits can cause system instability so use caution when running these against a production system.  
And some work out of the box and some require modification.  Google kernel/OS version to find any ..  
uname -a   //print kernel version
hostnamectl  //better  
cat/etc/ls-release  //os version  
User exploit suggester to suggest any available exploits  
Well known exploits:  
Dirty Cow - Linux Kernel 2.6.22 < 3.9  - CVE-2016-5195 - Race condition  
CVE-2017-16995 Linux Kernel < 4.4.0-116 – Ubuntu 16.04.4 - Buffer overflow   





