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

### 3. Special permissions: setuid and setgid  
setuid allows program/script to be run with permissions of owner of the file typically with elevated privs..  
setuid bit appears as an s instead of x in owner perms  -rwsr-xr-x  
find / -perm -4000 -type f 2>/dev/null -ls //suid  
find / -perm -2000 -type f 2>/dev/null -ls //sgid  
// next use GTFO bins to see if any unusual    
Exploitables: systemctl, tcpdump, vim etc  
//suid is set on passwd doesn't work - why ? because passwd not vul and doesn;t allow shell escape ?  
//think of this as on top of sudo or similar - if wget has it set - can read shadow because its run as root !!  
#### Suid files Via Shared Object Injection:  
similar to dll injection, can try on both custom sudo enabled/suid executables if the binary lods libraries from writable locations.  
say no gtfo shortcut, still investigate further for custom executables for any missing library  
and replace it with your malicious library to escalate privileges !!  
find / -type f -perm -4000 -ls 2>/dev/null 
strace /usr/local/bin/suid-so   //debug tool to see what process does with linux kernel  
Look for no such file or directory errors  
Strace /usr/local/bin/suid-so 2>&1 | grep -I –E "open|access|no such file"  
Look for any files that you can write.. In this case /home/user/.config/libcalc.so   
--- just create a file and run executable again – it should catch your file and run it !  
Search for c shell code !! Compile it and place it in that directory with that name !!  

#### Escalation via Binary Symlinks  
one of the tests, cron jobs had a symlink run by root - not vulnerable, as symlink dire was not writable  
vulnerable if can change/update symlinks - need write perms - can maybe make it point to then run bin/bash instead ?   
Probably similar case with nginx version until 1.6.2 - CVE-2016-1247 //exploit suggester flags this  
exploit: https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html  
nginx issue: ss –la /var/log/nginx  - dir owned by web user www-data - replace a file here with a symlink and restart nginx 
Upon nginx startup/restart the logs would be written to the file pointed to  ..hence the vulnera  
requires: vulnerable nginx version <=1.6.2 and suid on sudo which is always the case  

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





