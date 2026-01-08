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

# Kernel Exploits:  Kernel is an interface between software and hardware.  
Note: Kernel exploits can cause system instability so use caution when running these against a production system.  
And some work out of the box and some require modification.  Google kernel/OS version to find any ..  
uname -a   //print kernel version
hostnamectl  //better  
cat/etc/ls-release  //os version  
User exploit suggester to suggest any available exploits  
Well known exploits:  
Dirty Cow - Linux Kernel 2.6.22 < 3.9  - CVE-2016-5195 - Race condition  
CVE-2017-16995 Linux Kernel < 4.4.0-116 – Ubuntu 16.04.4 - Buffer overflow   




