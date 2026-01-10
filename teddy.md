Source --> https://github.com/TheVeryAngryUnicorn/Teddybears_Picnic/blob/master/Teddybears_Picnic_v2.0.sh  

Except Not writing to files.. good for manual build reviews..  
**#Grab System Info**  
uname -a or hostnamectl or cat /etc/os-release  //os+kernel info    
lscpu   //cpu architecture 
ps aux  //running processes   
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"   //command-line args used to start every running process  
./pspy64 -pf -I 1000  /similar but good  
ss -tulp    //listening services    
lsblk  
systemctl status    
lpstat -a    //printers  
lsof -i  
cat /etc/shells    //shells and thier versions -- bash 4.1 is vul to shellshock  
lsblk      //list hdd,usb,other drives  
cat /etc/fstab    //filesystem table  
cat /etc/fstab | grep -v "#" | column -t    //unmounted fs, mount check for any sensitive info  
df -h   //mounted file sys  
sudo -v  //sudo version  

**#Grab User Info**  
id  //user id info  
sudo -l   //list sudo perms of current user  
history   //check sensitive info in command history of current or other users history  
env   //any sensitive info in env users variables     
echo $PATH   // . in path is bad  
w and who and users  //Who else is logged on to system  
cat /etc/passwd   //check creds in descrption or hash holder  
cat /etc/group   //list groups  
getent group sudo  //list members of sudo group  
pwd, ls /home , cd /tmp /var/tmp dev/shm    //check  
lastlog  

**#Grab Networking Info**  
ip a  or ifconfig -a   //ip info  
arp -a  or ip neigh  //neighbours 
cat /etc/hosts  //hosts file localhost dns  
cat /etc/resolv.conf  //DNS info  
netstat -pal   
route -n  Or ip route  //route table  
netstat -ano   //listening and estabilished connections //exposed and localhost only both  

**#Recruiting Firewall and AV Teddies**  
sestatus   
aa-status //app armour  
apparmor_status   //same  
ps aux | grep -i clam   
ps aux | grep -i mcafee   
iptables -L  
systemctl status firewalld.service  
cat /proc/sys/kernel/randomize_va_space 2>/dev/null  
check AV: both installed and running services ..   
for all  
systemctl list-units --type=service | grep -Ei 'clam|sophos|trend|mcafee|symantec|eset|avast|avg|'  
For Ubuntu:  
dpkg -l | grep -E 'clamav|sophos|bitdefender|kaspersky|mcafee|avast|eset|comodo'  
sudo systemctl list-units --type=service --state=running | grep -E 'clamav|sophos|bdagent|kav|mcafee|avast|eset|comodo'  
systemctl list-units --type=service --state=running  
sudo firewall-cmd --list-all       //firewall rules  --hence blocked   

**#Grab Packages Info**  
dpkg -l   
rpm -qa   
find / \( -name "wget" -o -name "cc" -name "tftp" -o -name "ftp" -o -o -name "nmap" -o -name "perl" -o -name "nc" -o -name "netcat" -o -name "python" -o -name "gcc" -o -name "as" \) 2>/dev/null -ls    
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null   
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list   //list installed packages  
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done  
//compare the existing binaries with the ones from GTFObins to see which binaries we should investigate later  

**#Pull Interesting Files**  
cat /etc/passwd    //any passwd in descriptions ?
cat /etc/shadow  
cat /etc/ssh/sshd_config  
cat /etc/passwd  
cat /etc/group  
cat /etc/sudoers  

**Cron**  
system level cron jobs -- /etc/cron.daily, monthly, weekly  
these folders create scripts owned by root to be run daily weekly monthly  

cat /etc/crontab  //system wide crons  
sudo ls -al /var/spool/cron/  --other user jobs  
then cat it - sudo cat /var/spool/cron/adm_wsi --cron job of user  
crontab -l   //of current user  

for all users: GET INTO BASH SUDO THEN RUN BELOW OR EVEN WITHOUT   
for user in $(cut -f1 -d: /etc/passwd); do  
    echo "Cron jobs for $user:"  
    crontab -u $user -l 2>/dev/null  
done  

**Recruiting Conf Teddies**  
cat /etc/fstab  
cat /etc/rsyslog.conf  
cat /etc/modprobe.d/CIS.conf  
cat /etc/hosts.allow   
cat /etc/hosts.deny  
cat /etc/postfix/main.cf  
cat /etc/chrony.conf  
cat /boot/grub2/grub.cfg  
cat /boot/grub2/user.cfg  
cat /etc/services  

**echo "Recruiting Permission Teddies"  
#Check For Naughty User Perms**  
ls -alR /home  
ls -alR /root  

**#Check For Poor File Perms**  
find / -perm -4000 -type f 2>/dev/null -ls  //suid  
find / -perm -2000 -type f 2>/dev/null -ls  //sgid  
find / -nouser 2>/dev/null -ls  //file not owned by any user  
find / -nogroup 2>/dev/null -ls  //no_group.txt  

find / -path /proc -prune -perm -2 -type f 2>/dev/null -ls //World_Writable_files  
find / -perm -2 -type d 2>/dev/null -ls //World_Writeable_Dirs  

find / -perm /o=x -name "*.sh" 2>/dev/null -ls  //world_Executable_scripts  
find / -perm /o=x -name "*.key" 2>/dev/null -ls  //world_Executable_Keys  
find /var/log/ -perm /o=rwx 2>/dev/null -ls > //Var_logs_other_Permission  
find /var/log -perm /go=rwx 2>/dev/null -ls > //Var_logs_group_Permission  

****echo "Recruiting File Teddies"  **  
# Check the following **  
find / -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" 2>/dev/null |xargs -r ls -la  //SSH_keys  
! -path "*/proc/*"    //add this to below commands to exclude /proc  
find / -type f \( -name *.conf -o -name *.config -o -name *.cfg \) -exec ls -l {} \; 2>/dev/null   //find conf, config files  
find / -type f \( -name *.yml -o -name *.yaml \) -exec ls -l {} \; 2>/dev/null   
find / -type f -iname "*.log" 2>/dev/null -ls  //files_log    
find / -type f -iname "*.properties" 2>/dev/null -ls  //files_properties  
find / -type f -iname "*.sh" 2>/dev/null -ls  //files .sh  
find / -type f -iname "*jar" 2>/dev/null -ls  //files_jar  
find / -type f -iname "*.key" 2>/dev/null -ls  //files_key  
find / -type f -iname "*.csv" 2>/dev/null -ls  //files_csv  
find / -type f -iname "*.ini" 2>/dev/null -ls  //files_ini  
find / -type f -iname "*.xml" 2>/dev/null -ls  //files_xml  
find / -type f -iname "*.old" 2>/dev/null -ls //files_old  
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student   //hidden files  
find / -type d -name ".*" -ls 2>/dev/null      //hidden directories  
find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null     //find all history files  

**echo "Recruiting Password Teddies"**  
**#Password Hunting**  
grep -rHi 'password=' /home/  //home_password  
grep -rHi 'password=' /etc/  //etc_password  
grep -rHi 'password=' /opt/  //opt_password  
grep -rHi 'password=' /var/  //var_password  
grep -rHi 'password=' /tmp/  //tmp_password  
grep -rHi 'password=' /mnt/  //mnt_password  
grep -rHi 'password=' /usr/  //usr_password  
locate password | more   //files named password  
watch 'ps aux | grep password'    //processes with string password in their command line arguments  
find / -name \*.sh 2>/dev/null | xargs cat | grep "HTB"     //find flag HTB in .sh files  

#this one takes too long  
#find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \  //find_password  
#grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null  //grep_password  

**echo "Recruiting Capability Teddies"**  
**#capability hunting**  
getcap -r / 2>/dev/null  //capabilities_BIN  
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \\;  //of files only in those paths  
cat /etc/security/capability.conf | grep Cap  //capabilities_USER  
