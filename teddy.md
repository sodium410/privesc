Source --> https://github.com/TheVeryAngryUnicorn/Teddybears_Picnic/blob/master/Teddybears_Picnic_v2.0.sh  

Except Not writing to files.. good for manual build reviews..  
**#Grab System Info**  
uname -a  //os info -- can also try hostnamectl  //similar  
ps aux  //running processes  
ss -tulp    //listening services  
lsblk  
systemctl status    
lpstat -a    //printers  
lsof -i  

**#Grab Networking Info**  
ip a  
ifconfig -a    
arp -a  
cat /etc/hosts  //hosts file localhost dns  
cat /etc/resolv.conf  //DNS info  
netstat -pal   
route -n  

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

**#Pull Interesting Files**  
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

find / -type f -iname "*.conf" 2>/dev/null -ls  //files_conf  
find / -type f -iname "*.log" 2>/dev/null -ls  //files_log  
find / -type f -iname "*.cfg" 2>/dev/null -ls  //files_cfg  
find / -type f -iname "*.properties" 2>/dev/null -ls  //files_properties  
find / -type f -iname "*.sh" 2>/dev/null -ls  //files_sh  
find / -type f -iname "*.yml" 2>/dev/null -ls  //files_yml  
find / -type f -iname "*.yaml" 2>/dev/null -ls  //files_yaml  
find / -type f -iname "*jar" 2>/dev/null -ls  //files_jar  
find / -type f -iname "*.key" 2>/dev/null -ls  //files_key  
find / -type f -iname "*.csv" 2>/dev/null -ls  //files_csv  
find / -type f -iname "*.ini" 2>/dev/null -ls  //files_ini  
find / -type f -iname "*.xml" 2>/dev/null -ls  //files_xml  
find / -type f -iname "*.old" 2>/dev/null -ls //files_old  

**echo "Recruiting Password Teddies"**  
**#Password Hunting**  
grep -rHi 'password=' /home/  //home_password  
grep -rHi 'password=' /etc/  //etc_password  
grep -rHi 'password=' /opt/  //opt_password  
grep -rHi 'password=' /var/  //var_password  
grep -rHi 'password=' /tmp/  //tmp_password  
grep -rHi 'password=' /mnt/  //mnt_password  
grep -rHi 'password=' /usr/  //usr_password  

#this one takes too long  
#find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \  //find_password  
#grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null  //grep_password  

**echo "Recruiting Capability Teddies"**  
**#capability hunting**  
getcap -r / 2>/dev/null  //capabilities_BIN  
cat /etc/security/capability.conf | grep Cap  //capabilities_USER 

