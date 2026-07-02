NT Authority\SYSTEM -- built in local system account not user account, no uac, full unrestricted access - more priv than local/default administrator  
uses machine identity on network DOMAINGROUP\COMPUTERNAME$  
The SYSTEM account ensures the core operating system can function smoothly without human intervention  

## Useful tools  
seatbelt, Winpeas, Powerup, sharpup, JAWS - powershell script, sessiongopher - saved session info, watson missing kbs  
Lazagne, windows exploit suggester - netxt generation, sysinternals suite  

## Situational awareness  
ipconfig /all  -- check available network interfaces  
arp -a    //arp table to discover neighbors  
route print  //check configured routes  

PS C:\htb> Get-MpComputerStatus   //check defender status  
PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections   //check applocker rules  
PS C:\htb> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone  //test if app is allowed by app locker rules  

## Initial Enumeration  
**We can escalate privileges to one of the following**  
Nt AUTHORITY\SYSTEM - localsystem account  
built in local administrator account - mostly disabled by org but not uncommon  
Another local account that is member of local Administrators group  
A standard domain user who is part of the local Administrators group on the target  
A domain admin that is part of the local administrators group  

**Key Data Points**  
systemfinfo  //detailed configuration info hostname os name os version archi if domain if vm  
tasklist /svc    -- list running processes  
wmic product get name  //list installed programs  
PS C:\htb> Get-WmiObject -Class Win32_Product |  select Name, Version   //powershell command to list installed programs  

set   //display set environment variables look path  

wmic qfe   //list install hotfixes  
PS C:\htb> Get-HotFix | ft -AutoSize   //installed hotfixes with powershell  

netstat -ano  //display running services - listeners and active connections - look for services running on 127.0.0.1 not exposed  

query user   //logged in user sessions  
echo %USERNAME%  //current user -- or simply whoami  
whoami /priv     //current user privileges  
whoami /groups   //current user groups  
net user   //list all local users  
net localgroup  //list all groups  
net localgroup administrators   //details of group descript and members  
net accounts   //local password policy  

**common examples**..  
SeImpersonate privilege to impersonate other users  
admin portal running only on 127.0.0.1 reveals creds/run as admin  
splunk univsal forwarder configured to run as System and no authnti  
erlang port 25672 - rabbitmq   

**Communication with Processes**  

## Windows User Privileges  
**Windows Authorization process**  
Security principals are anything that can be authenticated by the Windows operating system, including user and computer accounts, processes  
Every single security principal is identified by a unique Security Identifier (SID).  
When a security principal is created, it is assigned a SID which remains assigned to that principal for its lifetime.  

User access token ---- sid, group sids, privileges is compared against Access control entities ACEs within object security descriptor  

**Rights and Privileges in Windows**  - similar to capabilities in linux but capa is process level this is user level  
Windows contains many groups that grant their members powerful rights and privileges.  
users can have various rights assigned to their account. // whoami /priv  
Below are some of the key user rights assignments, which are settings applied to the localhost.  
SeNetworkLogonRight - allow access to system over network smb, netbios, cifs, com+ if not allowed then user cant smb  
SeRemoteInteractiveLogonRight - allow logon through rdp, port will be reachable logon screen displayed but cant login  
SeBackupPrivilege - backup files and dir  
SeSecurityPrivilege - manage auditing and security log - can clear security log in the event viewer  
SeTakeOwnershipPrivilege - take ownership of files or other objects  
SeDebugPrivilege - debug programs even the ones they do not own  
SeImpersonatePrivilege - impersonate a cleint after authentication  
SeLoadDriverPrivilege - load and unload device drivers  
SeRestorePrivilege - restore files and dire  
SeTcbPrivilege  - act as part of operating system - impersonation  
When a privilege is listed for our account in the Disabled state, specific privilege assigned cannot be used until enabled  


 

 



