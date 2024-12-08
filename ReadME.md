# Check ACL for an User with ADACLScanner/Bloodhound

ADACLScan.ps1 -Base “DC=contoso;DC=com” -Filter “(&(AdminCount=1))” -Scope subtree

bloodhound-python -v --zip -c All -u <username> -p <password> -d certified.htb -ns <dc-ip/system-ip>
