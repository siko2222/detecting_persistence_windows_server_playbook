# Domain controller setup

# Domain server setup
## Join to domain
```powershell
# Rename the computer and restart before joining to domain
Rename-Computer -NewName "MasterVM0x" -Restart
```

```powershell
# On the domain controller, create the computer object
Import-Module ActiveDirectory
New-ADComputer -Name "MasterVM0x" -Path "CN=Computers,DC=ad,DC=masterlab,DC=local" -SAMAccountName "MasterVM0x"
```

```powershell
# On the server, join it to the domain using the domain admin credentials
Add-Computer -DomainName "ad.masterlab.local" -Credential masterlab\Administrator -Restart
```



# C2 Server setup
