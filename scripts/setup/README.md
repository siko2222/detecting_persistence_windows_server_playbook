# Domain controller setup
* Basic Windows Server 2022 install
* Ensure the server has a static ip
* Install the basic required services for a domain controller
* Add a DNS forwarder to allow for DNS request to outside domains (Eg. google dns 8.8.8.8)

# Domain server setup
* Basic Windows Server 2022 install
* Ensure the server has a static IP and is using the DNS from the domain controller
## Join to domain
```powershell
# Rename the computer and restart before joining to domain
Rename-Computer -NewName "MasterVM0x" -Restart

# On the domain controller, create the computer object
Import-Module ActiveDirectory
New-ADComputer -Name "MasterVM0x" -Path "CN=Computers,DC=ad,DC=masterlab,DC=local" -SAMAccountName "MasterVM0x"

# On the domain controller, create a DNS record for the computername
Import-Module DnsServer
Add-DnsServerResourceRecordA -Name "MasterVM0x" -ZoneName "ad.masterlab.local" -IPv4Address "<SERVER_IP_HERE>" -CreatePtr

# On the server, join it to the domain using the domain admin credentials
Add-Computer -DomainName "ad.masterlab.local" -Credential masterlab\Administrator -Restart
```

# C2 Server setup
* Basic Kali Linux install
* Ensure the server has a static IP and is using the DNS from the domain controller
