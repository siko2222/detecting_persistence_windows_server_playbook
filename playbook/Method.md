# Method for uncovering persistence in a windows server environment v2

## Prerequisites
### Audit policies:
In the **Local Security Policy** -> **Advanced Audit Policy Configuration** -> **Audit Policies**, enable the following:

- In **Account Management**:
  - Enable **Audit User Account Management** for both success and failure
  - Enable **Audit Security Group Management** for both success and failure

- In **Policy Change**:
  - Enable **Audit MPSSVC Rule-Level Policy Change** for both success and failure

- In **Object Access**:
  - Enable **Audit Other Object Access Events** for both success and failure

- In **System**:
  - Enable **Audit Security System Extension** for both success and failure

### Tools and modules:
You will need the following tools and modules:
- Windows AD PowerShell module
    - Install the feature on the server (if not already present):
        ```powershell
        Install-WindowsFeature -Name 'RSAT-AD-PowerShell'
        ```
- WebAdministration module
    - Install the feature on the server (if not already present):
        ```powershell
        Install-WindowsFeature -Name 'Web-Scripting-Tools'
        ```
- Sysmon
    - Create the config file (save as sysmon_config.xml)
        ```xml
        <Sysmon schemaversion="4.90">
        <!-- Capture all hashes -->
        <HashAlgorithms>*</HashAlgorithms>
            <EventFiltering>
                <ProcessCreate onmatch="exclude"></ProcessCreate>
                <ProcessAccess onmatch="exclude"></ProcessAccess>
                <ProcessTerminate onmatch="exclude"></ProcessTerminate>
                <DriverLoad onmatch="exclude"></DriverLoad>
                <ImageLoad onmatch="exclude"></ImageLoad>
            </EventFiltering>
        </Sysmon>
        ```
    - Install using PowerShell (Run in same directory as config file)
        ```powershell
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "./sysmon.zip";
        Expand-Archive -Path "./sysmon.zip" -DestinationPath "./sysmon";
        Remove-Item -Path "./sysmon.zip";
        Copy-Item -Path "./sysmon_config.xml" -Destination "./sysmon/sysmon_config.xml"
        Set-Location "./sysmon";
        ./Sysmon64.exe -i ./sysmon_config.xml -accepteula -l 2>$null; # Change to './Sysmon64.exe -u' and run again to uninstall
        Set-Location "..";
        Remove-Item -Path "./sysmon" -Recurse -Force;
        ```
---
## Detection difficulty levels: 
1. <span style="color: green;">Easy</span> 
    - Requires basic Windows/Windows Server knowledge and basic understanding of the corporate environment

2. <span style="color: orange;">Challenging</span>  
    - Requires a more intermeditate understanding of Windows/Windows Server and some knowledge of the corporate environment 

3. <span style="color: red;">Difficult</span> 
    - Requires a deep understanding of Windows/Windows Server and a good understanding of the corporate environment 

The method is designed to prioritize simpler detections initially, followed by progressively more advanced persistence techniques.

---
## Method
### 1. <span style="color: green;">New local user accounts</span>
- Look at user created events (Event ID 4720) in the **Security** event log.
- Look at all the enabled local users, when did they last log on, and when did they last set their password? Correlate it with the event logs for creation date.
- Script to list all enabled local users, including their names, descriptions, last logon times, last password set dates, and SIDs:
```powershell
Get-LocalUser |
Where-Object {$_.Enabled -eq $true} |
Select-Object -Property Name, FullName, Description, LastLogon, PasswordLastSet, SID
```
### 2. <span style="color: green;">Modified local user accounts</span>
- Look at modified user accounts events (Event ID 4738) in the **Security** event log.
- Look at modifications to user accounts that might be of interest based on the account creation time or last log on time.
### 3. <span style="color: green;">Local user accounts with elevated privilegies</span>
- Look at member added to security enabled local group events (Event ID 4732) in the **Security** event log.
- Look at users in privilegied groups
- Script to list all members of multiple local privileged groups:
```powershell
$privilegedGroups = @("Administrators", "Backup Operators", "Remote Desktop Users", "Hyper-V Administrators", "Print Operators")

Write-Host "--------------------------------------"
ForEach ($group in $privilegedGroups){
	$groupMembers = Get-LocalGroupMember -Group $group
    Write-Host "$($group):"
    $groupMembers | ForEach-Object {
    Write-Host "* $($_.Name)"
    }
    Write-Host "--------------------------------------"
}
```
### 4. <span style="color: green;">New domain user accounts</span>
- Look at user created events (Event ID 4720) in the **Security** event log on the domain controller.
- Look for users rectly created, in the timeframe we believe the server to be compromised.
- Script to list all active Active Directory users created in the last week, including their account name, distinguished name, creation date, and last logon date:
```powershell
Import-Module ActiveDirectory

$startDate = (Get-Date).AddDays(-7) # Last week
Get-ADUser -Filter {(whenCreated -ge $startDate) -and (Enabled -eq $true)} -Properties * |
Select-Object -Property SamAccountName, DistinguishedName, whenCreated, LastLogonDate
```
### 5. <span style="color: green;">Modified domain user accounts</span>
- Look at modified user account events (Event ID 4738) in the **Security** event log on the domain controller.
    - Fields with the value – has not been changed. ACL changes may generate a 4738 event with all - fields
    - Look at recently modified users in particular, check that something other than the 'LastLogonDate' has been altered, look for modification to group memberships (*memberOf*) or other user security attributes like *scriptPath*.
- Script to list all active Active Directory users modified in the last week, including their account name, distinguished name, modification date, and last logon date:
```powershell
Import-Module ActiveDirectory

$startDate = (Get-Date).AddDays(-7) # Last week
Get-ADUser -Filter {(whenChanged -ge $startDate) -and (Enabled -eq $true)} -Properties * |
Select-Object -Property SamAccountName, DistinguishedName, whenChanged, LastLogonDate
```
### 6. <span style="color: green;">Domain user accounts with elevated privilegies</span>
- Look at member added to security enabled global groups (Event ID 4728) in the **Security** event log on the domain controller.
- Look at users in privilegied groups
- Script to list all members of multiple domain privileged groups:
```powershell
Import-Module ActiveDirectory

$privilegedGroups = @("Administrators", "Backup Operators", "Remote Desktop Users", "Hyper-V Administrators", "Print Operators", "Enterprise Admins", "Domain Admins")

Write-Host "--------------------------------------"
ForEach ($group in $privilegedGroups){
	$groupMembers = Get-ADGroupMember -Identity $group
    Write-Host "$($group):"
    $groupMembers | ForEach-Object {
    Write-Host "* $($_.Name)"
    }
    Write-Host "--------------------------------------"
}
```

### 7. <span style="color: green;">Registry changes</span>
Look at the following registry keys for paths that should not be set to run at startup. This could be files outside the Program Files directory or paths to applications known to be malicious or unwanted. Sometimes the path might not be to a file, but the code can be placed directly as the key value. It can even be obfuscated e.g. PowerShell invoking a base64 encoded command.
- HKCU:\Environment -> UserInitMprLogonScript
- HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
- HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce
- HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
- HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce

### 8. <span style="color: green;">Shortcut manipulation</span>
- Look for shortcuts (.lnk files) with weird target paths. By weird target paths I mean paths that points to a different software than the name and icon suggests or ones that includes several separated commands.
- Script to list all lnk files on the C-drive including their TargetPath and Arguments:
```powershell 
$lnkFiles = Get-ChildItem -Recurse -Path 'C:\*' -Filter *.lnk -ErrorAction SilentlyContinue

# Create a WScript.Shell COM object
$shellObject = New-Object -ComObject WScript.Shell

# Loop through each .lnk file and get its target path
$lnkFiles | ForEach-Object {
    try {
        $lnkFilePath = $_.FullName
        $shortcut = $shellObject.CreateShortcut($lnkFilePath)
        $targetPath = $shortcut.TargetPath
        $arguments = $shortcut.Arguments

        # Output the .lnk file path and its target path
        [PSCustomObject]@{
            LnkFilePath = $lnkFilePath
            TargetPath  = $targetPath+" $arguments"
        }
    } catch {
        # Handle the error (e.g., log it, display a message, etc.)
        Write-Warning "Could not access $($_.FullName): $_"
    }
} | Format-Table -AutoSize
```
### 9. <span style="color: orange;">Services</span>
- Look at service installed events (Event ID 4697) in the **Security** event log.
- Look at running services and pay attention to:
    - Service names that looks weird
    - Service that runs with elevated privilegies that seems like it shouldn't
    - Services started from a path that seems unusual
- Script that lists the running services, their names, the user they are running under, and the path to their executable:
```powershell
Get-WmiObject -Class Win32_Service | 
Where-Object { 
    $_.State -eq "Running" -and 
    $_.PathName -notlike "C:\Windows\system32\svchost.exe*" # Exclude svchost since it's a Windows system process that's used by many services
} | 
Select-Object Name, 
    @{Name="User"; Expression={$_.StartName}}, 
    @{Name="ExecutablePath"; Expression={$_.PathName}}
```
### 10. <span style="color: orange;">Scheduled tasks</span>
- Look at scheduled task creation and update events (Event IDs 4698 and 4702) in the **Security** event log.
- Look at the installed scheduled tasks and pay attention to:
    - Where they are created
    - Who authored the task
    - If they run with system privilegies
    - If they run obfuscated PowerShell scripts
- Script to list scheduled tasks, including their authors, task paths, and executable paths with arguments:
```powershell
Get-ScheduledTask | 
Where-Object { 
    $_.Author -notin "Microsoft Corporation", "Microsoft Corporation.", "Microsoft" # Exclude most tasks Authored by Microsoft
} | 
Select-Object @{Name="Name"; Expression={$_.TaskName}}, 
              @{Name="ExecutablePath"; Expression={"$($_.Actions.Execute) $($_.Actions.Arguments)"}},
              Author,
              TaskPath | 
ForEach-Object {
    Write-Host "Name: $($_.Name)"
    Write-Host "TaskPath: $($_.TaskPath)"
    Write-Host "ExecutablePath: $($_.ExecutablePath)"
    Write-Host "Author: $($_.Author)"
    Write-Host "##########################################"
}
```
### 11. <span style="color: orange;">Firewall rules</span>
- Look at firewall rule creation or modification events (Event IDs 4946 and 4947) in the **Security** event log.
    - In particular look for rules that was crated or modified in the timeframe the server was compromised.
    - Look for outbound rules even if the default is allow, the atackers may create the rules regardless of environment to ensure they maintain access
    - Look for inbound rules for ports/services or hosts that seems unlikely to need access (eg. allow all from a host that's not in our environment)
- Script to look at a local firewall rule in more detail:
```powershell
$ruleId = '<enter_firewall_rule_id_here>'
Get-NetFirewallRule -PolicyStore PersistentStore -Name $ruleId | ForEach-Object {
    $addressFilter = $_ | Get-NetFirewallAddressFilter
    $portFilter = $_ | Get-NetFirewallPortFilter
    $serviceFilter = $_ | Get-NetFirewallServiceFilter
    [PSCustomObject]@{
        DisplayName = $_.DisplayName
        LocalIP = $addressFilter.LocalAddress
        LocalPort = $portFilter.LocalPort
        RemoteIP = $addressFilter.RemoteAddress
        RemotePort = $portFilter.RemotePort
        ServiceName = $serviceFilter.ServiceName
        Action = $_.Action
        Direction = $_.Direction
    }
} | Format-Table -AutoSize
```
### 12. <span style="color: orange;">Internet Information Services (IIS) Modules and Handlers</span>
- Look at all the installed modules and handlers
- Look for custom modules not provided by a software vendor and examine handlers running on paths that should not be in use (e.g., executing code on all GET *. requests)
- Script to list all installed IIS modules and handlers:
```powershell
# Import module
Import-Module WebAdministration

# All modules
$modules = (Get-WebConfigurationProperty -Filter "system.webServer/modules" -PSPath "IIS:\" -Name ".").Collection | Select-Object -Property name, type
# List modules with $modules | Format-Table -AutoSize

# All handlers
(Get-WebConfigurationProperty -Filter "system.webServer/handlers" -PSPath "IIS:\" -Name ".").Collection | Select-Object -Property name, path, verb, type
# List handlers with $handlers | Format-Table -AutoSize
```
### 13. <span style="color: red;">Look for signs of C2 traffic</span>
- Look for network connections and corresponding executables
- Look at the dns cache on the server
- Script to list TCP connections to other machines (remote is not localhost), including ports, remote addresses, and the names of the owning processes:
```powershell
Get-NetTCPConnection | 
Where-Object { $_.RemoteAddress -notin '0.0.0.0', '::' } | 
Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, @{ Name = 'OwningProcess'; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName }
} | Format-Table -AutoSize
```
- Script to view the dns cache:
```powershell
Get-DnsClientCache | 
Select-Object -Property 'Entry', 'RecordName', 'Status', 'Data', 'TimeToLive' | Format-Table -AutoSize
```
### 14. <span style="color: red;">DLL Hijack</span>
- Check for Image Loaded events (Event ID 7) in the **Applications and Services Logs** under **Microsoft > Windows > Sysmon > Operational**.
- If you suspect a particular process may be hijacked, use Process Monitor to filter for .dll files where the operation is CreateFile or LoadImage for the given process.

- Pay special attention to DLL files that:
  1. Are loaded from unusual locations (e.g. user home directory).
  2. Exist elsewhere with almost the same name but are not signed (unlike the legitimate DLL).
  3. Have the same name as a legitimate DLL but a different hash.


## Sources:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-user-account-management
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-mpssvc-rule-level-policy-change
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-object-access-events
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-system-extension
- https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps
- https://learn.microsoft.com/en-us/powershell/module/webadministration/?view=windowsserver2022-ps
- https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#configuration-files

- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#hyper-v-administrators
- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#administrators
- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#backup-operators
- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#print-operators
- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#remote-desktop-users
- https://learn.microsoft.com/en-us/windows/win32/ad/security-properties
- https://medium.com/@polygonben/detecting-dll-hijacking-with-sysmon-logs-410051d4173f
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#introduction
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events
