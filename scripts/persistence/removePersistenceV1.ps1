# Base script path and user
$scriptAndPayloadLocation = "C:\Program Files\Application Support"
$user = $Env:UserName

# Scheduled task
$taskName = "System Health Check"
$taskPath = "\Microsoft\Windows\WindowsUpdate\"
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -TaskPath $taskPath

# Service
$serviceName = "Application Support Service"
sc.exe delete $serviceName

# User Registry run key
$userRunkeyName = "Application Performance Monitor"
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $userRunkeyName

# Modified .lnk file (Shortcut)
$shortcutPath = "C:\Users\$user\Desktop\Event Viewer.lnk"
Remove-Item -Path $shortcutPath

# Remove a regular account from the administrators group
$existingUsername = "lunhar"
Remove-LocalGroupMember -Group Administrators -Member $existingUsername

# Remove a new administrator account
$newUsername = "ethree"
Remove-LocalGroupMember -Group Administrators -Member $newUsername
Remove-LocalUser -Name $newUsername

# Persistence in UserInitLogonScript
Remove-ItemProperty -Path "HKCU:\Environment" -Name "UserInitMprLogonScript"

# Remove the directory for payloads and all it's content
Remove-Item -Path $scriptAndPayloadLocation -Recurse -Force

# Ensure everything is properly deleted
Clear-RecycleBin -Force
