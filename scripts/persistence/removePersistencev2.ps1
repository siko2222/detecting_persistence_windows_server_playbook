# Base script path and user
$scriptAndPayloadLocation = "C:\Program Files\Application Support"
$user = $Env:UserName

# Scheduled task
$taskName = "SynchronizeTimeAtBootup"
$taskPath = "\Microsoft\Windows\Time Synchronization\"
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -TaskPath $taskPath

# Service
$serviceName = "ALG"
sc.exe config $serviceName obj= "NT AUTHORITY\LocalService" # Run as NT AUTHORITY\LocalService
sc.exe config $serviceName binpath=  "C:\Windows\System32\alg.exe"
sc.exe config $serviceName start= demand
Stop-Service -Name $serviceName

# User Registry run key
$userRunkeyName = "Application Performance Monitor"
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $userRunkeyName

# Machine Registry run key
$computerRunkeyName = "Startup optimizer"
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $computerRunkeyName

# Modified .lnk file (Shortcut)
$shortcutPath = "C:\Users\$user\Desktop\Task Manager.lnk"
Remove-Item -Path $shortcutPath

# Remove a regular account from the administrators group
$existingUsername = "annbro"
Remove-LocalGroupMember -Group Administrators -Member $existingUsername

# Remove a new administrator account
$newUsername = "thojon"
Remove-LocalGroupMember -Group Administrators -Member $newUsername
Remove-LocalUser -Name $newUsername

# Persistence in UserInitLogonScript
Remove-ItemProperty -Path "HKCU:\Environment" -Name "UserInitMprLogonScript"

# Remove the directory for payloads and all it's content
Remove-Item -Path $scriptAndPayloadLocation -Recurse -Force

# Remove the temp folder
Remove-Item -Path "C:\Temp" -Recurse -Force

# Remove the hijacked dll (V2)
$dllPath = "C:\Program Files (x86)\Microsoft\Edge\Application\profapi.dll"
Remove-Item -Path $dllPath -Force

# Remove the IIS module (V2)
# Define the module name
$moduleName = "AuthenticationModule.AuthModule"
$inetBinPath = "C:\inetpub\wwwroot\bin"
Import-Module WebAdministration
Remove-WebConfigurationProperty -Filter "system.webServer/modules" -PSPath "IIS:\" -Name "." -AtElement @{name=$moduleName}
iisreset # Reset IIS
Remove-Item -Path $inetBinPath -Recurse

# Remove firewall rules
Remove-NetFirewallRule -Name '{b1c4c56c-b24f-43f3-bf8f-0694006cd2bd}', '{1cf7d2bf-c7c7-470f-9fd8-5b0a7fbebb57}'

# Ensure everything is properly deleted
Clear-RecycleBin -Force
