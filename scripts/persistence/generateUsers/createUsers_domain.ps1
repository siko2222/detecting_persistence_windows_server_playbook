# Import the CSV file
$userList = Import-Csv -Path "users_domain.csv"

# Define the common password
$password = "Really Great Lab Password ! 25" | ConvertTo-SecureString -AsPlainText -Force

foreach ($user in $userList) {
    $username = $user.Username
    $fullName = $user.FullName

    $userProperties = @{
        SamAccountName          = $username
        DisplayName             = $fullName
        UserPrincipalName       = "$username@ad.masterlab.local" # Replace with your domain
        AccountPassword         = $password
        Enabled                 = $true
        ChangePasswordAtLogon   = $true
    }
    
    New-ADUser @userProperties
}