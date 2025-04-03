# Import the CSV file
$userList = Import-Csv -Path "users.csv"

# Define the common password
$password = "Really Great Lab Password ! 25" | ConvertTo-SecureString -AsPlainText -Force

foreach ($user in $userList) {
    $username = $user.Username
    $fullName = $user.FullName

    # Create the new local user
    New-LocalUser -FullName $fullName -Name $username -AccountNeverExpires -PasswordNeverExpires -Password $password
}