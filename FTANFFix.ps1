# Define the registry key path
$registryPath = "HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\test"

# Create the registry key
New-Item -Path $registryPath -Force

# Get the current ACL (Access Control List) of the registry key
$acl = Get-Acl -Path $registryPath

# Disable inheritance
$acl.SetAccessRuleProtection($true, $false)

# Remove existing permissions for "Users"
$acl.Access | Where-Object { $_.IdentityReference -eq "Users" } | ForEach-Object { $acl.RemoveAccessRule($_) }

# Define the permission rule for "Creator Owner" (remove Delete permissions)
$creatorOwnerRule = New-Object System.Security.AccessControl.RegistryAccessRule("CREATOR OWNER", "Delete", "Allow")
$acl.AddAccessRule($creatorOwnerRule)

# Define the permission rule for "Local Users" (Everything but Full Control and Delete)
$localUsersRights = [System.Security.AccessControl.RegistryRights]::ReadKey -bor [System.Security.AccessControl.RegistryRights]::WriteKey -bor [System.Security.AccessControl.RegistryRights]::EnumerateSubKeys -bor [System.Security.AccessControl.RegistryRights]::QueryValues
$localUsersRule = New-Object System.Security.AccessControl.RegistryAccessRule("Users", $localUsersRights, "Allow")
$localUsersRuleInheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
$acl.AddAccessRule($localUsersRule)

# Set the modified ACL back to the registry key
Set-Acl -Path $registryPath -AclObject $acl