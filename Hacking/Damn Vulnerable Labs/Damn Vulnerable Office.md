**Damn Vulnerable Office** es un laboratorio de Active Directory vulnerable basado en la serie de televisión [The Office (US)](https://www.imdb.com/title/tt0386676/). 

>[!note]- DC Provision
```powershell
class User {
    [string]$Name
    [string]$Surname
    [string]$Password

    User([string]$name, [string]$surname, [string]$password) {
        $this.Name = $name
        $this.Surname = $surname
        $this.Password = $password
    }
}

<#
.SYNOPSIS
Promotes the local Windows Server to a Domain Controller if it is not already one.

.DESCRIPTION
The Vuln-CreateAD function checks whether the local server is already acting as an Active Directory Domain Controller. If the server is not a DC, the function installs the Active Directory Domain Services role (if necessary) and promotes the server by creating a new Active Directory forest with the specified domain name.

If the server is already a Domain Controller, no action is taken.

This function must be executed with administrative privileges and will trigger
a system reboot as part of the promotion process.

.PARAMETER Domain
Specifies the fully qualified domain name (FQDN) of the new Active Directory
forest to be created (for example, contoso.local).

.PARAMETER SecureAdminPassword
Specifies the Directory Services Restore Mode (DSRM) password as a SecureString.
This password is required during recovery scenarios and is mandatory for
Domain Controller promotion.

.EXAMPLE
$securePassword = Read-Host "DSRM Password" -AsSecureString
Vuln-CreateAD -Domain "theoffice.local" -SecureAdminPassword $securePassword
#>
function Vuln-CreateAD {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [SecureString]$SecureAdminPassword
    )

    try {
        $isDC = $false
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $null = Get-ADDomain -ErrorAction Stop
            $isDC = $true
        } catch {
            $isDC = $false
        }
        if ($isDC) {
            Write-Host "[!] Server is already a Domain Controller."
            return
        }
        Write-Host "[*] Initializing Domain Controller promotion ($Domain)."
		
        if (-not (Get-WindowsFeature -Name AD-Domain-Services).Installed) {
            Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
        }
        Import-Module ADDSDeployment
        if (-not $SecureAdminPassword) {
	        $SecureAdminPassword = Read-Host -AsSecureString "DC Admin password: "
        }

        Install-ADDSForest `
            -DomainName $Domain `
            -SafeModeAdministratorPassword $SecureAdminPassword `
            -InstallDNS `
            -Force

    } catch {
        throw "Error in Vuln-CreateAD: $_"
    }
}

<#
.SYNOPSIS
Installs a lightweight IIS web service and configures an existing domain user
as a Kerberos-enabled IIS service account.

.DESCRIPTION
The Vuln-InstallIIS function installs IIS (if not present), assigns a
forest-unique Kerberos SPN to an existing domain user, and configures an IIS
Application Pool running under that account.

If another IIS Application Pool created by this function already exists,
it is removed before applying the new configuration.
If the specified SPN exists elsewhere in the forest, it is detached prior
to reassignment.

This function prepares a realistic Kerberoasting scenario using an existing
Active Directory user.

.PARAMETER User
Specifies the SamAccountName of an existing domain user to be used as
the IIS service account.

.PARAMETER SPN
Specifies the service name to be used for the HTTP Service Principal Name.
The final SPN will be created as: HTTP/<SPN>.theoffice.local

.EXAMPLE
Vuln-InstallIIS -User "ryan.howard" -SPN "wuphf"
#>
function Vuln-InstallIIS {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$User,

        [Parameter(Mandatory = $true)]
        [string]$SPN
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        $adUser = Get-ADUser -Filter "SamAccountName -eq '$User'" -ErrorAction Stop
        if (-not $adUser) {
            throw "User '$User' does not exist in Active Directory."
        }

        if (-not (Get-WindowsFeature -Name Web-Server).Installed) {
            Install-WindowsFeature -Name Web-Server -IncludeManagementTools
            Write-Host "[+] IIS installed successfully."
        } else {
            Write-Host "[!] IIS already installed."
        }

        Import-Module WebAdministration -ErrorAction Stop
        $spnValue = "HTTP/$SPN.$((Get-ADDomain).DNSRoot)"
        $appPoolPrefix = "TheOffice-AppPool-"
        $appPoolName = "$appPoolPrefix$User"

        $existingPools = Get-ChildItem IIS:\AppPools | Where-Object { $_.Name -like "$appPoolPrefix*" }
        foreach ($pool in $existingPools) {
            if ($pool.Name -ne $appPoolName) {
                Remove-Item "IIS:\AppPools\$($pool.Name)" -Recurse -Force
                Write-Host "[+] Removed previous IIS Application Pool '$($pool.Name)'."
            }
        }

        $spnOwners = Get-ADObject -Filter "servicePrincipalName -eq '$spnValue'" -Properties servicePrincipalName
        foreach ($obj in $spnOwners) {
            if ($obj.DistinguishedName -ne $adUser.DistinguishedName) {
                Set-ADObject -Identity $obj -Remove @{ servicePrincipalName = $spnValue }
                Write-Host "[+] SPN '$spnValue' removed from '$($obj.Name)'."
            }
        }

        $currentSpns = (Get-ADUser -Identity $User -Properties ServicePrincipalName).ServicePrincipalName
        if ($currentSpns -notcontains $spnValue) {
            Set-ADUser -Identity $User -Add @{ ServicePrincipalName = $spnValue }
            Write-Host "[+] SPN '$spnValue' assigned to '$User'."
        } else {
            Write-Host "[!] SPN '$spnValue' already assigned to '$User'."
        }

        if (-not (Test-Path "IIS:\AppPools\$appPoolName")) {
            New-Item "IIS:\AppPools\$appPoolName" | Out-Null
            Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name processModel.identityType -Value 3
            Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name processModel.userName -Value $User
            Write-Host "[+] Application Pool '$appPoolName' created and configured."
        } else {
            Write-Host "[!] Application Pool '$appPoolName' already exists."
        }

    } catch {
        throw "Error in Vuln-InstallIIS: $_"
    }
}

<#
.SYNOPSIS
Returns the metadata of users to be created in the lab environment.

.DESCRIPTION
The Vuln-UsersMetadata function is a private helper function that returns an array of User objects containing predefined user information for the vulnerable lab environment.

This function centralizes user data management, allowing multiple functions to access the same user information consistently.

.OUTPUTS
Returns an array of User objects with Name, Surname, and Password properties.

.EXAMPLE
$users = Vuln-UsersMetadata
#>
function Vuln-UsersMetadata {
    return @(
        [User]::new("Michael","Scott","Worlds@BestBoss1"),
        [User]::new("Dwight","Schrute","B33ts&Bear2s"),
        [User]::new("Jim","Halpert","Office^Pranks1"),
        [User]::new("Pam","Beesly","Art*Desk2Creative"),
        [User]::new("Ryan","Howard","TempMBA!Fail2"),
        [User]::new("Andy","Bernard","Nard+DogSings3"),
        [User]::new("Stanley","Hudson","ID0ntWant2BeHere!"),
        [User]::new("Kevin","Malone","Chili^Spill1Fun"),
        [User]::new("Angela","Martin","C4ts&RulesOffice"),
        [User]::new("Oscar","Martinez","Logic#MathWins1"),
        [User]::new("Phyllis","Lapin-Vance","Cozy*OfficeLife2"),
        [User]::new("Meredith","Palmer","Casual!Policy1"),
        [User]::new("Creed","Bratton","Unknown+Past4Life"),
        [User]::new("Kelly","Kapoor","Drama^TextQueen1"),
        [User]::new("Toby","Flenderson","HR-NoFun4Ever")
    )
}

<#
.SYNOPSIS
Returns a random weak password for lab purposes.

.DESCRIPTION
The Vuln-GetWeakPassword function provides a password selected randomly from a predefined set of weak passwords suitable for lab environments.

.OUTPUTS
Returns a string containing a weak password.

.EXAMPLE
$pwd = Vuln-GetWeakPassword
#>
function Vuln-GetWeakPassword {
    $weakPasswords = @(
        "!@#ABC123abc",
        "!@#123ASDasd",
        "123!@#asdASD",
        "123!@#abcABC",
        "@@@###poi321654",
        "!4@tePAssw0rds",
        "!BaByGiRl_89!",
        "!TEXas!76542",
        "#1Everything",
        "#1PapiChulo1#"
    )
    return Get-Random -InputObject $weakPasswords
}

<#
.SYNOPSIS
Creates Active Directory user accounts.

.DESCRIPTION
The Vuln-AddUsers function creates multiple user accounts in Active Directory
based on predefined metadata. Each user is created with a specific naming convention (firstname.lastname) and their corresponding attributes such as GivenName, Surname, DisplayName, and initial password.

The function checks if each user already exists before attempting creation to
avoid duplication errors. All users are created as enabled accounts with the
PasswordNeverExpires flag set to true.

This function requires the Active Directory PowerShell module and must be
executed with appropriate permissions to create user accounts in the domain.

.EXAMPLE
Vuln-AddUsers
#>
function Vuln-AddUsers {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $Users = Vuln-UsersMetadata

        foreach ($user in $Users) {
            $samAccountName = "$($user.Name).$($user.Surname)".ToLower()
            $userPrincipalName = "$samAccountName@$((Get-ADDomain).DNSRoot)"
            $displayName = "$($user.Name) $($user.Surname)"

            if (Get-ADUser -Filter "SamAccountName -eq '$samAccountName'" -ErrorAction SilentlyContinue) {
                Write-Host "[!] User '$samAccountName' already exists."
                continue
            }

            $params = @{
                Name                 = $samAccountName
                GivenName            = $user.Name
                Surname              = $user.Surname
                SamAccountName       = $samAccountName
                UserPrincipalName    = $userPrincipalName
                DisplayName          = $displayName
                AccountPassword      = (ConvertTo-SecureString $user.Password -AsPlainText -Force)
                Enabled              = $true
                PasswordNeverExpires = $true
                Office               = "Scranton"
            }

            New-ADUser @params
            Write-Host "[+] User '$samAccountName' created successfully."
        }

    } catch {
        throw "Error in Vuln-AddUsers: $_"
    }
}

<#
.SYNOPSIS
Adds a specified user to the Domain Admins group and disables the default Administrator account.

.DESCRIPTION
The Vuln-ChangeAdmin function performs security-related actions in Active Directory:
1. Removes all current members from the Domain Admins group except built-in accounts.
2. Adds the specified user account to the Domain Admins group, granting full administrative privileges.
3. Disables the built-in Administrator account to comply with security best practices.

This function verifies that the specified user exists before attempting to add them to the Domain Admins group. It preserves built-in administrative accounts while removing other members that may have been added in previous executions.

This function requires the Active Directory PowerShell module and must be executed with Domain Admin or equivalent permissions.

.PARAMETER User
Specifies the SamAccountName of the user to be added to the Domain Admins group.
This parameter is mandatory and must correspond to an existing user account in the domain.

.EXAMPLE
Vuln-ChangeAdmin -User "michael.scott"

.EXAMPLE
Vuln-ChangeAdmin -User "dwight.schrute"
#>
function Vuln-ChangeAdmin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$User
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        $adUser = Get-ADUser -Filter "SamAccountName -eq '$User'" -ErrorAction Stop
        if (-not $adUser) {
            throw "User '$User' not found in Active Directory."
        }

        $domainAdminsGroup = Get-ADGroup -Identity "Domain Admins" -ErrorAction Stop
        $currentMembers = Get-ADGroupMember -Identity $domainAdminsGroup
        $builtInAccounts = @("Administrator", "Domain Admins", "Enterprise Admins")
        foreach ($member in $currentMembers) {
            if ($member.SamAccountName -notin $builtInAccounts -and $member.SamAccountName -ne $User) {
                Remove-ADGroupMember -Identity $domainAdminsGroup -Members $member -Confirm:$false
                Write-Host "[+] Removed '$($member.SamAccountName)' from Domain Admins group."
            }
        }

        $isMember = Get-ADGroupMember -Identity $domainAdminsGroup | Where-Object { $_.SamAccountName -eq $User }
        if (-not $isMember) {
            Add-ADGroupMember -Identity $domainAdminsGroup -Members $adUser
            Write-Host "[+] User '$User' added to Domain Admins group successfully."
        } else {
            Write-Host "[!] User '$User' is already a member of Domain Admins."
        }

        $adminAccount = Get-ADUser -Filter "SamAccountName -eq 'Administrator'" -ErrorAction Stop
        if ($adminAccount.Enabled) {
            Disable-ADAccount -Identity $adminAccount
            Write-Host "[+] Built-in Administrator account disabled successfully."
        } else {
            Write-Host "[!] Built-in Administrator account is already disabled."
        }

    } catch {
        throw "Error in Vuln-ChangeAdmin: $_"
    }
}

<#
.SYNOPSIS
Stores user passwords in their Active Directory Description fields.

.DESCRIPTION
The Vuln-PasswordInDescription function intentionally creates a security vulnerability by storing users' passwords in plain text within their Active Directory Description attributes. This makes passwords easily discoverable through LDAP queries and standard AD enumeration.

WARNING: This function creates a significant security vulnerability and should ONLY be used in isolated lab environments for educational purposes.

This function requires the Active Directory PowerShell module and must be executed with appropriate permissions to modify user attributes.

.PARAMETER User
Specifies the SamAccountName of the user whose password will be stored in the Description field.

.EXAMPLE
Vuln-PasswordInDescription -User "kelly.kapoor"
#>
function Vuln-PasswordInDescription {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$User
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $Users = Vuln-UsersMetadata

		$userObj = $Users | Where-Object { "$($_.Name).$($_.Surname)".ToLower() -eq $User.ToLower() }
		if (-not $userObj) {
			throw "User '$User' not found in metadata."
		}
		
		$samAccountName = "$($userObj.Name).$($userObj.Surname)".ToLower()
		$adUser = Get-ADUser -Filter "SamAccountName -eq '$samAccountName'" -ErrorAction SilentlyContinue
		if (-not $adUser) {
			throw "User '$samAccountName' not found in Active Directory."
		}
		Set-ADUser -Identity $adUser -Description "Pass: $($userObj.Password)"
		Write-Host "[+] Password stored in Description field for '$samAccountName' successfully."

    } catch {
        throw "Error in Vuln-PasswordInDescription: $_"
    }
}

<#
.SYNOPSIS
Configures a user so that their password is equal to their username.

.DESCRIPTION
The Vuln-UserAsPass function introduces a deliberate security vulnerability by
assigning a Fine-Grained Password Policy (FGPP) to a specific user, allowing
their password to be set equal to their SamAccountName.

Only one user can have this vulnerability at a time.

If the function is executed for a different user while the vulnerability is
already active:
- The previous user is restored
- The vulnerability is then applied to the new user

WARNING: This function intentionally weakens password security and must ONLY
be used in isolated lab environments for educational or testing purposes.

.PARAMETER User
Specifies the SamAccountName of the user to be configured with
username-as-password authentication.

.EXAMPLE
Vuln-UserAsPass -User "phyllis.lapin-vance"
#>
function Vuln-UserAsPass {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$User
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $policyName = "WeakExceptional-Policy"

        $targetUser = Get-ADUser -Filter "SamAccountName -eq '$User'" -Properties Description -ErrorAction Stop

        $policy = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$policyName'" -ErrorAction SilentlyContinue
        if (-not $policy) {
            New-ADFineGrainedPasswordPolicy -Name $policyName -Precedence 1 -MinPasswordLength 8 -PasswordHistoryCount 0 -ComplexityEnabled $false -LockoutThreshold 0 -ErrorAction Stop
            Write-Host "[+] Fine-Grained Password Policy '$policyName' created."
        } else {
	        Write-Host "[!] Fine-Grained Password Policy '$policyName' already exists."
        }

		$metadataUsers = Vuln-UsersMetadata
		foreach ($assigned in $assignedUsers) {
		    if ($assigned.SamAccountName -ne $User) {
		        $oldUser = Get-ADUser -Identity $assigned -ErrorAction Stop
		        $metaUser = $metadataUsers | Where-Object {
		            "$($_.Name).$($_.Surname)".ToLower() -eq $oldUser.SamAccountName.ToLower()
		        }
		        if ($metaUser) {
		            Set-ADAccountPassword -Identity $oldUser -Reset -NewPassword (ConvertTo-SecureString $metaUser.Password -AsPlainText -Force)
		            Write-Host "[+] Original password restored for '$($oldUser.SamAccountName)'."
		        }
		        else {
		            Write-Host "[!] No metadata found for '$($oldUser.SamAccountName)'. Password not restored."
		        }
		
		        Remove-ADFineGrainedPasswordPolicySubject -Identity $policyName -Subjects $oldUser -Confirm:$false
		        Write-Host "[+] Password policy removed from '$($oldUser.SamAccountName)'."
		    }
		}

        if ($assignedUsers.SamAccountName -contains $User) {
            Write-Host "[!] User '$User' already has the FGPP assigned."
		} else {
	        Add-ADFineGrainedPasswordPolicySubject -Identity $policyName -Subjects $targetUser -ErrorAction Stop
		}
        Set-ADAccountPassword -Identity $targetUser -Reset -NewPassword (ConvertTo-SecureString $targetUser.SamAccountName -AsPlainText -Force)
        Write-Host "[+] Password for '$User' is now equal to the username."

    } catch {
        throw "Error in Vuln-UserAsPass: $_"
    }
}

<#
.SYNOPSIS
Configures multiple users with the same plaintext password to simulate a password spraying vulnerability.

.DESCRIPTION
The Vuln-PasswordSpraying function intentionally weakens security by assigning
the same plaintext password to multiple Active Directory user accounts.

The function validates that at least two users are provided, as password spraying
is only meaningful when applied across multiple accounts.

WARNING: This function intentionally introduces a severe security vulnerability
and must ONLY be used in isolated lab environments for educational purposes.

.PARAMETER Users
Comma-separated list of SamAccountNames to which the password will be applied.
At least two users are required.

.PARAMETER Password
Plaintext password to assign to all specified users.

.EXAMPLE
Vuln-PasswordSpraying -Users "jim.halpert,pam.beesly" -Password "DunderMifflin1!"
#>
function Vuln-PasswordSpraying {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Users,

        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        $userList = $Users.Split(",") | ForEach-Object { $_.Trim().ToLower() }

        if ($userList.Count -lt 2) {
            throw "Password spraying requires at least two users."
        }

        $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force

        foreach ($user in $userList) {
            $adUser = Get-ADUser -Filter "SamAccountName -eq '$user'" -ErrorAction SilentlyContinue
            if (-not $adUser) {
                Write-Host "[!] User '$user' not found. Skipping."
                continue
            }

            Set-ADAccountPassword -Identity $adUser -Reset -NewPassword $securePassword
            Write-Host "[+] Password for '$user' set to spraying password."
        }

    } catch {
        throw "Error in Vuln-PasswordSpraying: $_"
    }
}

<#
.SYNOPSIS
Disables Kerberos pre-authentication for a user and sets a weak password.

.DESCRIPTION
The Vuln-ASREProast function introduces a deliberate security vulnerability by
disabling the Kerberos pre-authentication flag for a specified user. This allows for offline AS-REP attacks.

If another user already has this vulnerability, it is reverted:
- The FGPP is removed (if used)
- The original password from metadata is restored
- Pre-authentication is re-enabled

The target user's password is replaced with one of several weak passwords

WARNING: This function intentionally weakens password security and must ONLY
be used in isolated lab environments for educational or testing purposes.

.PARAMETER User
Specifies the SamAccountName of the user to be configured for AS-REP Roasting.

.EXAMPLE
Vuln-ASREProast -User "standley.hudson"
#>
function Vuln-ASREProast {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$User
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        $metadataUsers = Vuln-UsersMetadata
        $asrepFlag = 4194304
        $previousUsers = Get-ADUser -Filter "UserAccountControl -band $asrepFlag" -Properties UserAccountControl

        foreach ($prev in $previousUsers) {
            if ($prev.SamAccountName -ne $User) {
                $metaUser = $metadataUsers | Where-Object {
                    "$($_.Name).$($_.Surname)".ToLower() -eq $prev.SamAccountName.ToLower()
                }
                if ($metaUser) {
                    Set-ADAccountPassword -Identity $prev.SamAccountName -Reset -NewPassword (ConvertTo-SecureString $metaUser.Password -AsPlainText -Force)
                    Write-Host "[+] Original password restored for '$($prev.SamAccountName)'."
                }
                $newUac = $prev.UserAccountControl -band (-bnot $asrepFlag)
                Set-ADUser -Identity $prev.SamAccountName -Replace @{userAccountControl=$newUac}
                Write-Host "[+] Kerberos pre-authentication re-enabled for '$($prev.SamAccountName)'."
            }
        }

        # Obtener el usuario objetivo antes de usarlo
        $targetUser = Get-ADUser -Filter "SamAccountName -eq '$User'" -Properties UserAccountControl -ErrorAction Stop
        if (-not $targetUser) {
            throw "User '$User' not found in Active Directory."
        }

		$randomPassword = Vuln-GetWeakPassword
        Set-ADAccountPassword -Identity $targetUser -Reset -NewPassword (ConvertTo-SecureString $randomPassword -AsPlainText -Force)
        Write-Host "[+] Password for '$User' changed to a weak password."
        $newUac = $targetUser.UserAccountControl -bor $asrepFlag
        Set-ADUser -Identity $targetUser -Replace @{userAccountControl=$newUac}
        Write-Host "[+] Kerberos pre-authentication disabled for '$User'."

    } catch {
        throw "Error in Vuln-ASREProast: $_"
    }
}

<#
.SYNOPSIS
Changes the password of a user to a weak password for Kerberoasting lab exercises.

.DESCRIPTION
The Vuln-Kerberoast function sets the password of the specified user to a randomly selected weak password using Vuln-GetWeakPassword. It also ensures the user exists before changing the password.

WARNING: This function intentionally weakens password security and must ONLY
be used in isolated lab environments for educational or testing purposes.

.PARAMETER User
Specifies the SamAccountName of the user whose password will be set for Kerberoast.

.EXAMPLE
Vuln-Kerberoast -User "kevin.malone"
#>
function Vuln-Kerberoast {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$User
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        $targetUser = Get-ADUser -Filter "SamAccountName -eq '$User'" -ErrorAction Stop
        if (-not $targetUser) {
            throw "User '$User' not found in Active Directory."
        }

        $randomPassword = Vuln-GetWeakPassword
        Set-ADAccountPassword -Identity $targetUser -Reset -NewPassword (ConvertTo-SecureString $randomPassword -AsPlainText -Force)
        Write-Host "[+] Password for '$User' set to a weak password."

    } catch {
        throw "Error in Vuln-Kerberoast: $_"
    }
}

function Vuln-Install {
	Vuln-CreateAD -Domain "theoffice.local"
	Vuln-AddUsers
	Vuln-ChangeAdmin -User "michael.scott"
	
	# Vulnerabilities
	Vuln-UserAsPass -User "phyllis.lapin-vance"
	Vuln-PasswordInDescription -User "kelly.kapoor"
	Vuln-PasswordSpraying -Users "jim.halpert,pam.beesly" -Password "DunderMifflin1!"
	Vuln-ASREProast -User "stanley.hudson"
	Vuln-InstallIIS -User "ryan.howard" -SPN "wuphf"; Vuln-Kerberoast -User "ryan.howard"
}
```
