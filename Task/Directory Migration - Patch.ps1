<#
    TODO
    * Reimplement ExcludeUsers (Should I wait for array parameters?)
#>
[CmdletBinding()]
param(
    # [Parameter(ParameterSetName="IgnoreMappingErrors")]
    # [Parameter(ParameterSetName="IgnoreOldProfiles")]
    # [ValidateRange(0,1000)]
    # [int]$IgnoreProfilesOlderThanDays=0,
    [Parameter(Mandatory, Position = 0, HelpMessage = @"
# Profile Mapping Logic

For each profile on a machine, ImmyBot gets the SID of the associated user, and determines if that SID
is Local, ActiveDirectory, or AzureAD.

ImmyBot will not attempt to migrate the machine if it can't find a target account in the destination directory for every profile.

You can avoid this by limiting the profiles using this parameter.

## Workgroup Migrations

** Select WorkplaceJoined instead of Local. **

In situations where machines are on a Workgroup, it is possible and often likely that when setting up Outlook, OneDrive or any other Office app
that the user was prompted to "Allow the organization to manage this device" which joins _just that profile_ to Azure AD. This is also known as a "User Join" or "Azure AD Registered"

When this happens, the UPN of the user is placed under the HKEY_CURRENT_USER and we look for that UPN in the destination directory.

In this way a generically named user profile like C:\Users\FrontDesk that is actually used by jane.doe@company.com can be accurately mapped.

If the user opted to not "Allow the organization to manage this device" we then look for the default email address in the default Outlook profile in the destination directory.


"@)]
    [ValidateSet('ActiveDirectory', 'AzureAD', 'Local', 'All', 'WorkplaceJoined')]
    [string]$ProfileTypesToMigrate,
    [Parameter(Position = 2, HelpMessage = @"    
Use this to avoid migrating profiles that don't have a matching identity in the target AzureAD. (Like local admin accounts)

Enter a comma separated list of search strings you would like to exclude.

Does a case insensitive "Contains" search.

For example, C:\Users\ITAdmin would be excluded if you enter ITAdmin or admin
"@)]
    [string]$ProfileNamesToAvoid,
    [Parameter(Position = 3, HelpMessage = 'Enable this to allow Immy to find usernames in the target directory based on profile foldername')]
    [switch]$FuzzyMatch,
    [Parameter(Position = 4, HelpMessage = "Not recommended. This will suppress errors when Immy can't find a user to map a profile to.")]
    [switch]$IgnoreProfilesWithoutMatchingUsers,
    [Parameter(Position = 5, HelpMessage = "Use this in a hostile takeover situation where you are unable to install an agent on the domain controller. The domain controller is used to verify that user is active and still exists (to prevent trying to map profiles to users for employees that are no longer with the company)")]
    [switch]$SkipDomainControllerLookup
)
dynamicparam {
    New-ParameterCollection -Parameters @(
        Get-DirectoryTypeParameters -DirectoryTypeVariableName 'DestinationDirectoryType'
        $DirectoryType = $DestinationDirectoryType
        switch ($DirectoryType) {
            'AzureAD' {
                New-HelpText -Name "MappingHint" -HelpMessage "If the profile folder name does not match the UPN prefix in the destination directory, Immy will use the email address configured in the default Outlook profile."
                Get-JoinAzureADParameters
                New-CheckboxParameter -Name LimitToPrimaryUser -Position 6 -HelpMessage (@"
This only works in Hybrid Joined environments!

We ask Azure AD for the OnPremisesSecurityIdentifier of the primary user.

Then, we only migrate the profile associated to that user.

This is useful if you don't want to have to exclude all profiles that can't be mapped.
"@ | Out-Markdown)
            }
            'ActiveDirectory' {
                New-JoinableDomainsDropDown
                New-Parameter -Name StaticallyAssignDomainControllerAsDNSServer -Position 6 -Type 'Boolean' -DefaultValue $false -HelpMessage 'Useful for ensuring the machines can hit the new DC'
            }
        }
    )
}
begin {
    $VerbosePreference = 'continue'
    Invoke-ImmyCommand {
        Get-WmiObject Win32_OperatingSystem -Property Caption | ForEach-Object {
            if ($_.Caption -like "*home*") {
                throw "$($_.Caption) is not supported" 
            }
        }
    }

    #region Functions
    $TestResults = @{}
    $TestResults.AllProfilesHaveDestinationUsers = $true
    [bool]$OnPremisesSyncEnabled = $false
    
    if ($DirectoryType -eq 'AzureAD' -and $ProfileTypesToMigrate -match 'AzureAD|All|WorkplaceJoined|ActiveDirectory') {
        try {
            $onPremisesSyncEnabledResult = Get-MSGraphApiResults -ErrorAction Stop -Endpoint organization -Select onPremisesSyncEnabled | Select-Object -Expand onPremisesSyncEnabled
        } catch {
            $_.Exception | Write-Variable
            throw
        }
        try {
            $OnPremisesSyncEnabled = !!$onPremisesSyncEnabledResult
        } catch {
            Write-Warning ($_ | Out-String)
            $onPremisesSyncEnabledResult | Format-List * | Out-String | Write-Verbose
        }
        if ($LimitToPrimaryUser -and !$OnPremisesSyncEnabled) {
            throw "LimitToPrimaryUser selected but $TenantName doesn't have Azure AD Sync setup"
        }
    }

    if ($method -eq 'set') {
        if ($RebootPreference -like 'suppress') {
            $RebootPreference = 'IfNecessary'
            # throw "Reboots need to be allowed for Azure AD Migration. Please re-run session with reboots allowed."
        }
    }
    $PSDefaultParameterValues."Invoke-RestMethod:ProgressAction" = 'SilentlyContinue'
    $PSDefaultParameterValues."Invoke-WebRequest:ProgressAction" = 'SilentlyContinue'
    # $PSDefaultParameterValues."Write-Progress:Status" = {
    #     $FunctionName = Get-PSCallStack | ?{$_.FunctionName -notlike '<ScriptBlock>*'} | select -First 1 -Expand FunctionName
    #     if(!$FunctionName)
    #     {
    #         if($MaintenanceTaskName)
    #         {
    #             "$MaintenanceTaskName - $method"
    #         } elseif($SoftwareName)
    #         {
    #             $SoftwareName
    #         }
    #     } else
    #     {
    #         $FunctionName
    #     }
    # }

    function Test-LocalProfile {
        param(
            $Profiles,
            [switch]$RemoveInvalidLinks
        )

        $Result = $true
        $OffendingProfiles = $null

        Write-Progress "Verifying all profiles are linked to one identity"
        $ProfilesLinkedToMultipleIdentities = $Profiles | Group-Object ProfilePath | Where-Object {$_.Count -gt 1} | ForEach-Object {$_.Group}
        if ($ProfilesLinkedToMultipleIdentities) {
            Write-Warning "`r`n$(($ProfilesLinkedToMultipleIdentities | Format-List * | Out-String))"
            $Result = $false
        }

        Write-Progress "Verifying all identities are linked to one profile"
        $IdentitiesLinkedToMultipleProfiles = $Profiles | Where-Object {$_.UPN} | Group-Object UPN | Where-Object {$_.Count -gt 1}
        $IdentitiesLinkedToMultipleProfiles | ForEach-Object {
            Write-Warning "$($_.Name) is linked to $($_.Count) profile(s)"
            $OffendingProfiles = $_.Group
            Write-Host -Fore Yellow ($OffendingProfiles | Format-Table SID, ProfilePath, UPN, UPNSource, DirectoryType | Out-String)
            $Result = $false
        }

        if ($OffendingProfiles -and $Repair -eq $true) {
            # TODO: This is rare though
        }
        
        return $Result
    }

    function Get-AzureADUserJoinInfo {
        Invoke-HKCU -IncludeUnlinked -ScriptBlock {
            $BasePath = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo"
            if (Test-Path $BasePath) {
                Get-ItemProperty -Path "$BasePath\*\" | ForEach-Object {
                    $acl = Get-Acl ($UserProfile.ProfilePath + "\ntuser.dat")
                    $owner = $null
                    $ownerSID = $null
                    $ownerDomainSID = $null

                    try {
                        $owner = $acl.GetOwner([System.Security.Principal.NTAccount]).Value
                        $ownerSID = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
                        $ownerDomainSID = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).AccountDomainSid
                    } catch {
                        Write-Debug "Error getting ACL: $_"
                        $null
                    }

                    [PSCustomObject][Ordered]@{
                        ProfilePath           = $UserProfile.ProfilePath
                        Owner                 = $owner
                        OwnerSID              = $ownerSID
                        OwnerDomainSID        = $ownerDomainSID
                        UserEmail             = $_.UserEmail
                        IdpDomain             = $_.IdpDomain
                        TenantId              = $_.TenantId
                        DeviceDisplayName     = $_.DeviceDisplayName
                        OsVersion             = $_.OsVersion
                        DnsFullyQualifiedName = $_.DnsFullyQualifiedName
                        TransportKeyStatus    = $_.TransportKeyStatus
                        AikCertStatus         = $_.AikCertStatus
                        AttestationLevel      = $_.AttestationLevel
                        LastSyncTime          = (Get-Date "1970-01-01 00:00:00.000Z") + ([TimeSpan]::FromSeconds($_.LastSyncTime))
                        PSChildName           = $_.PSChildName
                        # PSProperty            = $_
                        # Path                  = $_.PSPath
                        # Values                = Get-Item -Path $_.PSPath | ForEach-Object { $item = $_; $item.GetValueNames() | ForEach-Object { New-Object PSObject -Property ([Ordered]@{Name = $_; Value = $item.GetValue($_) })}}
                    }
                }
            } else {
                Write-Debug "$BasePath does not exist"
            }
        }
    }

    #endregion

    #region Check Prerequisites
    Write-Progress "Destination DirectoryType: $DirectoryType"
    switch ($DirectoryType) {
        "AzureAD" {
            try {
                $null = Connect-ImmyAzureAD -ErrorAction Stop
            } catch {
                throw "Unable to connect to Azure AD, ensure Secret is not expired under Settings->Azure`r`n$($_.Exception.Message)"
            }
            # Get-AzureADVerifiedDomains
            if (($OAuthInfo)?.accessToken) {
                Write-Progress "Retrieving destination TenantId from OAuthInfo"
                $ParsedJwt = Parse-JWT $OAuthInfo.accessToken
                $DestinationTenantID = $ParsedJwt | ForEach-Object { $_.tid }
                $DEMUsername = $ParsedJwt | ForEach-Object { $_.upn }
            }
            if ($DEMUsername) {
                $DestinationTenantDomain = $DEMUsername -Split '@' | Select-Object -Last 1 | ForEach-Object {$_.Trim()}
            }
            if (!$DestinationTenantID) {
                if (!$DEMUsername) {
                    throw "Unable to determine destination tenantId as DEMUsername is null"
                }
                Write-Progress "Looking up Destination AzureTenantId for $DestinationTenantDomain"
                if (!$DestinationTenantDomain) {
                    throw "Aborting: Invalid DeviceEnrollmentManagerUsername: $DEMUsername"
                }
                Write-Progress "Verifying Tenant exists for $DestinationTenantDomain" -PercentComplete 5
                $DestinationTenantID = Get-AzureADTenantID -DomainName $DestinationTenantDomain
                if (!$DestinationTenantID) {
                    throw "$DestinationTenantDomain is not a valid Azure AD Tenant Domain."
                }
            }
            $Computer = Get-ImmyComputer
            if ($null -eq $Computer.TenantPrincipalId -or $Computer.TenantPrincipalId -ne $DestinationTenantID) {
                throw "Aborting: Computer not associated with the same tenant as the DEM user`r`nOpen the computer in Immy, go to the Onboarding tab, select the appropriate tenant, click Save and then Skip Onboarding"
            }
            Write-Progress "Getting AzureAD Join Status..."
            $AzureADStatus = Get-AzureADJoinStatus
            Write-Progress "CurrentTenantID:     $($AzureADStatus.TenantDetails.TenantId)"
            Write-Progress "DestinationTenantID: $DestinationTenantID"
            Write-Progress "DomainJoined: $($AzureADStatus.DeviceState.DomainJoined)"
            $HybridJoined = $AzureADStatus.DeviceState.DomainJoined -and $AzureADStatus.DeviceState.AzureAdJoined
            Write-Progress "HybridJoined: $HybridJoined"

            if ($null -eq (($AzureADStatus)?.TenantDetails)?.TenantId) {
                Write-Warning "Machine is not joined to AzureAD. Should be joined to tenant $DestinationTenantID"
                $TestResults.AzureADJoined = $false
            } elseif ($AzureADStatus.TenantDetails.TenantId -ne $DestinationTenantID) {
                Write-Warning "Machine is joined to the incorrect AzureAD"
                $TestResults.CorrectAzureADTenant = $false
            }
            Write-Progress "Destination $DestinationTenantDomain ($DestinationTenantID) OnPremisesSyncEnabled: $onPremisesSyncEnabled"
            $UserJoinInfo = Get-AzureADUserJoinInfo
            if ($UserJoinInfo) {
                Write-Verbose "AzureADUserJoinInfo:`r`n$($UserJoinInfo | Format-List * | Out-String)" -Verbose
            } else {
                Write-Verbose "Not User Joined"
            }
            # After deleting the local users that previously owned the profile, the SID will remain but the Owner (NTAccount formatted) will be gone.
            #14393
            $WindowsVersion = Invoke-ImmyCommand {
                [System.Environment]::OSVersion.Version
            }
            $IgnoreWorkplaceJoin = $WindowsVersion.Major -eq 10 -and $WindowsVersion.Build -gt 14393
            if (!$IgnoreWorkplaceJoin) {
                $TestResults."NotAzureADUserRegistered" = $UserJoinInfo | Test-All { !$_.Owner }
                if (!$TestResults."NotAzureADUserRegistered") {
                    Write-Warning "This version of Windows ($WindowsVersion) will fail Azure AD Join since there are Workplace Joined profiles"
                }
            } else {
                Write-Verbose "Ignoring Workplace Joined Profile since Windows Version $WindowsVersion is greater than 14393 (1603)"
            }
            Write-Progress "NotAzureADUserRegistered: $($TestResults.NotAzureADUserRegistered)" 
        }
        "ActiveDirectory" {
            # TODO: Verify connectivity to domain controller?
        }
    }
    #endregion

}
process {
    $Computer = Get-ImmyComputer
    if ($Domain) {
        Write-Progress "Domain: $($Domain | Format-List * | Out-String)"
        if ($Domain -is [Hashtable]) {
            Write-Progress "Domain is Hashtable"
            $Domain = New-Object PSObject -Property $Domain
        } else {
            Write-Progress "Domain is $($Domain.GetType().name)"
            $Domain = $Domain
        }
        Write-Progress "Domain: $($Domain | Format-List * | Out-String)"
        if ($Domain.DomainDNSName) {
            $DirectoryType = "ActiveDirectory"
        }

         $DomainController = Get-ImmyDomainController -DomainSID $Domain.DomainSID
    }
    <#
    2022-11-17 - Attempted to remove MappingMode and refactor script into one big loop after adding Fuzzy matching
    [bool]$OnPremisesSyncEnabled = Get-MSGraphApiResults -Endpoint organization -Select onPremisesSyncEnabled
    $OnPremisesSyncEnabled
    return
    #>

    # ImmyBot AzureAD Migration Script

    # $VerbosePreference = 'Continue'
    # $DebugPreference = 'Continue'
    [Array]$ProfileNamesToAvoidArray = @()
    $ProfileNamesToAvoidArray += $ProfileNamesToAvoid -Split '[,;:|]' | ForEach-Object {$_.Trim()}
    $ProfileNamesToAvoidArray += $AccountsToAvoid -Split '[,;:|]' | ForEach-Object {$_.Trim()}

    # DirectoryType is the DestinationDirectoryType
    
    if ($LimitToSpecificUsername -and !$LimitToSpecificProfile) {
        # TODO Lookup the local user, get its SID, then translate to profile name
        $LimitToSpecificProfile = $LimitToSpecificUsername
    }
    
    Write-Progress "Fetching User Profiles"
    $GetUserProfileParams = @{}
    if ($LimitToPrimaryUser) {
        Write-Warning "Limiting to PrimaryUser"
        $GetUserProfileParams.LimitToPrimaryUser = $true
    }
    switch ($DirectoryType) {
        "AzureAD" {
            $GetUserProfileParams.ResolveIdentity = $true
        }
        "ActiveDirectory" {
            # -Basic is really just needed in the event that we don't have access to the original directory
            $GetUserProfileParams.Basic = $true
        }
    }
    if ($SkipDomainControllerLookup) {
        Write-Progress "Skipping User Profile Lookup against domain controller"
        $GetUserProfileParams.Basic = $true
    }
    $Profiles = Get-UserProfile @GetUserProfileParams #-ErrorAction Stop
    $Profiles | Write-Count "Profile"
    #region Business Logic
    ###########################################################################
    Write-Progress -Id 2 -Activity "Finding destination SIDs for Profiles"
    
    $ProfilesToMigrate = $Profiles | ForEach-Object {
        # This logic will attempt to map the profile to a user in the target directory (Azure AD or Active Directory)
        $UserProfile = $_
        $AADUser = $null
        $FuzzyMatched = $false
        $DestinationUser = $null
        $PSDefaultParameterValues."Write-Progress:Status" = $UserProfile.ProfilePath
        $PSDefaultParameterValues."Write-Progress:ParentId" = 2
        $ProfilesArray = @($Profiles)
        $Index = [Array]::IndexOf($ProfilesArray, $UserProfile)
        # Check if the index was found
        if ($Index -ne -1) {
            $PSDefaultParameterValues."Write-Progress:Id" = $Index + 3
        } else {
            Write-Error "UserProfile not found in Profiles"
        }
        
        Write-Verbose ($UserProfile | Format-List * | Out-String)
        $ProfileFolderName = Split-Path $_.ProfilePath -Leaf | ForEach-Object { $_.ToLower()}
        
        if ($UserMapping -and $UserMapping."$ProfileFolderName") {
            Write-Progress "Found UserMapping for Profile folder name $ProfileFolderName"
            $MappedDestinationUser = $UserMapping."$ProfileFolderName"
            if ($MappedDestinationUser -notlike "*@*.*") {
                throw "Found mapped user $MappedDestinationUser but expected destination was not in UPN (user@domain.com) format"
            }
            switch ($DirectoryType) {
                "AzureAD" {
                    Write-Progress "Looking up $MappedDestinationUser in $DirectoryType"
                    $PotentialDestinationUsers = Get-ImmyAzureADUser -StartsWith $MappedDestinationUser -FieldName userPrincipalName
                    $PotentialDestinationUsers | Should-HaveOne "Azure AD user with UPN $MappedDestinationUser"
                    $DestinationUser = $PotentialDestinationUsers
                }
                "ActiveDirectory" {
                    # TODO: Lookup manually mapped users in AD
                }
            }
        } else {
            if ($LimitToSpecificProfile) {
                $LimitToSpecificProfileUri = [Uri]$LimitToSpecificProfile
                if ($LimitToSpecificProfileUri.IsAbsoluteUri) {
                    $LimitToSpecificProfile = Split-Path $LimitToSpecificProfile -Leaf
                    Write-Verbose "AbsoluteUri to profile provided, Getting Directory Name: $($LimitToSpecificProfile)"
                } elseif ($LimitToSpecificUsername -like "*@*") {
                    Write-Progress "Splitting supplied UPN"
                    $LimitToSpecificUsername = $LimitToSpecificUsername.Split('@') | Select-Object -First 1
                }
                $ProfileFolderNameOrUsernameMatchesSpecifiedProfileNameOrUsername = $LimitToSpecificProfile -like $ProfileFolderName
                Write-Verbose "$LimitToSpecificProfile -like $ProfileFolderName`: $ProfileFolderNameOrUsernameMatchesSpecifiedProfileNameOrUsername"
                if (!$ProfileFolderNameOrUsernameMatchesSpecifiedProfileNameOrUsername) {
                    Write-Progress "Skipping $($UserProfile.ProfilePath) because it doesn't match $LimitToSpecificProfile"
                    return
                }
            }
            # Write-Progress "Filtering out Accounts to Avoid $DestinationTenantDomain" -PercentComplete 15
            if ($ProfileFolderName -like "*.$ComputerName") {
                Write-Progress "Skipping $ProfileFolderName because it ends with .$ComputerName indicating that it was likely created erroneously after the AzureAD Join completed but the desired profile hadn't been migrated"
                return
            }
            if ($ProfileNamesToAvoidArray) {
                $ShouldAvoid = $ProfileNamesToAvoidArray | Test-Any {
                    $AccountToAvoid = $_.ToLower()
                    $result = $AccountToAvoid -and $ProfileFolderName -like "*$AccountToAvoid*"
                    if ($AccountToAvoid) {
                        Write-Verbose "ProfileFolderName: $ProfileFolderName -like `"*$AccountToAvoid*`": $result"
                    }
                    $result
                }

                if ($ShouldAvoid) {
                    Write-Progress "Skipping $($UserProfile.ProfilePath) because it is an account to avoid"
                    return
                }
            } else {
                Write-Progress "No profiles to avoid"
            }
            # Specifically compare to $false because it could be $null in which case we want to proceed
            if ($UserProfile.UserEnabled -eq $false) {
                Write-Progress "Skipping $($UserProfile.ProfilePath) because the associated owner ($($UserProfile.SID)) is disabled"
                return
            }
            if ($ProfilePath.WorkplaceJoined) {
                Write-Warning "$($UserProfile.ProfilePath) is workplace joined"
            }

            # $TestResults.NotAzureADUserRegistered = !$UserProfile.WorkplaceJoined
            # if(!$TestResults.NotAzureADUserRegistered)
            # {
            #     Write-Warning "Device is Workplace Joined"
            # }
            $ProfileType = $UserProfile.DirectoryType
            if ($ProfileTypesToMigrate -ne 'All') {
                if ($UserProfile.DirectoryType -ne $ProfileTypesToMigrate) {
                    Write-Progress "Skipping $($UserProfile.ProfilePath) because its current owner ($($UserProfile.SID)) is $($UserProfile.DirectoryType) not $ProfileTypesToMigrate"
                    return
                }
            }

            Write-Progress "ProfileType: $ProfileType -> DirectoryType: $DirectoryType (Destination)"
            switch ($ProfileType) {
                # Source
                "ActiveDirectory" {
                    switch ($DirectoryType) {
                        # Destination
                        "ActiveDirectory" {
                            Write-Progress "Domain.DomainSID $($Domain.DomainSID)"
                            if ($Domain.DomainSID -and $UserProfile.SID.StartsWith($Domain.DomainSID)) {
                                Write-Progress "Skipping $($UserProfile.ProfilePath) because it is already associated to a user in $($Domain.DomainDNSName)"
                                return
                            }

                            Write-Progress "Looking up $($UserProfile.ProfilePath) in Active Directory"
                            if ($UserProfile.UPN) {
                                $ADUser = Get-ADUser -Filter "UserPrincipalName -eq '$($UserProfile.UPN)' -or SamAccountName -eq '$($UserProfile.UPN.Split("@")[0])'" -DomainController $DomainController -ErrorAction SilentlyContinue
                            } elseif ($UserProfile.ProfilePath) {
                                Write-Warning "No UPN found for $($UserProfile.ProfilePath). Attempting to use ProfilePath..."
                                $Username = Split-Path $UserProfile.ProfilePath -Leaf
                                $ADUser = Get-ADUser -Filter "SamAccountName -eq '$Username'" -DomainController $DomainController -ErrorAction SilentlyContinue
                            }

                            if ($ADUser) {
                                Write-Progress "Found corresponding Active Directory user for $($UserProfile.ProfilePath)"
                                $UserProfile | Add-Member -NotePropertyName "DestinationUser" -NotePropertyValue $ADUser
                                $UserProfile | Add-Member -NotePropertyName "DestinationUPN" -NotePropertyValue $ADUser.UserPrincipalName
                                $UserProfile | Add-Member -NotePropertyName "DestinationUserSID" -NotePropertyValue $ADUser.SID
                                $UserProfile | Add-Member -NotePropertyName "DestinationDisplayName" -NotePropertyValue $ADUser.DisplayName
                                $DestinationUser = $ADUser
                            } else {
                                Write-Warning "No corresponding Active Directory user found for $($UserProfile.ProfilePath)"
                            }
                        }
                        "AzureAD" {
                            if (!$OnPremisesSyncEnabled -and !$FuzzyMatch) {
                                Write-Warning "Setup AzureAD Connect before attempting to migrate Active Directory accounts to AzureAD or enable FuzzyMatch to attempt to map the profile folder name to a username in AzureAD"
                            }

                            # Azure AD Sync by design doesn't sync the -500 account (or any users that are Domain Administrators) 
                            # Therefore we will never find a destination user for these accounts in Azure, so we should remove them here
                            # Todo: Also check for non -500 accounts that are also Domain Admins
                            if ($UserProfile.SID.EndsWith('-500')) {
                                Write-Warning "Skipping $($UserProfile.ProfilePath) because it is the domain administrator"
                                return
                            }
                            
                            if ($OnPremisesSyncEnabled) {
                                $AzureADUser = Get-ImmyAzureADUser -Filter "onPremisesSecurityIdentifier eq '$($UserProfile.SID)'"
                                if (!$FuzzyMatch) {
                                    try {
                                        $DestinationUser = $AzureADUser | Should-HaveOne "User in AzureAD with onPremisesSecurityIdentifier $($UserProfile.SID)" -PassThru
                                    } catch {
                                        if ($UserProfile.UPN -like "*@*.*") {
                                            Write-Warning "There are no users in AzureAD with onPremisesSecurityIdentifier $($UserProfile.SID). Searching AzureAD by UPN $($UserProfile.UPN)"
                                            $DestinationUser = Get-ImmyAzureADUser -Identity $UserProfile.UPN
                                            if (!$DestinationUser) {
                                                Write-Error "There are no users in AzureAD with onPremisesSecurityIdentifier $($UserProfile.SID).`r`n or with UPN $($UserProfile.UPN) in AzureAD. Make sure the user is in the AzureAD Connect Sync scope and is not a Domain Admin as those are excluded from syncing to AzureAD."
                                            }
                                        } else {
                                            Write-Error -TargetObject $UserProfile -Message @"
AzureAD Connect is enabled, yet no users in Azure have onPremisesSecurityIdentifier $($UserProfile.SID).

Additionally $($UserProfile.ProfilePath) has no associated UPN, therefore we can't look for users in AzureAD by UPN.

Make sure the user associated to this profile is in the AzureAD Connect sync scope.
"@
                                        }
                                    }
                                    Write-Progress "Will map $($UserProfile.ProfilePath) to AzureAD User: $($DestinationUser.DisplayName) ($($DestinationUser.UPN))"
                                } else {
                                    Write-Progress "Unable to find AzureAD user with onPremisesSecurityIdentifier $($UserProfile.SID), will attempt fuzzy match"
                                }
                            } else {
                                Write-Progress "Skipping onPremisesSecurityIdentifier lookup since Azure AD Connect is not setup for this tenant"
                            }
                        }
                    }
                }
                "AzureAD" {
                    switch ($DirectoryType) {
                        "AzureAD" {
                            Write-Progress "Verifying Profile is not already mapped to destination AzureAD"
                            if ($UserProfile.AzureADObjectID) {
                                if ($null -eq $DestinationTenantDomain) {
                                    $DestinationTenantDomain = $UserProfile.UPN.Split('@') | Select-Object -First 1
                                }
                                Write-Verbose "$($UserProfile.ProfilePath) is an AzureAD profile mapped to AzureAD ObjectId $($UserProfile.AzureADObjectID), verifying that user exists in $DestinationTenantDomain AzureAD"
                                try {
                                    $AADUser = Get-ImmyAzureADUser -Identity $UserProfile.AzureADObjectID
                                    if (!$AADUser) {
                                        Write-Verbose "$($UserProfile.AzureADObjectID) does NOT exist in $DestinationTenantDomain AzureAD, will migrate"
                                    } else {
                                        Write-Progress "$($UserProfile.AzureADObjectID) already exists in $DestinationTenantDomain AzureAD, mapping already complete"
                                        return
                                    }
                                } catch {
                                    throw
                                }
                            }
                        }
                        "ActiveDirectory" {
                            Write-Progress "Looking up $($UserProfile.ProfilePath) in Active Directory"
                            $ADUser = Get-ADUser -Filter "UserPrincipalName -eq '$($UserProfile.UPN)' -or SamAccountName -eq '$($UserProfile.UPN.Split("@")[0])'" -DomainController $DomainController -ErrorAction SilentlyContinue
                            if ($ADUser) {
                                Write-Progress "Found corresponding Active Directory user for $($UserProfile.ProfilePath)"
                                $UserProfile | Add-Member -NotePropertyName "DestinationUser" -NotePropertyValue $ADUser
                                $UserProfile | Add-Member -NotePropertyName "DestinationUPN" -NotePropertyValue $ADUser.UserPrincipalName
                                $UserProfile | Add-Member -NotePropertyName "DestinationUserSID" -NotePropertyValue $ADUser.SID
                                $UserProfile | Add-Member -NotePropertyName "DestinationDisplayName" -NotePropertyValue $ADUser.DisplayName
                                $DestinationUser = $ADUser
                            } else {
                                Write-Warning "No corresponding Active Directory user found for $($UserProfile.ProfilePath)"
                            }
                        }
                    }
                }
                default {
                    #"WorkplaceJoined"
                    # Write-Progress "UserProfile has $(count($UserProfile.UPN)) UPN(s):`r`n$(($UserProfile.UPN | Out-String))"
                    foreach ($UPN in ($UserProfile.UPN | Where-Object {$_ -like "*@*.*"})) {
                        Write-Progress "Looking up $UPN in AzureAD"
                        $DestinationUser = Get-ImmyAzureADUser -Identity $UPN
                        if (!$DestinationUser) {
                            Write-Warning "Unable to find $($UPN) in AzureAD"
                        } else {
                            Write-Progress "Found DestinationUser $($UPN) in AzureAD"
                            break
                        }
                    }
                }
            }
        }

        if ($DirectoryType -eq 'AzureAD') {
            function Get-UserByProfileFolderName {
                [CmdletBinding()]
                param(
                    [Parameter(Mandatory)]
                    [string]$ProfileName,

                    [Parameter(Mandatory = $false)]
                    [string[]]$UserIdentifierPrefixes
                )

                # Initialize the search list with user identifier prefixes, if any
                $searchList = @()
                if ($UserIdentifierPrefixes -and $UserIdentifierPrefixes.Count -gt 0) {
                    $searchList += $UserIdentifierPrefixes | Where-Object { $_ -ne '' }  # Filter out empty strings
                }
                
                # Add profile name variations to the search list
                $searchList += Get-UserNameVariation -Name $ProfileName

                foreach ($identifier in $searchList) {
                    if (![string]::IsNullOrWhiteSpace($identifier)) {
                        Write-Verbose "Searching for user with identifier: '$identifier'"
                        $users = Get-ImmyAzureADUser -FieldName userPrincipalName -StartsWith $identifier
                        if ($users.Count -gt 1) {
                            Write-Warning "More than one user found for identifier '$identifier'."
                            foreach ($user in $users) {
                                Write-Progress "User found: $($user.userPrincipalName)"
                            }
                            break
                        }
                        $user = $users | Should-HaveOne -Name "AzureAD user with userPrincipalName starting with: '$identifier'" -ErrorAction SilentlyContinue -Passthru
                        $user | Write-Variable
                        if ($user) { return $user }
                    } else {
                        Write-Verbose "Skipped searching for a user with an empty identifier."
                    }
                }

                return $null
            }

            function Get-UserByEmailAddress {
                [CmdletBinding()]
                param(
                    [Parameter(ParameterSetName = 'UPN', Mandatory)]
                    [string]$UPN,

                    [Parameter(ParameterSetName = 'Email', Mandatory)]
                    [string]$Email
                )

                if ($UPN) {
                    $DestinationUser = Get-ImmyAzureADUser -Identity $UPN
                    if ($DestinationUser) {
                        return $DestinationUser
                    } 
                    $DestinationUser = Get-ImmyAzureADUser -EmailAddress $UPN
                    if ($DestinationUser) {
                        Write-Verbose "For users with proxyAddress: $UPN"
                        return $DestinationUser
                    }                        
                    $UPNPrefix = $UPN -Split '@' | Select-Object -First 1
                    Write-Verbose "Searching by UPN prefix: $UPNPrefix"
                    return Get-ImmyAzureADUser -FieldName userPrincipalName -StartsWith $UPNPrefix
                }

                if ($Email) {
                    $DestinationUser = Get-ImmyAzureADUser -EmailAddress $Email
                    if ($DestinationUser) {
                        return $DestinationUser
                    }
                }
            }

            if (!$DestinationUser) {
                $Username = Split-Path $UserProfile.ProfilePath -Leaf
                $UPNPrefix = $UserProfile.UPN -split "@" | Select-Object -First 1
                $EmailPrefix = $UserProfile.OutlookEmail -split "@" | Select-Object -First 1

                # Attempt to find user by UPN
                Write-Progress "Attempting to find AzureAD user by UPN"
                if (![string]::IsNullOrWhiteSpace($UserProfile.UPN)) {
                    $DestinationUser = Get-UserByEmailAddress -UPN $UserProfile.UPN
                } else {
                    Write-Warning "UPN is null or empty. Skipping UPN search."
                    Write-Verbose "Trying Outlook email next."
                }

                # Attempt to find user by Outlook Email if user not found by UPN
                if (!$DestinationUser -and ![string]::IsNullOrWhiteSpace($UserProfile.OutlookEmail)) {
                    Write-Progress "Attempting to find AzureAD user by Outlook email"
                    $DestinationUser = Get-UserByEmailAddress -Email $UserProfile.OutlookEmail
                } elseif (!$DestinationUser) {
                    Write-Warning "Outlook email is null or empty. Skipping Outlook email search."
                }

                # Attempt to find user by the email captured in the WorkplaceJoin/dsreg blob (AzureADUserJoinInfo).
                # On Windows builds > 14393 the WorkplaceJoin record is excluded from the AAD-Join readiness test,
                # which means a Workplace/Hybrid-cached profile can carry no UPN or Outlook email even though the
                # dsreg blob still contains a valid UserEmail. Without this step the resolver degrades to a
                # folder-name guess that can't match a real UPN.
                if (!$DestinationUser) {
                    $WorkplaceJoinEmail = $UserJoinInfo |
                        Where-Object { $_.ProfilePath -eq $UserProfile.ProfilePath -and ![string]::IsNullOrWhiteSpace($_.UserEmail) } |
                        Select-Object -ExpandProperty UserEmail -First 1
                    if (![string]::IsNullOrWhiteSpace($WorkplaceJoinEmail)) {
                        Write-Progress "Attempting to find AzureAD user by WorkplaceJoin email '$WorkplaceJoinEmail'"
                        $DestinationUser = Get-UserByEmailAddress -UPN $WorkplaceJoinEmail
                    } else {
                        Write-Warning "No WorkplaceJoin email found for $($UserProfile.ProfilePath). Skipping WorkplaceJoin email search."
                    }
                }

                # Fallback to using Profile Folder Name if no user found by UPN or Outlook Email
                if (!$DestinationUser) {
                    Write-Warning "User not found by UPN or Outlook email. Expanding search with profile folder name and identifier prefixes."
                    Write-Progress "Attempting to find AzureAD user by Profile Folder Name '$Username' and identifier prefixes"
                    $DestinationUser = Get-UserByProfileFolderName -ProfileName $Username -UserIdentifierPrefixes $UPNPrefix, $EmailPrefix
                }
            }
        }

        # If we still haven't found a user, attempt to use Fuzzy Matching
        if (!$DestinationUser) {
            Write-Progress "Attempting Fuzzy Match"
            $StartsWith = $ProfileFolderName.Substring(0, 1)
            if ($ProfileFolderName.Contains(' ')) {
                # Use Display Name
                Write-Progress "ProfileName '$ProfileFolderName' contains a space. Attempting to fuzzy match '$ProfileFolderName' against AzureAD Display Names."
                switch ($DirectoryType) {
                    "AzureAD" {
                        $PotentialMatchingUsers = Get-ImmyAzureADUser -FieldName displayName -StartsWith $ProfileFolderName | ForEach-Object {
                            $AzureSID = Convert-AzureAdObjectIdToSid $_.Id
                            # Check if the SID property already exists before adding it
                            if (-not $_.PSObject.Properties.Name -contains "SID") {
                                $_ | Add-Member -NotePropertyName SID -NotePropertyValue $AzureSID -PassThru
                            } else {
                                $_
                            }
                        }
                        Write-Progress "Got $($PotentialMatchingUsers.Count) potential matching users`r`n$($PotentialMatchingUsers | Format-Table displayName, userPrincipalName | Out-String)"
                        $Property = 'displayName'
                    }
                    "ActiveDirectory" {
                        Write-Progress "Looking up $ProfileFolderName in $DirectoryType"
                        $PotentialMatchingUsers = Get-ADUser -Filter "name -like `"$ProfileFolderName`"" -DomainController $DomainController
                    }
                }
            } else {
                switch ($DirectoryType) {
                    "AzureAD" {
                        $PotentialAzureADUsers = Get-ImmyAzureADUser -StartsWith $StartsWith -FieldName userPrincipalName
                        if (!$PotentialAzureADUsers) {
                            Write-Warning "No userPrincipalNames in $DirectoryType start with '$StartsWith'"
                        } else {
                            $PotentialMatchingUsers = $PotentialAzureADUsers
                        }
                    }
                    "ActiveDirectory" {
                        Write-Progress "Looking up $ProfileFolderName in $DirectoryType"
                        $PotentialMatchingUsers = Get-ADUser -NoCache -Filter "userPrincipalName -like `"$ProfileFolderName*`" -or samAccountName -like `"$ProfileFolderName`"" -DomainController $DomainController
                    }
                }
            }

            #$PotentialMatchingUsernames = $PotentialMatchingUsers | ForEach-Object {$_.userPrincipalName -split '@' | Select-Object -First 1} | sort
            $PotentialMatchingUsernames = $PotentialMatchingUsers | ForEach-Object {
                $upnPrefix = $_.userPrincipalName -split '@' | Select-Object -First 1
                $givenName = $_.givenName
                # Ensure we don't add null, empty strings, or duplicate values
                $names = @()
                if (-not [string]::IsNullOrWhiteSpace($upnPrefix)) { $names += $upnPrefix }
                if (-not [string]::IsNullOrWhiteSpace($givenName) -and $givenName -ne $upnPrefix) { $names += $givenName }
                return $names
            } | Sort-Object -Unique

            if ($null -eq $Property) { $Property = 'userPrincipalName' }
            $PotentialMatchingUserCount = $PotentialMatchingUsernames.Count
            if ($PotentialMatchingUserCount -gt 1) {
                Write-Progress "Attempting to fuzzy match folder name '$ProfileFolderName' against the following $PotentialMatchingUserCount usernames:`r`n$(($PotentialMatchingUsernames | Out-String))"
                $FuzzyResultsPrimaryProperty = @(Select-FuzzyString -Search $ProfileFolderName -Data $PotentialMatchingUsers -Property $Property)
                $FuzzyResultsGivenName = @(Select-FuzzyString -Search $ProfileFolderName -Data $PotentialMatchingUsers -Property 'givenName')
                $CombinedFuzzyResults = $FuzzyResultsGivenName + $FuzzyResultsPrimaryProperty
                Write-Verbose "FuzzyMatch Results:`r`n$($CombinedFuzzyResults | Format-Table | Out-String)"
                $GroupedResults = $CombinedFuzzyResults | Group-Object -Property Result
                $UniqueResults = $GroupedResults | Where-Object { $_.Count -eq 1 } | ForEach-Object { $_.Group }

                if ($UniqueResults.Count -eq 1) {
                    $BestMatch = $UniqueResults | Sort-Object Score | Select-Object -Last 1
                    $DestinationUser = $BestMatch.Object
                } else {
                    if ($null -ne $GroupedResults -and $GroupedResults.Count -gt 0) {
                        Write-Warning "Multiple potential matches found. Unable to determine correct user for '$ProfileFolderName'."
                        $GroupedResults | ForEach-Object {
                            $_.Group | ForEach-Object {
                                Write-Warning "Name: $($_.Object.displayName), UPN: $($_.Object.userPrincipalName)"
                            }
                        }
                    } else {
                        Write-Warning "Expected multiple groups, but no valid data found."
                    }
                }
                # $FuzzyMatchResults = $PotentialMatchingUsernames | Select-FuzzyString $ProfileFolderName -Property $Property
                # Write-Verbose "FuzzyMatch Results:`r`n$($FuzzyMatchResults | ft | Out-String)"
                # $BestMatch = $FuzzyMatchResults | sort Score | select -Last 1
                # $DestinationUser = $PotentialMatchingUsers | ?{$_.userPrincipalName.StartsWith($BestMatch.Result)}
            } elseif ($PotentialMatchingUserCount -eq 1) {
                $DestinationUser = $PotentialMatchingUsers            
                Write-Progress "Found exactly 1 user: $($DestinationUser.displayName) ($($DestinationUser.userPrincipalName))"
            } else {
                Write-Warning "Unable to find destination user in $($DirectoryType): $($UserProfile.ProfilePath)"
                if (!$IgnoreProfilesWithoutMatchingUsers) {
                    $TestResults.AllProfilesHaveDestinationUsers = $false
                }
                if ($DirectoryType -ne 'ActiveDirectory') {
                    return
                }
            }
            
            $FuzzyMatched = !!$DestinationUser
            if ($FuzzyMatched) {
                Write-Progress "FuzzyMatched $($UserProfile.ProfilePath) to $DirectoryType user $($DestinationUser.userPrincipalName)"
            } else {
                Write-Warning "Unable to fuzzy match $($UserProfile.ProfilePath) to a user in $DirectoryType"
            }
        }

        # After we have extinguished all possible options
        if (!$DestinationUser -and $IgnoreProfilesWithoutMatchingUsers) {
            Write-Warning "No destination user found for $($UserProfile.ProfilePath) but ignoring because 'IgnoreProfilesWithoutMatchingUsers' is specified"
            return
        }
        if (!$DestinationUser.SID) {
            Write-Error "Unable to find SID for DestinationUser $($DestinationUser.displayName)" -TargetObject $DestinationUser
        } elseif ($DestinationUser.SID -notlike "S-*") {
            Write-Error "Invalid DestinationUser.SID: $($DesinationUser.SID)" -TargetObject $DestinationUser
        }
        
        Write-Progress  "Verifing no other profiles are already mapped to this SID"
        $ConflictingProfile = $Profiles | Where-Object {$UserProfile.ProfilePath -ne $_.ProfilePath -and $_.SID -like $DestinationUser.SID}
        if ($ConflictingProfile) {
            $ConflictMessage = ""
            # Set the UserIdentifier to the UPN if it exists, otherwise use the UserPrincipalName
            $UserIdentifier = $DestinationUser.UPN
            if (-not $UserIdentifier) {
                $UserIdentifier = $DestinationUser.UserPrincipalName
            }
            if ($UserProfile.NewLocal -eq $false) {
                if ($ConflictingProfile.NewLocal -eq $true) {
                    Write-Warning @"
DestinationUser $UserIdentifier is associated to NewLocal profile $($ConflictingProfile.ProfilePath) created $([int]$ProfileAge.TotalDays) day(s) ago.

This likely happened when you or the end user logged in as to test the profile migration on a previous run.

Will soft delete the link to the new profile to prevent migration from failing.

"@
                    SoftDelete-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($DestinationUser.SID)" -ErrorAction Stop | Out-Null
                } elseif ($ConflictingProfile.CreationTime -gt $UserProfile.CreationTime) {
                    $ProfileAge = (Get-Date) - $ConflictingProfile.CreationTime
                    $ConflictMessage = @"
DestinationUser $UserIdentifier is associated to newer profile $($ConflictingProfile.ProfilePath) created $([int]$ProfileAge.TotalDays) day(s) ago.

This likely happened when you or the end user logged in to test the profile migration.

"@
                }
                #$UserProfile.ConflictingProfileLinkPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($DestinationUser.SID)"
                $UserProfile | Add-Member -NotePropertyName "ConflictingProfileLinkPath" -NotePropertyValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($DestinationUser.SID)"
            } elseif ($UserProfile.NewLocal -eq $true -and $ConflictingProfile.NewLocal -eq $false) {
                Write-Warning "Skipping NewLocal profile $($UserProfile.ProfilePath) as it is was created erroneously when the user logged in before their old profile was migrated."
                # return
            } else {
                $ConflictMessage += @"
$($DestinationUser.SID) is currently mapped to $($ConflictingProfile.ProfilePath)
but should be mapped to 
$($UserProfile.ProfilePath)

This could be because $UserIdentifier logged in before the profile was migrated.

"@
            }if ($ConflictMessage) {
                $ConflictMessage += @"

Source Profile Info:
$($UserProfile | Format-List * | Out-String)
Conflicting Profile Info:
$($ConflictingProfile | Format-List * | Out-String)
To correct this, open the terminal in Immy for the machine and run:

Rename-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($DestinationUser.SID)' -NewName "_$($DestinationUser.SID)"
"@
                Write-Error $ConflictMessage -TargetObject $ConflictingProfile -ErrorAction Stop
            }
        }

        if(!$DestinationUser){
            Write-Warning "Unable to find destination user for $($UserProfile.ProfilePath)"
            return
        }

        if($DestinationUser -and $DestinationUser.SecurityIdentifier -and !$DestinationUser.SID){
            Write-Progress "Found DestinationUser.SecurityIdentifier without DestinationUser.SID, setting DestinationUser.SecurityIdentifier without DestinationUser.SID"
            $DestinationUser.SID = $DestinationUser.SecurityIdentifier
        }

        #$UserProfile | Add-Member -NotePropertyName 
        $UserProfile | Add-Member -NotePropertyName "DestinationUser" -NotePropertyValue $DestinationUser -Force
        $UserProfile | Add-Member -NotePropertyName "DestinationUPN" -NotePropertyValue $DestinationUser.UserPrincipalName -Force
        $UserProfile | Add-Member -NotePropertyName "DestinationUserSID" -NotePropertyValue $DestinationUser.SID -Force
        $UserProfile | Add-Member -NotePropertyName "DestinationDisplayName" -NotePropertyValue $DestinationUser.DisplayName -Force
        $UserProfile | Add-Member -NotePropertyName "FuzzyMatch" -NotePropertyValue $FuzzyMatched -Force
        
        $UserProfile
    }
    #endregion

    # We want to show the user who we would have picked
    $FuzzyMatchedProfiles = $ProfilesToMigrate | Where-Object {$_.FuzzyMatch -eq $true}
    if ($FuzzyMatchedProfiles) {
        if (!$FuzzyMatch) {
            $FuzzyProfileString = $FuzzyMatchedProfiles | Format-Table ProfilePath, DestinationUPN, DestinationDisplayName, DestinationUserSID | Out-String
            throw "Fuzzy Match not enabled. Fuzzy Match would have mapped the following profiles:`r`n$FuzzyProfileString`r`nSet FuzzyMatch to true if this looks correct"
        }
    }
    $TestResults.ProfileTest = $ProfilesToMigrate | Test-LocalProfile
    if ($DestinationDirectoryType -eq 'AzureAD' -and $true -eq $HybridJoined) {
        $TestResults.NotHybridJoined = !$HybridJoined
    }
    
    $ProfilesToMigrateCount = $ProfilesToMigrate | Measure-Object | Select-Object -Expand Count
    if ($ProfilesToMigrateCount -eq 0) {
        Write-Verbose "No profiles to migrate"
    } else {
        Write-Progress "ProfilesToMigrate:`r`n$($ProfilesToMigrate | Format-Table ProfilePath, DestinationUPN, DestinationDisplayName, DestinationUserSID | Out-String)"
        # Also using Write-Host to make sure this table gets written to the script output.
        Write-Host -ForegroundColor Cyan "ProfilesToMigrate:`r`n$($ProfilesToMigrate | Format-Table ProfilePath, DestinationUPN, DestinationDisplayName, DestinationUserSID | Out-String)"
    }
    $TestResults.AllProfilesMapped = ($ProfilesToMigrateCount -eq 0)
    
    <#
        Write-Progress "Checking if Outlook has been flagged for reconfiguration" -PercentComplete 35
        $OutlookTest = Invoke-HKCU -LimitToSID ($ProfilesToMigrate.SID) -ScriptBlock {
            $BasePath = 'HKCU:\SOFTWARE\Microsoft\Office'
            $ZeroConfigValue = Get-ItemProperty -Path "$BasePath\AutoDiscover" -Name ZeroConfigExchange -ErrorAction SilentlyContinue | %{$_.ZeroConfigExchange}
            if($ZeroConfigValue -ne 1)
            {
                Write-Warning "Outlook: ZeroConfigValue not equal 1: $ZeroConfigValue"
                return $false
            }
            $ProfilesExists = Test-Path "$BasePath\16.0\Outlook\Profiles"
            if($ProfilesExists)
            {
                Write-Warning "Outlook: Profiles exist: $ProfilesExists"
                return $false
            }    
            $FirstRun = Get-ItemProperty -Path "$BasePath\16.0\Outlook\Setup" -Name 'First-Run' -ErrorAction SilentlyContinue | %{$_.'First-Run'}
            if($FirstRun)
            {
                Write-Warning "Outlook: First-Run Exists"
                return $false
            }    
            return $true
        }
        Write-Host "OutlookTest: $OutlookTest"
        if($OutlookTest -eq $false)
        {
            Write-Warning "Outlook needs to be reconfigured"
            $Status = $false
        }
    #>
    
    $ProfilesWithoutDestinationUsers = $ProfilesToMigrate | Where-Object {!$_.DestinationUser}
    if ($ProfilesWithoutDestinationUsers) {
        $Message = "Found $($ProfilesWithoutDestinationUsers.Count) profile(s) without destination users `r`n`r`n$(($ProfilesWithoutDestinationUsers | Format-Table ProfilePath, SID, UPN, DestinationUser | Out-String))`r`n`r`nYou may need to adjust your mapping mode so Immy can map the users correctly"
        Write-Warning $Message
        throw $message
    }

    $NonUniqueDestinationMappings = $ProfilesToMigrate | Where-Object { $_.DestinationUPN } | Group-Object -Property DestinationUPN | Where-Object {$_.Count -gt 1 }
    $TestResults.UniqueMappings = !$NonUniqueDestinationMappings
    if (!$TestResults.UniqueMappings) {
        # throw ($NonUniqueDestinationMappings | fl * | Out-String)
        # throw ($NonUniqueDestinationMappings | select ProfilePath, DestinationUPN | Out-String)
        $Message = "The following profiles were mapped to the same user.`r`n"
        foreach ($NonUniqueMapping in $NonUniqueDestinationMappings.Values) {
            # $Message += $NonUniqueMapping | fl * | Out-String
            $Message += $ProfilesToMigrate | Where-Object {$_.DestinationUPN -eq $NonUniqueMapping} | Select-Object ProfilePath, DestinationUPN | Out-String
        }
        $message += "`r`nConsider adding these profiles to ProfilesToAvoid or disable FuzzyMatch"
        throw $Message
    }
    
    if ($DirectoryType -eq 'ActiveDirectory') {
        $TestResults.OnCorrectDomain = Configure-ComputerNameAndDomainJoinOld -Domain $Domain.DomainDNSName -ShouldBeDomainJoined
    }

    switch ($method) {
        "test" {
            Write-Host "$($TestResults | Format-Table | Out-String)"
            $OverallResult = $TestResults | Test-All
            Write-Progress "Test Complete" -PercentComplete 100
            return $OverallResult
        }
        "set" {
            switch ($DirectoryType) {
                "AzureAD" {
                    if ($AzureADStatus.TenantDetails.TenantId) {
                        if ($AzureADStatus.TenantDetails.TenantId -ne $DestinationTenantID) {
                            Write-Progress "Machine is not in desired tenant."
                            Write-Progress "Leaving AzureAD..." -PercentComplete 50
                            Get-ImmyComputer | Invoke-ImmyCommand {
                                dsregcmd /leave
                            }
                            Restart-ComputerAndWait
                
                            Write-Progress "Updating AzureAD Join Status..."
                            $AzureADStatus = Get-AzureADJoinStatus
                        } else {
                            if ($false -eq $TestResults.NotHybridJoined) {
                                Write-Progress "Machine is Hybrid Joined to AzureAD, do something fancy to fix it"
                                
                            } else {
                                Write-Progress "Machine already in desired tenant"
                            }
                        }
                    } else {
                        Write-Progress "Machine not joined to AzureAD"
                    }
                }
                "ActiveDirectory" {
                    # No need to unjoin domain before migration to ActiveDirectory
                }
            }
            
            Write-Progress "Migrating Profiles..." -PercentComplete 50
            $UserIdentifier = $UserProfile.DestinationUPN
            if (-not $UserIdentifier) {
                $UserIdentifier = $UserProfile.UPN
            }

            Write-Verbose "Total Profiles: $ProfilesToMigrateCount"
            foreach ($UserProfile in ($ProfilesToMigrate | Sort-Object LastWriteTime)) {
                try {
                    Write-Progress "Migrating $($UserProfile.ProfilePath)" -PercentComplete (50 + (($ProfilesToMigrate.IndexOf($UserProfile) / $ProfilesToMigrateCount) * 30))
                } catch {
                }
                Write-Verbose "DestinationUser:`r`n$($UserProfile.DestinationUser | Format-Table id, displayName, userPrincipalName | Out-String)"
                $DestinationUserSID = $UserProfile.DestinationUser.SecurityIdentifier
                if (!$DestinationUserSID) {
                    Write-Verbose "`$UserProfile.DestinationUser.SecurityIdentifier is null, checking `$UserProfile.DestinationUser.SID"
                    $DestinationUserSID = $UserProfile.DestinationUser.SID
                }
                if (!$DestinationUserSID) {
                    Write-Verbose "`$UserProfile.DestinationUser.SID is null checking `$UserProfile.DestinationUserSID"
                    $DestinationUserSID = $UserProfile.DestinationUserSID
                }
                
                Write-Progress "Invoking ImmyWiz to map $($UserProfile.ProfilePath) to $DirectoryType SID $($DestinationUserSID) ($($UserProfile.DestinationUser.displayName) $($UserIdentifier))"
                try {
                    $Result = Set-UserProfileOwner -ProfilePath $UserProfile.ProfilePath -SID $DestinationUserSID -ErrorAction Stop
                    if ($Result -ne 0) {
                        throw "$($UserProfile.ProfilePath) ChangeOwner() returned $Result"
                    }
                } catch {
                    Write-Error "Aborting migration. There was an error migrating $($UserProfile.ProfilePath)`r`n$($_ | Out-String)" -ErrorAction Stop
                }
            }

            Write-Progress "Setting $UserIdentifier to be the selected user for next logon"
            $LogonUIPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
            
            Get-WindowsRegistryValue -Path $LogonUIPath -Name LastLoggedOnUserSID | RegistryShould-Be -Value $DestinationUserSID
            Get-WindowsRegistryValue -Path $LogonUIPath -Name SelectedUserSID | RegistryShould-Be -Value $DestinationUserSID
            $DisplayName = $UserProfile.DestinationUser.DisplayName
            if (!$DisplayName) {
                # If DisplayName is null, use the UPN
                $DisplayName = $UserIdentifier
            }
            Get-WindowsRegistryValue -Path $LogonUIPath -Name LastLoggedOnDisplayName | RegistryShould-Be -Value $DisplayName

            Write-Progress "Restarting LogonUI to force update"
            Invoke-ImmyCommand {
                taskkill /IM logonui.exe /f 2>&1 | Out-Null
            
            }
            if ($OutlookTest -eq $false) {
                Write-Progress "Reconfiguring Outlook" -PercentComplete 90
                Reset-OutlookProfile -AllUsers
            }

            switch ($DirectoryType) {
                "AzureAD" {
                    if (!$HybridJoined -and $AzureADStatus.TenantDetails.TenantId -eq $DestinationTenantID) {
                        Write-Host "Skipping AzureAD join since machine is already AzureAD Joined to $DestinationTenantDomain"
                    } else {
                        if ((Test-PartOfDomain)) {
                            # throw "Aborting: Machine is still domain joined (Profwiz likely failed)"
                            Write-Progress "Machine is Domain Joined, Unjoining" -PercentComplete 95
                            $UnjoinResult = Unjoin-Domain
                
                
                            if (!$UnjoinResult) {
                                throw "Unjoin attempt returned error $($UnjoinResult.ReturnValue) (0x$($UnjoinResult.ReturnValue.ToString('X8'))"
                            }
                            Restart-ComputerAndWait -IgnoreRebootPreference
                            if ((Test-PartOfDomain)) {
                                throw "Aborting: Machine is still domain joined after Unjoin attempt"
                            }
                        }
                        Write-Progress "Constructing join parameters for selected authentication flow..." -PercentComplete 96
                        $JoinAzureADParams = @{
                            CacheProvisioningPackage = $CacheProvisioningPackage
                            Verbose                  = $true
                            ClearExistingEnrollments = $ClearExistingEnrollments
                            RequireIntuneEnrollment  = $RequireIntuneEnrollment
                        }
                        if (($OAuthInfo).AccessToken) {
                            Write-Verbose "Access Token found, adding to join parameters."
                            $JoinAzureADParams.OAuthInfo = $OAuthInfo
                        } else {
                            Write-Verbose "Adding DEM username and password to join parameters."
                            $JoinAzureADParams.DEMUsername = $DEMUsername
                            $JoinAzureADParams.DEMPassword = $DEMPassword
                        }
                        # $JoinResult = Join-AzureAD @JoinAzureADParams -PreferCachedBPRT:$false -SkipRegistryTest -ClearExistingEnrollments
                        # Chaned above line to remove PreferCachedBPRT per CB - DH #202407165
                        Write-Progress "Joining AzureAD: $($DestinationTenantDomain)" -PercentComplete 97
                        $JoinResult = if ($UseEnhancedAzureADJoin) {
                            # Remove parameters not supported by the beta function
                            $JoinAzureADParams.Remove('RequireIntuneEnrollment')
                            $JoinAzureADParams.Remove('CacheProvisioningPackage')

                            Join-AzureADBeta @JoinAzureADParams
                        } else {
                            Join-AzureAD @JoinAzureADParams
                        }
                        Write-Progress "AzureADJoinResult: $($JoinResult | Format-List * | Out-String)"
                    }
                }
                "ActiveDirectory" {
                    if ($StaticallyAssignDomainControllerAsDNSServer) {
                        $DomainControllerIP = Invoke-ImmyDomainController {
                            Get-NetConnectionProfile -IPv4Connectivity Internet | ForEach-Object { 
                                Get-NetIPConfiguration -InterfaceIndex $_.InterfaceIndex | ForEach-Object {$_.IPv4Address.IPAddress}
                            }
                        }
                        if ($DomainControllerIP) {
                            Write-Progress "Setting Domain Controller IP as static DNS server: $DomainControllerIP"
                            Invoke-ImmyCommand {
                                Get-NetConnectionProfile -IPv4Connectivity Internet | ForEach-Object { 
                                    Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses $using:DomainControllerIP
                                }
                            }
                        } else {
                            Write-Warning "Unable to retrieve IP address from domain controller"
                        }
                    }
                }
            }

            Write-Progress "Complete" -PercentComplete 100
        }
    }
}