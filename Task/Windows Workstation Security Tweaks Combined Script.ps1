<#
Author: Logan Cook
Notes: Requires `WinFeatureShould-Be` Helper function
Instructions: To discover new items to enforce, visit https://security.microsoft.com/exposure-recommendations -> Devices -> Misconfigurations.
    After selecting a misconfiguration and selecting the 'remediation options' tab, check if there is a registry control. If there is, that is what you use here.
    If there is no registry control, the hardening is likely intended to be done via device CSPs. Intune (usually Attack Surface Reduction) is a great secondary enforcement mechanism.
#>

param(
[Parameter(Position=0,Mandatory=$False,HelpMessage=@'
Controls Solicited Remote Assistance via SupportAssist
* `True` = Enables Solicited Remoting
* `False` = Disables Solicited Remoting

Base RegKey:
`HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp`
'@)]
[Boolean]$AllowToGetHelp=$false,
[Parameter(Position=1,Mandatory=$False,HelpMessage=@'
Control elevation requirement when setting a network's location
* `True` = Require elevation
* `False` = Do not require elevation

Base RegKey:
`HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation`
'@)]
[Boolean]$NetLocationElevation=$true,
[Parameter(Position=2,Mandatory=$False,HelpMessage=@'
Disable 'Autorun for non-volume devices'
* `True` = Disable Autorun
* `False` = Do not disable Autorun

Base RegKey:
`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun`
'@)]
[Boolean]$NoAutorun=$true,
[Parameter(Position=3,Mandatory=$False,HelpMessage=@'
Disable 'Autoplay for non-volume devices'
* `True` = Disable Autoplay
* `False` = Do not disable Autoplay

Base RegKey:
`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutoplayfornonVolume`
'@)]
[Boolean]$NoAutoplayfornonVolume=$true,
[Parameter(Position=4,Mandatory=$False,HelpMessage=@'
Disable 'Autoplay' for all drives
* `255` = Completely disable
* `...` = Unknown (currently)
* `0` = Do not disable

Base RegKey:
`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun`
'@)]
[ValidateSet('255','0')]
[String]$NoDriveTypeAutoRun='255',
[Parameter(Position=5,Mandatory=$False,HelpMessage=@'
Disable IPv4 source routing

* `2` = Disables IP Source Route processing.
* `$null` = Remove the RegKey, do not block Source Routing

Base RegKey:
`HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting`
'@)]
[ValidateSet('$null','2')]
[String]$DisableIPSourceRouting='2',
[Parameter(Position=6,Mandatory=$False,HelpMessage=@'
Disable IPv6 source routing

* `2` = Disables IP Source Route processing.
* `$null` = Remove the RegKey, do not block Source Routing

Base RegKey:
`HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting`
'@)]
[ValidateSet('$null','2')]
[String]$DisableIP6SourceRouting='2',
[Parameter(Position=7,Mandatory=$False,HelpMessage=@'
Set LAN Manager authentication level
[See the Documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level)

* `0` = Send LM & NTLM responses
* `1` = Send LM & NTLM - use NTLMv2 session security if negotiated
* `2` = Send NTLM response only
* `3` = Send NTLMv2 response only
* `4` = Send NTLMv2 response only. Refuse LM
* `5` = Send NTLMv2 response only. Refuse LM & NTLM

Base RegKey:
`HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel`
'@)]
[ValidateSet('0','1','2','3','4','5')]
[String]$LmCompatibilityLevel='5',
[Parameter(Position=8,Mandatory=$False,HelpMessage=@'
Configure running LocalSecurityAuthority as a Protected Process
[See the Documentation](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)

* `0` = LSA won't run as a protected process.
* `1` = LSA will run as a protected process and this configuration is UEFI locked.
* `2` = LSA will run as a protected process and this configuration isn't UEFI locked.

'@)]
[ValidateSet('0','1','2')]
[String]$RunAsPPL='1',
[Parameter(Position=9,Mandatory=$False,HelpMessage=@'
Do not allow storage of passwords and credentials for network authentication
[See the Documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-do-not-allow-storage-of-passwords-and-credentials-for-network-authentication)

* `True` = Credential Manager doesn't store passwords and credentials on the device
* `False` = Credential Manager will store passwords and credentials on this computer for later use for domain authentication.

Base RegKey:
`HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\DisableDomainCreds`
'@)]
[Boolean]$DisableDomainCreds=$true,
[Parameter(Position=10,Mandatory=$False,HelpMessage=@'
Disable Anonymous enumeration of shares
[See the Documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts-and-shares)

* `True` = Do not allow anonymous users to perform certain activities, such as enumerating the names of domain accounts and network shares
* `False` = No other permissions can be assigned by the administrator for anonymous connections to the device. Anonymous connections will rely on default permissions. However, an unauthorized user could anonymously list account names and use the information to attempt to guess passwords or perform social-engineering attacks.

Base RegKey:
`HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous`
'@)]
[Boolean]$RestrictAnonymous=$true,
[Parameter(Position=11,Mandatory=$False,HelpMessage=@'
Configure SMBv1 status via Windows Optional Feature
[See the Documentation](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3?tabs=server#how-to-remove-smbv1-via-powershell)

* `Enabled` = Currently does nothing. I do not wish to enable SMBv1 on any devices voluntarily.
* `Disabled` = Disables the Windows Optional Feature for SMBv1

FeatureName: `SMB1Protocol`
'@)]
[ValidateSet('Enabled','Disabled')]
[String]$SMB1='Disabled'
)

# Regkey DSC block - Only add tweaks here if they do not have a proper CMDlet.
#   Windows Regkeys
    # Disable Solicited Remote Assistance
    Get-WindowsRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fAllowToGetHelp | RegistryShould-Be -Value $AllowToGetHelp -Type DWord

    # Enable 'Require domain users to elevate when setting a network's location'
    Get-WindowsRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name NC_StdDomainUserSetLocation | RegistryShould-Be -Value $NetLocationElevation -Type DWord

    # Set default behavior for 'AutoRun' to 'Enabled: Do not execute any autorun commands'
    Get-WindowsRegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoAutorun | RegistryShould-Be -Value $NoAutoRun -Type DWord

    # Disable 'Autoplay for non-volume devices'
    Get-WindowsRegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoAutoplayfornonVolume | RegistryShould-Be -Value $NoAutoplayfornonVolume -Type DWord

    # Disable 'Autoplay' for all drives
    Get-WindowsRegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun | RegistryShould-Be -Value $NoDriveTypeAutoRun -Type DWord

    # Disable IP source routing
    Get-WindowsRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name DisableIPSourceRouting | RegistryShould-Be -Value $DisableIPSourceRouting -Type DWord

    # Set IPv6 source routing to highest protection
    Get-WindowsRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name DisableIPSourceRouting | RegistryShould-Be -Value $DisableIP6SourceRouting -Type DWord

    # Set LAN Manager authentication level to 'Send NTLMv2 response only. Refuse LM & NTLM'2
    Get-WindowsRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel | RegistryShould-Be -Value $LmCompatibilityLevel -Type DWord

    # Enable 'Local Security Authority (LSA) protection'
    Get-WindowsRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL | RegistryShould-Be -Value $RunAsPPL -Type DWord

    # Disable the local storage of passwords and credentials
    Get-WindowsRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name DisableDomainCreds | RegistryShould-Be -Value $DisableDomainCreds -Type DWord

    # Disable Anonymous enumeration of shares
    Get-WindowsRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymous | RegistryShould-Be -Value $RestrictAnonymous -Type DWord

#   Adobe Regkeys
Get-WindowsRegistryValue -Path "HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown" -Name bDisableJavaScript | RegistryShould-Be -Value 1 -Type DWord

# Granular State gathering
#   CMDlet DSC block

WinFeatureShould-Be -Feature "SMB1Protocol" -State $SMB1
