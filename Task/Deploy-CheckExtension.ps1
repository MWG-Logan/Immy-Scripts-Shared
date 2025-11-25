<#!
    .SYNOPSIS
        Compliance Task to enforce (or remove) CyberDrain "Check - Phishing Protection" extension policies for Chrome & Edge using ImmyBot registry helper functions.
    .DESCRIPTION
        Combined task to deploy https://github.com/CyberDrain/Check.
        Uses ImmyBot provided helper cmdlets `Get-WindowsRegistryValue` and `RegistryShould-Be` to automatically perform
        test vs set logic based on `$method` for the Present (enforce) scenario. For Absent we manually ensure keys are
        removed. This eliminates custom diff logic and leans on native ImmyBot compliance primitives.

        Chosen as a Task (not Software) because there is no discrete installable artifact nor version detection; we only
        enforce policy keys that force deployment & configuration of the browser extensions. Extensions self-update via
        their web stores using the configured update_url.

    .PARAMETER Method
    (Injected by ImmyBot) Specifies phase: 'test' or 'set'. When running outside ImmyBot you can pass -Method test|set.
    .PARAMETER Ensure
    'Present' to enforce policy (default). 'Absent' to remove the policy keys (effectively un-managing the extension).
    .PARAMETER ChromeExtensionId / EdgeExtensionId
    The extension IDs to manage. Defaults to known IDs.
    .PARAMETER ChromeUpdateUrl / EdgeUpdateUrl
    The update service endpoints.
    .PARAMETER ShowNotifications ... (etc)
    Integer 0/1 toggles matching extension managed storage interpretation.

    .NOTES
    For Immy purposes, add this script as a Combined Task with Script Parameters enabled.
    Returns [bool] during test phase. In set phase writes summary output (Absent) or relies on helper output (Present).
    Validates inputs (color hex, interval range). All registry writes are HKLM so run in System context.

    Script courtesy of https://github.com/MWGMorningwood/

#>
[CmdletBinding(SupportsShouldProcess=$false)]
param(
    [Parameter(HelpMessage=@'
Desired state of the extension policy:
| State   | Effect                                        |
|---------|-----------------------------------------------|
| Present | Enforce / create all required registry values |
| Absent  | Remove the policy keys (un-manage extension)  |
'@)][ValidateSet('Present','Absent')][string]$Ensure = 'Present',

    [Parameter(HelpMessage=@'
Chrome extension ID (32 char lowercase). Default is the CyberDrain Check extension.
'@)][ValidatePattern('^[a-p]{32}$')][string]$ChromeExtensionId = 'benimdeioplgkhanklclahllklceahbe',
    [Parameter(HelpMessage=@'
Edge extension ID (32 char lowercase). Default is the CyberDrain Check extension.
'@)][ValidatePattern('^[a-p]{32}$')][string]$EdgeExtensionId = 'knepjpocdagponkonnbggpcnhnaikajg',

    [Parameter(HelpMessage=@'
Chrome Web Store update URL for the extension. Usually leave default.
'@)][ValidateNotNullOrEmpty()][string]$ChromeUpdateUrl = 'https://clients2.google.com/service/update2/crx',
    [Parameter(HelpMessage=@'
Edge Add-ons store update URL for the extension. Usually leave default.
'@)][ValidateNotNullOrEmpty()][string]$EdgeUpdateUrl = 'https://edge.microsoft.com/extensionwebstorebase/v1/crx',

    [Parameter(HelpMessage=@'
Installation mode policy value for ExtensionSettings:
| State             | Effect                                      |
|-------------------|---------------------------------------------|
|`force_installed`  | forcibly installs & keeps enabled (default) |
|`normal_installed` | installs but can be removed                 |
|`allowed`          | allowed but not auto-installed              |
|`blocked`          | prevents installation                       |
'@)][ValidateSet('force_installed','normal_installed','allowed','blocked')][string]$InstallationMode = 'force_installed',

    [Parameter(HelpMessage=@'
Show Notifications toggle. Maps to "Show Notifications" in extension settings.
| State | Effect               |
|-------|----------------------|
| `0`   | Disabled / Unchecked |
| `1`   | Enabled (default)    |
'@)][ValidateSet(0,1)][int]$ShowNotifications = 1,
    [Parameter(HelpMessage=@'
Valid Page Badge toggle. Maps to "Show Valid Page Badge".
| State | Effect             |
|-------|--------------------|
| `0`   | Disabled (default) |
| `1`   | Enabled            |
'@)][ValidateSet(0,1)][int]$EnableValidPageBadge = 0,
    [Parameter(HelpMessage=@'
Page Blocking toggle. Maps to "Enable Page Blocking".
| State | Effect               |
|-------|----------------------|
| `0`   | Disabled             |
| `1`   | Enabled (default)    |
'@)][ValidateSet(0,1)][int]$EnablePageBlocking = 1,
    [Parameter(HelpMessage=@'
CIPP Reporting toggle. Maps to "Enable CIPP Reporting".
| State | Effect                                          |
|-------|-------------------------------------------------|
| `0`   | Disabled (default)                              |
| `1`   | Enabled (requires CippServerUrl & CippTenantId) |
'@)][ValidateSet(0,1)][int]$EnableCippReporting = 0,
    [Parameter(HelpMessage=@'
CIPP Server URL. Required if EnableCippReporting=1. Blank by default.
'@)][string]$CippServerUrl = '',
    [Parameter(HelpMessage=@'
Custom Rules / Config URL for detection configuration. Blank = unused.
'@)][string]$CustomRulesUrl = '',
    [Parameter(HelpMessage=@'
Update interval in hours for detection configuration.
Default 24. Range 1-168 (1 hour to 1 week).
'@)][ValidateRange(1,168)][int]$UpdateInterval = 24,
    [Parameter(HelpMessage=@'
Enable Debug Logging. Maps to "Enable Debug Logging" in Activity Log settings.
| State | Effect               |
|-------|----------------------|
| `0`   | Disabled             |
| `1`   | Enabled (default)    |
'@)][ValidateSet(0,1)][int]$EnableDebugLogging = 1,
    [Parameter(HelpMessage=@'
A list of URLs that will completely bypass blocking. Entering **ANY** will decrease security on that website significantly.
'@)][string[]]$urlAllowlist,

    [Parameter(HelpMessage=@'
Enable Generic Webhook. Maps to "Generic Webhook Enabled" in webhook settings.
| State | Effect                                              |
|-------|-----------------------------------------------------|
| `0`   | Disabled (default)                                  |
| `1`   | Enabled (requires GenericWebhookUrl and Events)     |
'@)][ValidateSet(0,1)][int]$EnableGenericWebhook = 0,
    [Parameter(HelpMessage=@'
Generic Webhook URL. Required if EnableGenericWebhook=1. Blank by default.
'@)][string]$GenericWebhookUrl = '',
    [Parameter(HelpMessage=@'
Generic Webhook Event Types. Array of event types to send to the webhook.
Valid values: detection_alert, false_positive_report, page_blocked, rogue_app_detected, threat_detected, validation_event
'@)][ValidateSet('detection_alert','false_positive_report','page_blocked','rogue_app_detected','threat_detected','validation_event')]
    [string[]]$GenericWebhookEvents,

    [Parameter(HelpMessage=@'
Branding: Company Name shown in extension UI.
'@)][string]$CompanyName  = 'CyberDrain',
    [Parameter(HelpMessage=@'
Branding: Company URL shown in extension UI.
'@)][string]$CompanyUrl   = 'https://cyberdrain.com/',
    [Parameter(HelpMessage=@'
Branding: Product Name shown in extension UI.
'@)][string]$ProductName  = 'Check - Phishing Protection',
    [Parameter(HelpMessage=@'
Branding: Support email address. Blank allowed.
'@)][string]$SupportEmail = '',
    [Parameter(HelpMessage=@'
Branding: Primary HEX color (#RRGGBB). Default #F77F00.
Must be valid hex (e.g. #FFFFFF).
'@)][ValidatePattern('^#([0-9A-Fa-f]{6})$')][string]$PrimaryColor = '#F77F00',
    [Parameter(HelpMessage=@'
Branding: Logo URL. Leave blank to omit.
'@)][string]$LogoUrl = ''
)

$ErrorActionPreference = 'Stop'
Write-Host "Starting enforcement for Extensions: Chrome=$ChromeExtensionId Edge=$EdgeExtensionId Ensure=$Ensure Mode=$InstallationMode"

# NOTE: All parameters are now passed explicitly into functions so PSScriptAnalyzer (PSReviewUnusedParameter)
# can detect their usage. If you intentionally keep a parameter for future use, you can suppress the rule like:
# [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter','')] param([string]$FutureParam)
# Prefer explicit functional parameters over relying on script scope to satisfy analyzers & improve clarity.

function Get-ManagedStorageBasePath {
    param(
        [string]$ChromeExtensionId,
        [string]$EdgeExtensionId,
        [string]$ChromeUpdateUrl,
        [string]$EdgeUpdateUrl
    )
    @(
        @{ Browser='Chrome'; ManagedKey="HKLM:SOFTWARE\\Policies\\Google\\Chrome\\3rdparty\\extensions\\$ChromeExtensionId\\policy"; SettingsKey="HKLM:SOFTWARE\\Policies\\Google\\Chrome\\ExtensionSettings\\$ChromeExtensionId"; UpdateUrl=$ChromeUpdateUrl },
        @{ Browser='Edge';   ManagedKey="HKLM:SOFTWARE\\Policies\\Microsoft\\Edge\\3rdparty\\extensions\\$EdgeExtensionId\\policy"; SettingsKey="HKLM:SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionSettings\\$EdgeExtensionId"; UpdateUrl=$EdgeUpdateUrl }
    )
}

function Get-DesiredItem {
    param(
        [string]$Ensure,
        [string]$ChromeExtensionId,
        [string]$EdgeExtensionId,
        [string]$ChromeUpdateUrl,
        [string]$EdgeUpdateUrl,
        [int]$ShowNotifications,
        [int]$EnableValidPageBadge,
        [int]$EnablePageBlocking,
        [int]$EnableCippReporting,
        [string]$CippServerUrl,
        [string]$CustomRulesUrl,
        [int]$UpdateInterval,
        [int]$EnableDebugLogging,
        [string[]]$urlAllowlist,
        [int]$EnableGenericWebhook,
        [string]$GenericWebhookUrl,
        [string[]]$GenericWebhookEvents,
        [string]$CompanyName,
        [string]$CompanyUrl,
        [string]$ProductName,
        [string]$SupportEmail,
        [string]$PrimaryColor,
        [string]$LogoUrl,
        [string]$InstallationMode
    )
    $bases = Get-ManagedStorageBasePath `
        -ChromeExtensionId $ChromeExtensionId `
        -EdgeExtensionId $EdgeExtensionId `
        -ChromeUpdateUrl $ChromeUpdateUrl `
        -EdgeUpdateUrl $EdgeUpdateUrl
    foreach($b in $bases){
        # Build canonical Present arrays once
        $brandingKey = Join-Path $b.ManagedKey 'customBranding'
        $webhookKey = Join-Path $b.ManagedKey 'genericWebhook'
        $policyItems = @(
            @{ Path=$b.ManagedKey; Name='showNotifications';    Type='DWord'; Value=$ShowNotifications },
            @{ Path=$b.ManagedKey; Name='enableValidPageBadge'; Type='DWord'; Value=$EnableValidPageBadge },
            @{ Path=$b.ManagedKey; Name='enablePageBlocking';   Type='DWord'; Value=$EnablePageBlocking },
            @{ Path=$b.ManagedKey; Name='enableCippReporting';  Type='DWord'; Value=$EnableCippReporting },
            @{ Path=$b.ManagedKey; Name='cippServerUrl';        Type='String'; Value=$CippServerUrl },
            @{ Path=$b.ManagedKey; Name='cippTenantId';         Type='String'; Value=$azureTenantId }, # $azureTenantId Value supplied by Immy environment
            @{ Path=$b.ManagedKey; Name='customRulesUrl';       Type='String'; Value=$CustomRulesUrl },
            @{ Path=$b.ManagedKey; Name='updateInterval';       Type='DWord'; Value=$UpdateInterval },
            @{ Path=$b.ManagedKey; Name='enableDebugLogging';   Type='DWord'; Value=$EnableDebugLogging }
            @{ Path=$b.ManagedKey; Name='urlAllowlist';         Type='MultiString'; Value=([string[]]@($urlAllowlist)) }
        )
        $webhookItems = @(
            @{ Path=$webhookKey; Name='enabled'; Type='DWord'; Value=$EnableGenericWebhook },
            @{ Path=$webhookKey; Name='url';     Type='String'; Value=$GenericWebhookUrl },
            @{ Path=$webhookKey; Name='events';  Type='MultiString'; Value=([string[]]@($GenericWebhookEvents)) }
        )
        $brandingItems = @(
            @{ Path=$brandingKey; Name='companyName';  Type='String'; Value=$CompanyName },
            @{ Path=$brandingKey; Name='companyURL';   Type='String'; Value=$CompanyUrl },
            @{ Path=$brandingKey; Name='productName';  Type='String'; Value=$ProductName },
            @{ Path=$brandingKey; Name='supportEmail'; Type='String'; Value=$SupportEmail },
            @{ Path=$brandingKey; Name='primaryColor'; Type='String'; Value=$PrimaryColor },
            @{ Path=$brandingKey; Name='logoUrl';      Type='String'; Value=$LogoUrl }
        )
        $settingsItems = @(
            @{ Path=$b.SettingsKey; Name='update_url';        Type='String'; Value=$b.UpdateUrl },
            @{ Path=$b.SettingsKey; Name='installation_mode'; Type='String'; Value=$InstallationMode }
        )

        if($Ensure -eq 'Present'){
            $policyItems + $webhookItems + $brandingItems + $settingsItems | ForEach-Object { $_ }
        } else {
            # Transform for Absent: null policy & branding values, block extension, drop update_url
            $absentPolicy   = $policyItems   | ForEach-Object { @{ Path=$_.Path; Name=$_.Name; Type=$_.Type; Value=$null } }
            $absentWebhook  = $webhookItems  | ForEach-Object { @{ Path=$_.Path; Name=$_.Name; Type=$_.Type; Value=$null } }
            $absentBranding = $brandingItems | ForEach-Object { @{ Path=$_.Path; Name=$_.Name; Type=$_.Type; Value=$null } }
            $absentSettings = @(
                @{ Path=$b.SettingsKey; Name='installation_mode'; Type='String'; Value='blocked' },
                @{ Path=$b.SettingsKey; Name='update_url';        Type='Remove'; Value=$null }
            )
            $absentPolicy + $absentWebhook + $absentBranding + $absentSettings | ForEach-Object { $_ }
        }
    }
}

# Input validation beyond attributes
if($EnableCippReporting -eq 1){
    if([string]::IsNullOrWhiteSpace($CippServerUrl) -or [string]::IsNullOrWhiteSpace($azureTenantId)){ # $azureTenantId Value supplied by Immy environment
        throw 'CippServerUrl and CippTenantId must be provided when EnableCippReporting=1.'
    }
}

if($EnableGenericWebhook -eq 1){
    if([string]::IsNullOrWhiteSpace($GenericWebhookUrl)){
        throw 'GenericWebhookUrl must be provided when EnableGenericWebhook=1.'
    }
    if($null -eq $GenericWebhookEvents -or $GenericWebhookEvents.Count -eq 0){
        throw 'At least one event type must be specified in GenericWebhookEvents when EnableGenericWebhook=1.'
    }
}

# Build desired items once
$desiredItems = Get-DesiredItem `
    -Ensure $Ensure `
    -ChromeExtensionId $ChromeExtensionId `
    -EdgeExtensionId $EdgeExtensionId `
    -ChromeUpdateUrl $ChromeUpdateUrl `
    -EdgeUpdateUrl $EdgeUpdateUrl `
    -ShowNotifications $ShowNotifications `
    -EnableValidPageBadge $EnableValidPageBadge `
    -EnablePageBlocking $EnablePageBlocking `
    -EnableCippReporting $EnableCippReporting `
    -CippServerUrl $CippServerUrl `
    -CippTenantId $CippTenantId `
    -CustomRulesUrl $CustomRulesUrl `
    -UpdateInterval $UpdateInterval `
    -EnableDebugLogging $EnableDebugLogging `
    -urlAllowlist $urlAllowlist `
    -EnableGenericWebhook $EnableGenericWebhook `
    -GenericWebhookUrl $GenericWebhookUrl `
    -GenericWebhookEvents $GenericWebhookEvents `
    -CompanyName $CompanyName `
    -CompanyUrl $CompanyUrl `
    -ProductName $ProductName `
    -SupportEmail $SupportEmail `
    -PrimaryColor $PrimaryColor `
    -LogoUrl $LogoUrl `
    -InstallationMode $InstallationMode

if($Ensure -eq 'Present'){
    # Use ImmyBot helper pipeline for each required value; it internally interprets $method for test/set
    # Collect boolean results during test phase to determine overall compliance.
    $valueItems = $desiredItems
    $results = foreach($item in $valueItems){
        # Some keys (branding) may have empty string values; those are still enforced.
        if($Method -eq 'test'){
            Get-WindowsRegistryValue -Path $item.Path -Name $item.Name | RegistryShould-Be -Value $item.Value
        } else {
            Get-WindowsRegistryValue -Path $item.Path -Name $item.Name | RegistryShould-Be -Value $item.Value | Out-Null
        }
    }
    if($Method -eq 'test'){
        # If any helper returned $false mark non-compliant
        $compliant = ($results -notcontains $false)
        if($compliant){ Write-Host 'All extension policy settings are compliant (helper).' } else { Write-Host 'One or more policy values are non-compliant.' }
        return $compliant
    }
} else { # Ensure = Absent
    # Mirror Present logic but enforce absence using Value=$null with helper.
    $valueItems = $desiredItems
    $results = foreach($item in $valueItems){
        $targetValue = if($item.Name -eq 'installation_mode') { $item.Value } else { $null }
        if($Method -eq 'test'){
            Get-WindowsRegistryValue -Path $item.Path -Name $item.Name | RegistryShould-Be -Value $targetValue
        } else {
            Get-WindowsRegistryValue -Path $item.Path -Name $item.Name | RegistryShould-Be -Value $targetValue | Out-Null
        }
    }
    if($Method -eq 'test'){
        $compliant = ($results -notcontains $false)
        if($compliant){ Write-Host 'All extension policy values are absent as desired.' } else { Write-Host 'One or more extension policy values still present.' }
        return $compliant
    } elseif($Method -eq 'set'){
        Write-Host 'Extension policy values removed and extension blocked via installation_mode.'
    }
}

if($Method -notin 'test','set'){
    throw "Unsupported Method '$Method' (expected test or set)."
}
