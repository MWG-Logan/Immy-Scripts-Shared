<#
	Summary: Determines the identity provider(s) the endpoint is joined to (AD DS and/or Entra ID) and emits a JSON report with the relevant identifiers.
	Script Type: Device Inventory-Metascript
	Dependencies: Invoke-ImmyCommand
	Author: GitHub Copilot
#>

function Get-DomainJoinData {
	<# Retrieves domain membership info from the endpoint via CIM. #>
	Invoke-ImmyCommand {
		try {
			$system = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
			[hashtable]@{
				PartOfDomain = [bool]$system.PartOfDomain
				Domain       = $system.Domain
			}
		} catch {
			$null
		}
	}
}

function Get-EntraJoinData {
	<# Parses dsregcmd output on the endpoint to capture Entra ID join metadata. #>
	Invoke-ImmyCommand {
		$exe = Join-Path $env:SystemRoot 'System32\dsregcmd.exe'
		if (-not (Test-Path $exe)) {
			return $null
		}

		$statusLines = & $exe /status 2>$null
		if (-not $statusLines) {
			return $null
		}

		$data = [hashtable]@{
			AzureAdJoined = $null
			TenantId      = $null
			TenantName    = $null
			DeviceId      = $null
		}

		foreach ($line in $statusLines) {
			if (-not $data.AzureAdJoined -and $line -match 'AzureAdJoined\s*:\s*(\w+)') {
				$data.AzureAdJoined = $matches[1].Trim().ToUpperInvariant()
				continue
			}

			if (-not $data.TenantId -and $line -match 'TenantId\s*:\s*([0-9a-fA-F-]+)') {
				$data.TenantId = $matches[1].Trim()
				continue
			}

			if (-not $data.TenantName -and $line -match 'TenantName\s*:\s*(.+)$') {
				$data.TenantName = $matches[1].Trim()
				continue
			}

			if (-not $data.DeviceId -and $line -match 'DeviceId\s*:\s*([0-9a-fA-F-]+)') {
				$data.DeviceId = $matches[1].Trim()
			}
		}

		$data
	}
}

$domainInfo = Get-DomainJoinData
$entraInfo  = Get-EntraJoinData

$hasAdDomain    = $false
$adDomainName   = $null
$adPartOfDomain = $false

if ($domainInfo -and $domainInfo.PartOfDomain -and $domainInfo.Domain) {
	$hasAdDomain    = $true
	$adDomainName   = $domainInfo.Domain
	$adPartOfDomain = $domainInfo.PartOfDomain
}

$hasEntraJoin = $false
$entraTenantId = $null
$entraTenantName = $null
$entraDeviceId = $null

if ($entraInfo -and $entraInfo.AzureAdJoined -eq 'YES' -and $entraInfo.TenantId) {
	$hasEntraJoin  = $true
	$entraTenantId = $entraInfo.TenantId
	$entraTenantName = $entraInfo.TenantName
	$entraDeviceId = $entraInfo.DeviceId
}

$idpType = 'Unknown'
if ($hasAdDomain -and $hasEntraJoin) {
	$idpType = 'Hybrid (AD DS + Entra ID)'
} elseif ($hasAdDomain) {
	$idpType = 'AD DS'
} elseif ($hasEntraJoin) {
	$idpType = 'Entra ID'
}

$result = [hashtable]@{
	ComputerName        = $ComputerName
	IdentityProvider    = $idpType
	AdDomainName        = $adDomainName
	AdPartOfDomain      = $adPartOfDomain
	EntraTenantId       = $entraTenantId
	EntraTenantName     = $entraTenantName
	EntraDeviceId       = $entraDeviceId
	GeneratedOnUtc      = (Get-Date).ToUniversalTime().ToString('o')
}

$result
