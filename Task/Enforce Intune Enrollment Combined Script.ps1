<#
Enforce Intune Enrollment

Requires the Set-ScheduledTask function script from this repository (with -Scope support),
and an Azure tenant bound to the Immy tenant ($AzureTenantId).
Deploy to Entra-joined computers only.

TEST passes only when this PC is really enrolled in Intune:
  - an enrollment key with ProviderID "MS DM Server", and
  - an unexpired Intune MDM device certificate in the machine store.
The registry policy values are NOT part of the test. They are only a means to enroll.

SET, when the PC is not enrolled:
  1. Writes the auto-enroll policy values and MDM URLs.
  2. Registers a SYSTEM scheduled task that runs the enroller at every logon,
     so enrollment does not depend on when an Immy session happens to run.
  3. If an Entra user with a PRT is signed in right now, runs the enroller immediately,
     waits up to 5 minutes, and throws with the MDM event log errors if it did not enroll.
  4. If nobody suitable is signed in, warns "pending next logon". The test stays false
     until the PC has actually enrolled.

THROWS in every mode when the PC is not Entra-joined, or is joined to a different
tenant than the one bound to this Immy tenant ($AzureTenantId).
#>

$TaskName = 'Intune Auto-Enroll at Logon'
$TaskDesc = 'Runs the MDM auto-enroller as SYSTEM at each logon until this PC is enrolled in Intune. Managed by ImmyBot.'
$EnrollerScript = {
$enrolled = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ItemProperty -Path $_.PSPath } |
    Where-Object { $_.ProviderID -eq 'MS DM Server' }
$cert = Get-ChildItem 'Cert:\LocalMachine\My' |
    Where-Object { $_.Issuer -like '*Microsoft Intune MDM Device CA*' -and $_.NotAfter -gt (Get-Date) }
# Same test as Get-IntuneEnrollmentState below: key AND unexpired certificate
if ($enrolled -and $cert) { exit 0 }
# Give the logon time to finish so the user's Entra token is available
Start-Sleep -Seconds 60
& "$env:windir\System32\deviceenroller.exe" /c /AutoEnrollMDM
}

function Get-IntuneEnrollmentState {
    Invoke-ImmyCommand {
        $joinKey = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo' -ErrorAction SilentlyContinue | Select-Object -First 1
        $joinTenantId = $null
        if ($joinKey) { $joinTenantId = (Get-ItemProperty -Path $joinKey.PSPath).TenantId }

        $enrollment = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue |
            ForEach-Object { Get-ItemProperty -Path $_.PSPath } |
            Where-Object { $_.ProviderID -eq 'MS DM Server' } |
            Select-Object -First 1

        $cert = Get-ChildItem 'Cert:\LocalMachine\My' |
            Where-Object { $_.Issuer -like '*Microsoft Intune MDM Device CA*' -and $_.NotAfter -gt (Get-Date) } |
            Sort-Object NotAfter -Descending |
            Select-Object -First 1

        $enrollmentId = $null; $enrollmentUpn = $null; $certExpires = $null
        if ($enrollment) { $enrollmentId = $enrollment.PSChildName; $enrollmentUpn = $enrollment.UPN }
        if ($cert) { $certExpires = $cert.NotAfter.ToString('s') }

        [pscustomobject]@{
            JoinTenantId   = $joinTenantId
            EnrollmentId   = $enrollmentId
            EnrollmentUpn  = $enrollmentUpn
            MdmCertExpires = $certExpires
            Enrolled       = [bool]($enrollment -and $cert)
        }
    }
}

$State = Get-IntuneEnrollmentState

# Guard rails: refuse to touch a PC that is not joined to the tenant Immy thinks it belongs to
if ([string]::IsNullOrWhiteSpace($AzureTenantId)) {
    throw "No Azure tenant is bound to this Immy tenant (`$AzureTenantId is empty). Bind it before running this task."
}
if ([string]::IsNullOrWhiteSpace($State.JoinTenantId)) {
    throw "This PC is not Entra-joined (no CloudDomainJoin\JoinInfo). It cannot auto-enroll in Intune. Fix the join first."
}
if ($State.JoinTenantId -ne $AzureTenantId) {
    throw "Tenant mismatch: this PC is joined to Entra tenant $($State.JoinTenantId), but this Immy tenant is bound to $AzureTenantId. Not touching it."
}

switch ($method) {
    'get' {
        return $State
    }

    'test' {
        if ($State.Enrolled) {
            Write-Host "Enrolled in Intune. Enrollment $($State.EnrollmentId) ($($State.EnrollmentUpn)), MDM certificate valid until $($State.MdmCertExpires)."
        } else {
            Write-Warning "NOT enrolled in Intune. Enrollment key: $([bool]$State.EnrollmentId). Valid MDM certificate: $([bool]$State.MdmCertExpires)."
        }
        return [bool]$State.Enrolled
    }

    'set' {
        if ($State.Enrolled) {
            Write-Host "Already enrolled in Intune. Nothing to do."
            return
        }

        # 1. Policy values and MDM URLs
        $mdmSettingsPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM'
        $null = Get-WindowsRegistryValue -Path $mdmSettingsPath -Name 'AutoEnrollMDM' | RegistryShould-Be -Value 1
        $null = Get-WindowsRegistryValue -Path $mdmSettingsPath -Name 'UseAADCredentialType' | RegistryShould-Be -Value 1

        $enrollmentPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\$AzureTenantId"
        $null = Get-WindowsRegistryValue -Path $enrollmentPath -Name 'MdmEnrollmentUrl' | RegistryShould-Be -Value 'https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc' -Type String
        $null = Get-WindowsRegistryValue -Path $enrollmentPath -Name 'MdmTermsOfUseUrl' | RegistryShould-Be -Value 'https://portal.manage.microsoft.com/TermsofUse.aspx' -Type String
        $null = Get-WindowsRegistryValue -Path $enrollmentPath -Name 'MdmComplianceUrl' | RegistryShould-Be -Value 'https://portal.manage.microsoft.com/?portalAction=Compliance' -Type String

        # 2. SYSTEM task that retries at every logon
        $null = Set-ScheduledTask -TaskName $TaskName -TaskDesc $TaskDesc -Trigger AtLogOn -Scope System -ScriptContent $EnrollerScript
        Write-Host "Registered scheduled task '$TaskName' (SYSTEM, at logon)."

        # 3. Is an Entra user with a PRT signed in right now?
        $dsreg = Invoke-ImmyCommand -ContextString User { dsregcmd /status | Out-String }
        $hasPrt = ("$dsreg" -match 'AzureAdPrt\s*:\s*YES')
        if (-not $hasPrt) {
            Write-Warning "No Entra user with a valid PRT is signed in. Enrollment is pending the next Entra user logon; this PC stays non-compliant until then."
            return
        }

        Write-Host "Entra user with a PRT is signed in. Running the enroller now."
        $null = Invoke-ImmyCommand { & "$env:windir\System32\deviceenroller.exe" /c /AutoEnrollMDM }

        # 4. Wait up to 5 minutes for the enrollment to appear
        $attempt = 0
        do {
            Start-Sleep -Seconds 10
            $attempt++
            $State = Get-IntuneEnrollmentState
            Write-Progress -Activity "Waiting for Intune enrollment" -CurrentOperation "Check $attempt of 30" -PercentComplete ([int]($attempt / 30 * 100))
        } while (-not $State.Enrolled -and $attempt -lt 30)
        Write-Progress -Activity "Waiting for Intune enrollment" -Completed

        if ($State.Enrolled) {
            Write-Host "Enrolled in Intune. Enrollment $($State.EnrollmentId) ($($State.EnrollmentUpn))."
            return
        }

        $events = Invoke-ImmyCommand {
            Get-WinEvent -FilterHashtable @{
                LogName   = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
                Level     = 1, 2, 3
                StartTime = (Get-Date).AddMinutes(-10)
            } -MaxEvents 10 -ErrorAction SilentlyContinue |
                ForEach-Object { "$($_.TimeCreated.ToString('s')) Id=$($_.Id) $($_.Message)" }
        }
        $eventText = ($events | Out-String)
        if ([string]::IsNullOrWhiteSpace($eventText)) { $eventText = '(no warning or error events in the MDM Admin log in the last 10 minutes)' }
        throw "Enroller ran but this PC did not enroll in Intune within 5 minutes. Recent MDM events:`n$eventText"
    }
}
