<#
Configure ImmyBot as an App Control managed installer

Onboarded : merges an AppLocker ManagedInstaller rule for the ImmyBot agent (signed by ImmyBot LLC),
            turns on managed installer tracking, and restarts the ImmyBot agent once so it runs
            under the rule. Files ImmyBot installs are then tagged, and an App Control policy with
            "Enabled:Managed Installer" trusts them.
Offboarded: removes only the ImmyBot rule from the AppLocker policy, the same way Microsoft's
            CatCleanIMEOnly.ps1 removes the Intune rule, and restarts the agent once.

TEST is functional, not just "is the rule there": it writes a probe file through ImmyBot and checks
whether Windows tagged it ($KERNEL.SMARTLOCKER.ORIGINCLAIM). The probe is deleted straight away.

The rule and the Exe/Dll placeholder collections follow Microsoft's
"Allow apps deployed with an App Control managed installer". Nothing here blocks any program.

Refuses to touch a PC whose existing AppLocker policy has an Exe or Dll collection that is
enforced or "NotConfigured": merging into those can start blocking programs or services.

Refuses Windows builds older than 15063 (Windows 10 1703). Managed installer does not exist there,
so that includes Server 2016 and Server 2012 R2.

Windows applies a changed AppLocker policy in the background, which has taken two to four minutes
on real PCs. The agent only runs under the rule if it starts after that, so Set waits for the
compiled policy before restarting the agent, and retries the restart if tagging has not started.
#>
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Onboarded', 'Offboarded')]
    [string]$ManagedInstallerState = 'Onboarded'
)

$RuleId = '5d2a7c3e-9b41-4f0a-8c6d-1e7f3a9b2c54'
$PublisherName = 'O=IMMYBOT LLC, L=BATON ROUGE, S=LOUISIANA, C=US'
$ProductName = 'IMMYBOT.AGENT'
$RestartTaskName = 'ImmyBot agent restart (managed installer)'

$PolicyXml = @"
<?xml version="1.0" encoding="utf-8"?>
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Benign DENY Rule" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" />
      </Conditions>
    </FilePathRule>
    <RuleCollectionExtensions>
      <ThresholdExtensions>
        <Services EnforcementMode="Enabled" />
      </ThresholdExtensions>
      <RedstoneExtensions>
        <SystemApps Allow="Enabled" />
      </RedstoneExtensions>
    </RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Benign DENY Rule" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" />
      </Conditions>
    </FilePathRule>
    <RuleCollectionExtensions>
      <ThresholdExtensions>
        <Services EnforcementMode="Enabled" />
      </ThresholdExtensions>
      <RedstoneExtensions>
        <SystemApps Allow="Enabled" />
      </RedstoneExtensions>
    </RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="AuditOnly">
    <FilePublisherRule Id="$RuleId" Name="ImmyBot agent (ImmyBot LLC)" Description="Immybot.Agent.exe and ImmyBot.Agent.Ephemeral.exe" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="$PublisherName" ProductName="$ProductName" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
</AppLockerPolicy>
"@

function Get-ManagedInstallerState {
    Invoke-ImmyCommand -AgentConnectionWaitTimeout (New-TimeSpan -Minutes 5) {
        $ruleId = $using:RuleId
        [xml]$effective = Get-AppLockerPolicy -Effective -Xml
        $collections = @($effective.AppLockerPolicy.ChildNodes | Where-Object { $_.LocalName -eq 'RuleCollection' })
        $mi = $collections | Where-Object { $_.Type -eq 'ManagedInstaller' }
        $miRules = @()
        if ($mi) { $miRules = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' }) }
        $exe = $collections | Where-Object { $_.Type -eq 'Exe' }
        $dll = $collections | Where-Object { $_.Type -eq 'Dll' }

        # Functional probe: copy a small Windows binary through this process tree and see if it gets tagged
        $probeDir = Join-Path $env:windir 'Temp\ImmyBotMIProbe'
        $probe = Join-Path $probeDir 'probe.exe'
        $tagged = $false
        try {
            if (-not (Test-Path $probeDir)) { New-Item -Path $probeDir -ItemType Directory | Out-Null }
            Copy-Item -Path (Join-Path $env:windir 'System32\choice.exe') -Destination $probe -Force
            $ea = (& fsutil.exe file queryEA $probe 2>&1 | Out-String)
            $tagged = [bool]($ea -match 'SMARTLOCKER')
        } finally {
            Remove-Item -LiteralPath $probeDir -Recurse -Force -ErrorAction SilentlyContinue
        }

        $compiled = Get-Item (Join-Path $env:windir (Join-Path 'System32' (Join-Path 'AppLocker' 'ManagedInstaller.AppLocker'))) -ErrorAction SilentlyContinue
        $agent = Get-Process -Name 'Immybot.Agent' -ErrorAction SilentlyContinue | Sort-Object StartTime | Select-Object -First 1
        [pscustomobject]@{
            RulePresent       = [bool]($miRules | Where-Object { $_.Id -eq $ruleId })
            OtherMiRules      = @($miRules | Where-Object { $_.Id -ne $ruleId }).Count
            ExeMode           = if ($exe) { "$($exe.EnforcementMode)" } else { 'Absent' }
            DllMode           = if ($dll) { "$($dll.EnforcementMode)" } else { 'Absent' }
            AppIdSvc          = "$((Get-Service AppIDSvc -ErrorAction SilentlyContinue).Status)"
            AppLockerFilter   = "$((Get-Service applockerfltr -ErrorAction SilentlyContinue).Status)"
            ProbeTagged       = $tagged
            AgentStarted      = if ($agent) { $agent.StartTime.ToString('s') } else { '' }
            OsBuild           = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
            CompiledPolicy    = if ($compiled) { $compiled.LastWriteTime.ToString('s') } else { '' }
            DeviceTime        = (Get-Date).ToString('s')
            RestartTaskExists = [bool](Get-ScheduledTask -TaskName $using:RestartTaskName -ErrorAction SilentlyContinue)
        }
    }
}

function Restart-ImmyAgentAndWait {
    # A session cannot restart the agent it is running under, so a self-deleting scheduled task does it.
    Invoke-ImmyCommand {
        $when = (Get-Date).AddSeconds(15)
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -WindowStyle Hidden -Command "Restart-Service -Name ''ImmyBot Agent'' -Force"'
        $trigger = New-ScheduledTaskTrigger -Once -At $when
        $trigger.EndBoundary = $when.AddMinutes(10).ToString('s')
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter (New-TimeSpan -Seconds 0) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $using:RestartTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    }
    Write-Host "ImmyBot agent restart scheduled. Waiting for the agent to come back."
    Start-Sleep -Seconds 50
    $state = Get-ManagedInstallerState
    if ($state.RestartTaskExists) {
        Invoke-ImmyCommand { Unregister-ScheduledTask -TaskName $using:RestartTaskName -Confirm:$false -ErrorAction SilentlyContinue }
    }
    return $state
}

function Wait-ManagedInstallerPolicyCompiled {
    # Waits until Windows has compiled the AppLocker policy that was merged at $Since (device local time).
    param([string]$Since, [int]$TimeoutSeconds = 480)
    $waited = 0
    $state = Get-ManagedInstallerState
    while ((-not $state.CompiledPolicy -or $state.CompiledPolicy -lt $Since) -and $waited -lt $TimeoutSeconds) {
        Start-Sleep -Seconds 5
        $waited += 5
        $state = Get-ManagedInstallerState
    }
    if ($state.CompiledPolicy -and $state.CompiledPolicy -ge $Since) { Write-Host "Windows compiled the AppLocker policy at $($state.CompiledPolicy), after waiting $waited seconds." }
    else { Write-Warning "Windows has not compiled the new AppLocker policy after $waited seconds (compiled policy time: '$($state.CompiledPolicy)')." }
    return $state
}

$MinimumBuild = 15063
$State = Get-ManagedInstallerState
$wantOnboarded = ($ManagedInstallerState -eq 'Onboarded')
$compliant = if ($wantOnboarded) { $State.RulePresent -and $State.ProbeTagged } else { (-not $State.RulePresent) -and (-not $State.ProbeTagged) }

switch ($method) {
    'get' {
        return $State
    }

    'test' {
        $summary = "rule present: $($State.RulePresent); files written by ImmyBot are tagged: $($State.ProbeTagged); other managed installer rules: $($State.OtherMiRules); Exe=$($State.ExeMode) Dll=$($State.DllMode)"
        if ($compliant) { Write-Host "ImmyBot managed installer is $ManagedInstallerState. $summary" }
        else { Write-Warning "ImmyBot managed installer is NOT $ManagedInstallerState. $summary" }
        return [bool]$compliant
    }

    'set' {
        if ($compliant) {
            Write-Host "Already $ManagedInstallerState. Nothing to do."
            return
        }

        if ($wantOnboarded) {
            if ($State.OsBuild -lt $MinimumBuild) {
                throw "This computer runs Windows build $($State.OsBuild). Managed installer needs build $MinimumBuild (Windows 10 1703) or later. Not changing it."
            }
            $mergedAt = ''
            if (-not $State.RulePresent) {
                foreach ($mode in @($State.ExeMode, $State.DllMode)) {
                    if ($mode -eq 'Enabled' -or $mode -eq 'NotConfigured') {
                        throw "This PC already has an AppLocker policy with an Exe or Dll collection in '$mode' mode (Exe=$($State.ExeMode), Dll=$($State.DllMode)). Merging the managed installer rule into that can start blocking programs or services. Not changing it."
                    }
                }
                $mergedAt = $State.DeviceTime
                Invoke-ImmyCommand {
                    $file = Join-Path $env:windir 'Temp\immybot-managed-installer.xml'
                    try {
                        Set-Content -Path $file -Value $using:PolicyXml -Encoding UTF8
                        Set-AppLockerPolicy -XmlPolicy $file -Merge -ErrorAction Stop
                    } finally {
                        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
                    }
                    $out = (& "$env:windir\System32\appidtel.exe" start 2>&1 | Out-String)
                    if ($LASTEXITCODE -ne 0) { throw "appidtel.exe start failed with exit code $LASTEXITCODE. $out" }
                    # Ask Windows to compile the new policy now; left alone it has taken two to four minutes
                    Start-ScheduledTask -TaskPath '\Microsoft\Windows\AppID\' -TaskName 'PolicyConverter' -ErrorAction SilentlyContinue
                }
                Write-Host "Merged the ImmyBot managed installer rule and turned on tracking."
                $State = Wait-ManagedInstallerPolicyCompiled -Since $mergedAt
                if (-not $State.RulePresent) { throw "The AppLocker merge reported success but the ImmyBot rule is not in the effective policy (compiled policy time: '$($State.CompiledPolicy)')." }
            }
            elseif (-not $State.ProbeTagged -and -not $State.CompiledPolicy) {
                # Rule merged by an earlier run that Windows has not compiled yet
                $State = Wait-ManagedInstallerPolicyCompiled -Since '0'
            }

            $attempt = 0
            while (-not $State.ProbeTagged -and $attempt -lt 3) {
                if ($attempt -gt 0) {
                    Write-Host "Files written by ImmyBot are not tagged yet. Waiting 60 seconds before restarting the agent again."
                    Start-Sleep -Seconds 60
                }
                $attempt++
                $State = Restart-ImmyAgentAndWait
            }
            if (-not $State.ProbeTagged) {
                throw "The rule is in place and the agent was restarted $attempt times (agent started $($State.AgentStarted), policy compiled '$($State.CompiledPolicy)'), but files written by ImmyBot are still not tagged. AppIDSvc=$($State.AppIdSvc), filter=$($State.AppLockerFilter)."
            }
            Write-Host "ImmyBot is onboarded as a managed installer. Files it writes are tagged."
            return
        }

        # Offboarded
        if ($State.RulePresent) {
            Invoke-ImmyCommand {
                [xml]$effective = Get-AppLockerPolicy -Effective -Xml
                Write-Host "AppLocker policy before the change: $($effective.OuterXml)"
                $new = $effective.Clone()
                $mi = $new.AppLockerPolicy.ChildNodes | Where-Object { $_.LocalName -eq 'RuleCollection' -and $_.Type -eq 'ManagedInstaller' }
                $rule = $mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and $_.Id -eq $using:RuleId }
                $condition = $rule.ChildNodes | ForEach-Object { $_.ChildNodes } | Where-Object { $_.LocalName -eq 'FilePublisherCondition' -and $_.PublisherName -eq $using:PublisherName }
                if (-not $rule -or -not $condition) { throw "Found rule id $($using:RuleId) but it is not the ImmyBot LLC publisher rule. Not removing it." }
                $mi.RemoveChild($rule) | Out-Null
                if (@($mi.ChildNodes | Where-Object { $_.LocalName -like 'File*Rule' }).Count -eq 0) { $mi.ParentNode.RemoveChild($mi) | Out-Null }
                $file = Join-Path $env:windir 'Temp\immybot-managed-installer-offboard.xml'
                try {
                    Set-Content -Path $file -Value $new.OuterXml -Encoding UTF8
                    Set-AppLockerPolicy -XmlPolicy $file -ErrorAction Stop
                } finally {
                    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
                }
            }
            Write-Host "Removed the ImmyBot managed installer rule. Other AppLocker rules and tracking are left as they were."
            $State = Get-ManagedInstallerState
            if ($State.RulePresent) { throw "The ImmyBot rule is still in the effective AppLocker policy after removal." }
        }

        if ($State.ProbeTagged) {
            $State = Restart-ImmyAgentAndWait
        }
        if ($State.ProbeTagged) {
            throw "The ImmyBot rule is removed and the agent was restarted, but files written by ImmyBot are still tagged. Another managed installer rule may cover this process tree (other rules: $($State.OtherMiRules))."
        }
        Write-Host "ImmyBot is offboarded as a managed installer."
    }
}
