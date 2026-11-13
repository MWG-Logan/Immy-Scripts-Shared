<#
Configure ImmyBot as an App Control managed installer

Onboarded : merges an AppLocker ManagedInstaller rule for the ImmyBot agent (signed by ImmyBot LLC),
            turns on managed installer tracking, and restarts the ImmyBot agent once so it runs
            under the rule. Files ImmyBot installs are then tagged, and an App Control policy with
            "Enabled:Managed Installer" trusts them.
Offboarded: removes only the ImmyBot rule from the local AppLocker policy, the same way Microsoft's
            CatCleanIMEOnly.ps1 removes the Intune rule, waits for Windows to apply that, and
            restarts the agent once. The Exe/Dll AuditOnly placeholder collections and managed
            installer tracking stay, because other managed installers may rely on them.

TEST is functional, not just "is the rule there": it writes a probe file through ImmyBot and checks
whether Windows tagged it ($KERNEL.SMARTLOCKER.ORIGINCLAIM). The probe is deleted straight away.

The rule and the Exe/Dll placeholder collections follow Microsoft's
"Allow apps deployed with an App Control managed installer". Nothing here blocks any program.

Refuses to touch a PC whose existing AppLocker policy has an Exe or Dll collection that is
enforced or "NotConfigured": merging into those can start blocking programs or services.

Refuses Windows builds older than 15063 (Windows 10 1703). Managed installer does not exist there,
so that includes Server 2016 and Server 2012 R2.

Windows applies a changed AppLocker policy in the background, which has taken two to four minutes
on real PCs. The agent only picks up a change if it starts after that, so Set (both directions)
asks Windows to compile the policy straight away, waits for it before restarting the agent, and
retries the restart if tagging has not started.

If Windows never writes ManagedInstaller.AppLocker, Set fails straight away with the AppID driver
start type and the compiled policy files, instead of restarting the agent. On some PCs the AppID
driver stays DEMAND_START after "appidtel.exe start" and the compiled policy never appears;
restarting the agent cannot fix that.
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
# Invoke-ImmyCommand defaults to 120 seconds. The state check has taken longer than that on some PCs
# (mostly a slow scheduled-task lookup), which failed Test with "Script timed out after 120 seconds".
$CommandTimeoutSeconds = 600

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
    Invoke-ImmyCommand -Timeout $CommandTimeoutSeconds -AgentConnectionWaitTimeout (New-TimeSpan -Minutes 5) {
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

        $compiledDir = Join-Path $env:windir 'System32\AppLocker'
        $compiled = Get-Item (Join-Path $compiledDir 'ManagedInstaller.AppLocker') -ErrorAction SilentlyContinue
        $agent = Get-Process -Name 'Immybot.Agent' -ErrorAction SilentlyContinue | Sort-Object StartTime | Select-Object -First 1
        $converter = Get-ScheduledTask -TaskPath '\Microsoft\Windows\AppID\' -TaskName 'PolicyConverter' -ErrorAction SilentlyContinue | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        # 0 = BOOT_START (what appidtel.exe start leaves on working PCs), 3 = DEMAND_START
        $appIdDriverStart = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\AppID' -Name Start -ErrorAction SilentlyContinue).Start
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
            # UTC round-trip format: keeps fractional seconds and still sorts correctly as a string
            CompiledPolicy    = if ($compiled) { $compiled.LastWriteTimeUtc.ToString('o') } else { '' }
            DeviceTime        = (Get-Date).ToUniversalTime().ToString('o')
            # -TaskPath matters: a name-only lookup searches every task folder and took 260 s on one PC
            RestartTaskExists = [bool](Get-ScheduledTask -TaskPath '\' -TaskName $using:RestartTaskName -ErrorAction SilentlyContinue)
            AppIdDriverStart  = "$appIdDriverStart"
            CompiledFiles     = (@(Get-ChildItem -LiteralPath $compiledDir -Filter '*.AppLocker' -File -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)=$($_.Length)B@$($_.LastWriteTimeUtc.ToString('s'))Z" }) -join ', ')
            PolicyConverter   = if ($converter) { "last run $($converter.LastRunTime.ToString('s')), result 0x$('{0:X}' -f $converter.LastTaskResult)" } else { 'task not found' }
        }
    }
}

function Restart-ImmyAgentAndWait {
    # A session cannot restart the agent it is running under, so a self-deleting scheduled task does it.
    Invoke-ImmyCommand -Timeout $CommandTimeoutSeconds {
        $when = (Get-Date).AddSeconds(15)
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -WindowStyle Hidden -Command "Restart-Service -Name ''ImmyBot Agent'' -Force"'
        $trigger = New-ScheduledTaskTrigger -Once -At $when
        $trigger.EndBoundary = $when.AddMinutes(10).ToString('s')
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter (New-TimeSpan -Seconds 0) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskPath '\' -TaskName $using:RestartTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    }
    Write-Host "ImmyBot agent restart scheduled. Waiting for the agent to come back."
    Start-Sleep -Seconds 50
    $state = Get-ManagedInstallerState
    if ($state.RestartTaskExists) {
        Invoke-ImmyCommand -Timeout $CommandTimeoutSeconds { Unregister-ScheduledTask -TaskPath '\' -TaskName $using:RestartTaskName -Confirm:$false -ErrorAction SilentlyContinue }
    }
    return $state
}

function Get-CompiledPolicyTime {
    # Lightweight poll: only the compiled ManagedInstaller policy's write time (UTC, 'o'), or '' if the file is absent
    Invoke-ImmyCommand -Timeout $CommandTimeoutSeconds {
        $compiled = Get-Item (Join-Path $env:windir 'System32\AppLocker\ManagedInstaller.AppLocker') -ErrorAction SilentlyContinue
        if ($compiled) { $compiled.LastWriteTimeUtc.ToString('o') } else { '' }
    }
}

function Start-AppLockerPolicyCompile {
    # Ask Windows to compile the AppLocker policy now; left alone it has taken two to four minutes
    Invoke-ImmyCommand -Timeout $CommandTimeoutSeconds {
        Start-ScheduledTask -TaskPath '\Microsoft\Windows\AppID\' -TaskName 'PolicyConverter' -ErrorAction SilentlyContinue
    }
}

function Wait-ManagedInstallerPolicyCompiled {
    # Waits until Windows has compiled the AppLocker policy that was changed at $Since (device UTC, 'o' format).
    # -AllowMissing: also done when the compiled file is gone, which can happen when the last
    # ManagedInstaller collection is removed.
    # 240 s: with PolicyConverter started the compile has landed within seconds; untriggered it took 2-4 min.
    param([string]$Since, [switch]$AllowMissing, [int]$TimeoutSeconds = 240)
    $waited = 0
    while ($true) {
        $compiled = Get-CompiledPolicyTime
        $done = ($compiled -and $compiled -ge $Since) -or ($AllowMissing -and -not $compiled)
        if ($done -or $waited -ge $TimeoutSeconds) { break }
        Start-Sleep -Seconds 5
        $waited += 5
    }
    if ($done) {
        if ($compiled) { Write-Host "Windows compiled the AppLocker policy at $compiled, after waiting $waited seconds." }
        else { Write-Host "Windows removed the compiled managed installer policy, after waiting $waited seconds." }
    }
    else { Write-Warning "Windows has not compiled the changed AppLocker policy after $waited seconds (compiled policy time: '$compiled')." }
    return Get-ManagedInstallerState
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
        $summary = "rule present: $($State.RulePresent); files written by ImmyBot are tagged: $($State.ProbeTagged); other managed installer rules: $($State.OtherMiRules); Exe=$($State.ExeMode) Dll=$($State.DllMode); AppID driver start type: $($State.AppIdDriverStart); compiled policy files: '$($State.CompiledFiles)'"
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
            # Since '0': any compiled policy counts. Used when the rule came from an earlier run.
            $changedAt = '0'
            if (-not $State.RulePresent) {
                foreach ($mode in @($State.ExeMode, $State.DllMode)) {
                    if ($mode -eq 'Enabled' -or $mode -eq 'NotConfigured') {
                        throw "This PC already has an AppLocker policy with an Exe or Dll collection in '$mode' mode (Exe=$($State.ExeMode), Dll=$($State.DllMode)). Merging the managed installer rule into that can start blocking programs or services. Not changing it."
                    }
                }
                $changedAt = Invoke-ImmyCommand -Timeout $CommandTimeoutSeconds {
                    $file = Join-Path $env:windir 'Temp\immybot-managed-installer.xml'
                    try {
                        Set-Content -Path $file -Value $using:PolicyXml -Encoding UTF8
                        $at = (Get-Date).ToUniversalTime().ToString('o')
                        Set-AppLockerPolicy -XmlPolicy $file -Merge -ErrorAction Stop
                    } finally {
                        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
                    }
                    $at
                }
                Write-Host "Merged the ImmyBot managed installer rule."
            }

            # Runs on every onboarding Set, not just right after the merge, so a run that merged the rule
            # but failed here is repaired by the next run. appidtel.exe start is safe to repeat.
            Invoke-ImmyCommand -Timeout $CommandTimeoutSeconds {
                $out = (& "$env:windir\System32\appidtel.exe" start 2>&1 | Out-String)
                if ($LASTEXITCODE -ne 0) { throw "appidtel.exe start failed with exit code $LASTEXITCODE. $out" }
            }
            Write-Host "Managed installer tracking is on."
            Start-AppLockerPolicyCompile
            $State = Wait-ManagedInstallerPolicyCompiled -Since $changedAt
            $diagnostics = "AppID driver start type: $($State.AppIdDriverStart) (0 = boot start, expected after appidtel.exe start). Compiled policy files: '$($State.CompiledFiles)'. PolicyConverter: $($State.PolicyConverter). AppIDSvc=$($State.AppIdSvc), filter=$($State.AppLockerFilter)."
            if (-not $State.RulePresent) { throw "The AppLocker merge reported success but the ImmyBot rule is not in the effective policy. $diagnostics" }
            if (-not $State.ProbeTagged -and -not ($State.CompiledPolicy -and $State.CompiledPolicy -ge $changedAt)) {
                # Restarting the agent cannot help until Windows has compiled the policy, so stop here
                throw "The rule is in place but Windows has not compiled the managed installer policy (ManagedInstaller.AppLocker is missing or older than the change). Not restarting the agent. $diagnostics"
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
                throw "The rule is in place and the agent was restarted $attempt times (agent started $($State.AgentStarted), policy compiled '$($State.CompiledPolicy)'), but files written by ImmyBot are still not tagged. AppID driver start type: $($State.AppIdDriverStart). Compiled policy files: '$($State.CompiledFiles)'. AppIDSvc=$($State.AppIdSvc), filter=$($State.AppLockerFilter)."
            }
            Write-Host "ImmyBot is onboarded as a managed installer. Files it writes are tagged."
            return
        }

        # Offboarded
        if ($State.RulePresent) {
            $removedAt = Invoke-ImmyCommand -Timeout $CommandTimeoutSeconds {
                # Edit the LOCAL policy only. The effective policy includes domain GPO rules, and writing
                # that back would copy them into local policy, where they outlive the GPO.
                [xml]$local = Get-AppLockerPolicy -Local -Xml
                Write-Host "Local AppLocker policy before the change: $($local.OuterXml)"
                $new = $local.Clone()
                $mi = $new.AppLockerPolicy.ChildNodes | Where-Object { $_.LocalName -eq 'RuleCollection' -and $_.Type -eq 'ManagedInstaller' }
                $rule = $mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and $_.Id -eq $using:RuleId }
                if (-not $rule) { throw "The ImmyBot rule (id $($using:RuleId)) is in the effective AppLocker policy but not in the local policy, so it comes from Group Policy or another source. Remove it there." }
                $condition = $rule.ChildNodes | ForEach-Object { $_.ChildNodes } | Where-Object { $_.LocalName -eq 'FilePublisherCondition' -and $_.PublisherName -eq $using:PublisherName }
                if (-not $condition) { throw "Found rule id $($using:RuleId) but it is not the ImmyBot LLC publisher rule. Not removing it." }
                $mi.RemoveChild($rule) | Out-Null
                if (@($mi.ChildNodes | Where-Object { $_.LocalName -like 'File*Rule' }).Count -eq 0) { $mi.ParentNode.RemoveChild($mi) | Out-Null }
                $file = Join-Path $env:windir 'Temp\immybot-managed-installer-offboard.xml'
                try {
                    Set-Content -Path $file -Value $new.OuterXml -Encoding UTF8
                    $at = (Get-Date).ToUniversalTime().ToString('o')
                    Set-AppLockerPolicy -XmlPolicy $file -ErrorAction Stop
                } finally {
                    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
                }
                $at
            }
            Write-Host "Removed the ImmyBot managed installer rule. Other AppLocker rules and tracking are left as they were."
            # The agent must restart after Windows compiles the removal, or it starts under the old policy
            Start-AppLockerPolicyCompile
            $State = Wait-ManagedInstallerPolicyCompiled -Since $removedAt -AllowMissing
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
