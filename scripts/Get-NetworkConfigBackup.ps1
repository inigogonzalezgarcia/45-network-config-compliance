<#
.SYNOPSIS
    Read-only collector of the running configurations that netcompliance reads: connects to every switch, router and firewall in
    inventory.csv over SSH and saves the output of one show command to configs/<hostname>.cfg.

.DESCRIPTION
    Only read commands are sent:
      - Cisco IOS / IOS-XE:  terminal length 0, then show running-config
      - ArubaOS-Switch:      no page, then show running-config
      - FortiOS:             show full-configuration
    "terminal length 0" and "no page" only turn off paging for this SSH session; they are not configuration commands and nothing is
    saved on the device. No configure, copy, write, execute or set command is ever sent.

    Credentials are asked with Get-Credential (or passed as a PSCredential) and kept in memory for the run only; nothing is written to
    disk except the configurations and backup_log.csv. Use a read-only account: privilege 15 is needed on Cisco to see the whole running
    configuration, so use a TACACS+ command authorisation set that allows "show running-config" and nothing else; on ArubaOS-Switch
    check that the account level you use can display the running configuration; on FortiGate an administrator profile with read-only
    access.

    Module: Posh-SSH (Install-Module Posh-SSH -Scope CurrentUser), with New-SSHSession, New-SSHShellStream, Invoke-SSHCommand and
    Remove-SSHSession. Host keys are checked against the Posh-SSH trusted hosts; -AcceptNewHostKey trusts the key of a device seen for
    the first time (verify the fingerprints out of band).

    Already running Oxidized or RANCID? You do not need this script: point netcompliance at a folder with their backups (Oxidized
    stores one file per node, named after the node, with or without .cfg; RANCID keeps <group>/configs/<hostname>). Keep the
    "! Last configuration change" and "! NVRAM config last updated" lines (some Oxidized setups remove them to keep diffs quiet); without
    them the unsaved-change and change-ticket rules are n/a.

    Files written:
      - <OutputFolder>\configs\<hostname>.cfg   the show output, UTF-8 without BOM, LF line endings, prompts and echoed commands removed
      - <OutputFolder>\backup_log.csv            hostname, collected_at (local time), result (ok / failed), detail

.PARAMETER InventoryCsv
    The comms-room inventory (Device42 export) with at least hostname, vendor and mgmt_ip columns (see docs/data-format.md).

.PARAMETER OutputFolder
    Where configs\ and backup_log.csv are written (default .\data).

.PARAMETER Credential
    The SSH credential. Asked with Get-Credential when not given.

.PARAMETER Hostname
    Only these devices (wildcards allowed), for example 'ZAZ-*'.

.PARAMETER TimeoutSeconds
    How long to wait for the output of one device (default 90).

.PARAMETER AcceptNewHostKey
    Trust the SSH host key of devices not yet in the Posh-SSH trusted hosts.

.EXAMPLE
    .\scripts\Get-NetworkConfigBackup.ps1 -InventoryCsv .\data\inventory.csv -OutputFolder .\data

.EXAMPLE
    .\scripts\Get-NetworkConfigBackup.ps1 -InventoryCsv .\data\inventory.csv -Hostname 'ZAZ-*' -AcceptNewHostKey
    Only the Zaragoza devices, trusting host keys seen for the first time.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $InventoryCsv,
    [string] $OutputFolder = '.\data',
    [System.Management.Automation.PSCredential] $Credential,
    [string[]] $Hostname = @('*'),
    [int] $TimeoutSeconds = 90,
    [switch] $AcceptNewHostKey
)

$ErrorActionPreference = 'Stop'
Import-Module Posh-SSH
if (-not $Credential) { $Credential = Get-Credential -Message 'Read-only SSH account for the network devices' }
$configs = Join-Path $OutputFolder 'configs'
New-Item -ItemType Directory -Force -Path $configs | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding $false

function Get-Platform([string] $Vendor, [string] $Model) {
    $v = "$Vendor $Model".ToLower()
    if ($v -match 'forti') { return 'fortios' }
    if ($v -match 'aruba|procurve|^hp|\bhpe?\b') { return 'aruba' }
    return 'ios'
}

function Read-Until-Quiet($Stream, [int] $Seconds) {
    # Reads the shell stream until nothing new arrives for 3 seconds, or the timeout.
    $sb = New-Object System.Text.StringBuilder
    $deadline = (Get-Date).AddSeconds($Seconds)
    $quiet = 0
    while ((Get-Date) -lt $deadline -and $quiet -lt 6) {
        Start-Sleep -Milliseconds 500
        $chunk = $Stream.Read()
        if ($chunk) { [void] $sb.Append($chunk); $quiet = 0 } else { $quiet++ }
    }
    return $sb.ToString()
}

function Clear-Output([string] $Text, [string] $Platform) {
    $t = $Text -replace "`r", '' -replace '\x1b\[[0-9;?]*[A-Za-z]', '' -replace '\x1bE', "`n"
    $lines = $t -split "`n"
    switch ($Platform) {
        'ios' {
            $start = [array]::FindIndex($lines, [Predicate[string]] { param($l) $l -match '^(Building configuration|Current configuration)' })
            $end = [array]::FindLastIndex($lines, [Predicate[string]] { param($l) $l -eq 'end' })
        }
        'aruba' {
            $start = [array]::FindIndex($lines, [Predicate[string]] { param($l) $l -match '^; \S+ Configuration Editor;' })
            $end = [array]::FindLastIndex($lines, [Predicate[string]] { param($l) $l -match '^\S+[#>] ?$' }) - 1
        }
        default {
            $start = [array]::FindIndex($lines, [Predicate[string]] { param($l) $l -match '^#config-version=' })
            $end = $lines.Count - 1
        }
    }
    if ($start -lt 0 -or $end -lt $start) { return $null }
    return (($lines[$start..$end] | ForEach-Object { $_.TrimEnd() }) -join "`n").TrimEnd() + "`n"
}

$devices = Import-Csv -Path $InventoryCsv | Where-Object {
    $h = $_.hostname; $_.mgmt_ip -and ($Hostname | Where-Object { $h -like $_ })
}
$log = foreach ($d in $devices) {
    $platform = Get-Platform $d.vendor $d.model
    $session = $null
    $result, $detail = 'failed', ''
    try {
        $params = @{ ComputerName = $d.mgmt_ip; Credential = $Credential; ConnectionTimeout = 30; ErrorAction = 'Stop' }
        if ($AcceptNewHostKey) { $params.AcceptKey = $true }
        $session = New-SSHSession @params
        if ($platform -eq 'fortios') {
            $out = Invoke-SSHCommand -SessionId $session.SessionId -Command 'show full-configuration' -TimeOut $TimeoutSeconds
            $raw = ($out.Output -join "`n")
        } else {
            $stream = New-SSHShellStream -SessionId $session.SessionId
            $hello = Read-Until-Quiet $stream 15
            if ($hello -match 'Press any key to continue') { $stream.WriteLine(''); [void] (Read-Until-Quiet $stream 10) }
            $stream.WriteLine($(if ($platform -eq 'aruba') { 'no page' } else { 'terminal length 0' }))
            [void] (Read-Until-Quiet $stream 10)
            $stream.WriteLine('show running-config')
            $raw = Read-Until-Quiet $stream $TimeoutSeconds
            $stream.Dispose()
        }
        $text = Clear-Output $raw $platform
        if (-not $text) { throw 'no configuration in the output (prompt, privilege or paging?)' }
        [System.IO.File]::WriteAllText((Join-Path $configs "$($d.hostname).cfg"), $text, $utf8)
        $result, $detail = 'ok', "$platform, $($text.Length) characters"
    } catch {
        $detail = $_.Exception.Message
    } finally {
        if ($session) { [void] (Remove-SSHSession -SessionId $session.SessionId) }
    }
    Write-Host ('{0,-14} {1,-7} {2}' -f $d.hostname, $result, $detail)
    [pscustomobject]@{ hostname = $d.hostname; collected_at = (Get-Date).ToString('yyyy-MM-dd HH:mm'); result = $result; detail = $detail }
}

$logPath = Join-Path $OutputFolder 'backup_log.csv'
$csv = (@($log) | ConvertTo-Csv -NoTypeInformation) -join "`n"
[System.IO.File]::WriteAllText($logPath, $csv + "`n", $utf8)
Write-Host "Done: $(@($log | Where-Object result -eq 'ok').Count) of $(@($log).Count) devices -> $configs"
