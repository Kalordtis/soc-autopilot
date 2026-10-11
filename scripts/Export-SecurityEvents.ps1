<#
.SYNOPSIS
    Export Windows Security log events into the JSON format SOC Autopilot ingests.

.DESCRIPTION
    Pulls logon (4624/4625), account creation (4720) and group-membership (4728/4732)
    events, flattens the XML EventData into named fields, and writes windows_events.json.
    Run from an elevated PowerShell prompt (reading the Security log needs admin).

.EXAMPLE
    .\Export-SecurityEvents.ps1 -Hours 24 -OutFile ..\data\mine\windows_events.json
    python -m socpilot run --data data/mine --out out-mine
#>
[CmdletBinding()]
param(
    [int]$Hours = 24,
    [string]$OutFile = ".\windows_events.json",
    [int]$MaxEvents = 20000
)

$ids = 4624, 4625, 4720, 4728, 4732
$since = (Get-Date).AddHours(-$Hours)
Write-Verbose "Reading Security log since $since"

try {
    $raw = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $ids; StartTime = $since } `
        -MaxEvents $MaxEvents -ErrorAction Stop
} catch [System.Exception] {
    if ($_.Exception.Message -match 'No events were found') { $raw = @() }
    else { throw "Could not read the Security log (run as Administrator?): $($_.Exception.Message)" }
}

$out = foreach ($e in $raw) {
    $xml = [xml]$e.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

    $rec = [ordered]@{
        TimeCreated     = $e.TimeCreated.ToUniversalTime().ToString('o')
        EventID         = $e.Id
        Computer        = $e.MachineName
        TargetUserName  = $data['TargetUserName']
        SubjectUserName = $data['SubjectUserName']
        IpAddress       = $data['IpAddress']
        LogonType       = if ($data['LogonType']) { [int]$data['LogonType'] } else { $null }
        WorkstationName = $data['WorkstationName']
    }
    if ($e.Id -in 4728, 4732) {
        # For group changes, TargetUserName is the GROUP and MemberName is a DN/SID
        $rec.TargetGroup = $data['TargetUserName']
        $member = $data['MemberName']
        if (-not $member -or $member -eq '-') {
            try { $member = (New-Object System.Security.Principal.SecurityIdentifier($data['MemberSid'])).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1] }
            catch { $member = $data['MemberSid'] }
        } elseif ($member -match '^CN=([^,]+)') { $member = $Matches[1] }
        $rec.MemberName = $member
    }
    [pscustomobject]$rec
}

$out | Sort-Object TimeCreated | ConvertTo-Json -Depth 3 | Set-Content -Path $OutFile -Encoding UTF8
Write-Host "Exported $(@($out).Count) events to $OutFile"
