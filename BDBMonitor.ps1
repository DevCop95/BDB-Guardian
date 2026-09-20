<#
.SYNOPSIS
    BDB-Guardian - Defensive monitor against the BigDiskBuster technique
    (Denial of Service against Windows Defender via disk exhaustion).

.DESCRIPTION
    Detects the 3 IoCs that the BigDiskBuster PoC (MSNightmare) relies on:
      1. Open handle to C:\Windows\System32\MRT.exe (Restart Manager, instant).
      2. Open handle to the C: volume (parallel handle scan; also backs up IoC 1).
      3. Giant hidden file in %TEMP% (directory scan).
    Native probing runs in Invoke-VolumeScan.ps1, a sacrificial child
    process: this monitor is 100% managed code and survives native crashes.
    Analysis of the original PoC: https://github.com/MSNightmare/BigDiskBuster (MIT, by MSNightmare)

.NOTES
    Read-only: it never modifies the system. Requires Admin to enumerate
    handles of protected/SYSTEM processes.
#>
param(
    [int]$TempSizeThresholdMB = 1024,
    [int]$MaxScanSeconds = 100,
    [string]$LogDir = "$PSScriptRoot\captures",
    [string]$ConsoleLogPath = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$script:logLines = New-Object System.Collections.Generic.List[string]
function Out-Log {
    param([string]$Msg = "", [string]$Color = "")
    if ($Color) { Write-Host $Msg -ForegroundColor $Color } else { Write-Host $Msg }
    $script:logLines.Add($Msg)
}

# ---------------------------------------------------------------- scan
# NOTE: this monitor is 100% managed code. ALL native probing (Restart
# Manager, volume handle enumeration) runs in Invoke-VolumeScan.ps1, a
# sacrificial child process. Native crashes can never kill this monitor.
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }

Out-Log "================================================================" "Cyan"
Out-Log " BDB-Guardian :: scan $stamp" "Cyan"
Out-Log "================================================================" "Cyan"
Out-Log ""

$volumeDevice = ''
$mrtPath = 'C:\Windows\System32\MRT.exe'
Out-Log "[*] MRT: $mrtPath"
Out-Log "[*] Hidden-temp threshold: $TempSizeThresholdMB MB | time-box: $MaxScanSeconds s"
Out-Log ""

$ownPid = $PID
# Processes that LEGITIMATELY hold volume handles (OS services).
# They must also live under C:\Windows* or Defender dirs.
$whiteVolumeNames = @('System', 'svchost', 'SearchIndexer', 'dllhost', 'SearchHost',
    'WmiPrvSE', 'TiWorker', 'TrustedInstaller', 'taskhostw', 'sihost',
    'MsMpEng', 'NisSrv', 'SecurityHealthService', 'MpDefenderCoreService', 'MsMpEngCP')
# NOBODY keeps MRT.exe persistently open; only updater/defender contexts.
$whiteMrtNames = @('MsMpEng', 'NisSrv', 'MpDefenderCoreService', 'MsMpEngCP',
    'TrustedInstaller', 'TiWorker', 'System')
$findings = New-Object System.Collections.Generic.List[object]
$seen = @{}

function Add-Finding {
    param($Type, [int]$Pid_, $Hval, $ObjName)
    $key = "$Type|$Pid_"
    if ($seen.ContainsKey($key)) { return }
    $seen[$key] = $true
    if ($Pid_ -eq $ownPid) { return }
    $pname = '?'; $ppath = 'N/A (protected)'; $whitelisted = $false; $reason = ''
    try {
        $p = Get-Process -Id $Pid_ -ErrorAction Stop
        $pname = $p.ProcessName
        try { if ($p.Path) { $ppath = $p.Path } } catch {}
        $inOS = ($ppath -like 'C:\Windows*') -or ($ppath -like 'C:\Program Files\Windows Defender*') -or ($ppath -like 'C:\ProgramData\Microsoft\Windows Defender*')
        if ($Pid_ -eq 4) { $whitelisted = $true; $reason = 'PID 4 (System)' }
        elseif ($Type -eq 'VOLUME_HANDLE' -and ($whiteVolumeNames -contains $pname) -and $inOS) {
            $whitelisted = $true; $reason = 'OS service with legitimate volume handle'
        }
        elseif ($Type -eq 'MRT_LOCK' -and ($whiteMrtNames -contains $pname) -and $inOS) {
            $whitelisted = $true; $reason = 'updater/defender'
        }
        elseif ($Type -eq 'DEFENDER_DIR_HANDLE' -and $inOS -and
                (($whiteVolumeNames -contains $pname) -or ($whiteMrtNames -contains $pname))) {
            $whitelisted = $true; $reason = 'OS/defender binary'
        }
    } catch { $pname = '(exited?)' }
    if ($whitelisted) { $sev = 'Info' } elseif ($Type -eq 'DEFENDER_DIR_HANDLE') { $sev = 'Medium' } else { $sev = 'High' }
    $findings.Add([pscustomobject]@{
        Type = $Type; PID = $Pid_; Process = $pname; Path = $ppath
        Handle = $Hval; ObjectName = $ObjName; Severity = $sev
        Whitelisted = $whitelisted; Why = $reason
    }) | Out-Null
}

# IoC 1+2: MRT locks (Restart Manager, instant) + volume handles (scan),
# both via the ISOLATED worker. MRT findings carry handle 'RM'; the name
# scan provides real handle values as backup/cross-check.
Out-Log "[1/3]+[2/3] Native probes in isolated worker (RM + handles)..." "Yellow"
$sw2 = [Diagnostics.Stopwatch]::StartNew()
$mrtPids = @()
$rawHandles = @()
$volScanned = 0; $volTotal = 0; $volSeconds = 0
$worker = Join-Path $PSScriptRoot 'Invoke-VolumeScan.ps1'
$wjson = Join-Path $LogDir "volscan-$stamp.json"
if (Test-Path $worker) {
    $wargs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$worker,'-MaxSeconds',"$MaxScanSeconds",'-MrtPath',$mrtPath,'-OutJson',$wjson)
    try {
        $wp = Start-Process powershell -ArgumentList $wargs -PassThru -WindowStyle Hidden -ErrorAction Stop
        $wok = $wp.WaitForExit(($MaxScanSeconds + 60) * 1000)
        if (-not $wok) { try { $wp.Kill() } catch {}; Out-Log "      worker TIMEOUT, killed" "DarkYellow" }
        elseif ($wp.ExitCode -ne 0) { Out-Log ("      worker exited code {0}" -f $wp.ExitCode) "DarkYellow" }
        if (Test-Path $wjson) {
            $wj = Get-Content -Raw $wjson | ConvertFrom-Json
            $volumeDevice = $wj.volumeDevice
            if ($wj.mrtPids -ne $null) { $mrtPids = @($wj.mrtPids) }
            if ($wj.matches -ne $null) { $rawHandles = @($wj.matches) }
            $volScanned = $wj.scanned; $volTotal = $wj.total; $volSeconds = $wj.seconds
            Out-Log ("      MRT holders: {0} | volume PIDs: {1}/{2} in {3:N1} s | matches: {4}" -f $mrtPids.Count, $volScanned, $volTotal, $volSeconds, $rawHandles.Count)
        } else {
            Out-Log "      worker produced no output (assumed crashed) - continuing with temp scan only" "DarkYellow"
        }
    } catch { Out-Log ("      worker launch failed: " + $_.Exception.Message) "DarkYellow" }
} else {
    Out-Log "      worker script missing - continuing with temp scan only" "DarkYellow"
}
$sw2.Stop()
Out-Log "[*] Volume C: -> $volumeDevice"
foreach ($mp in $mrtPids) { Add-Finding 'MRT_LOCK' ([int]$mp) 'RM' $mrtPath }
foreach ($line in $rawHandles) {
    if ([string]::IsNullOrEmpty($line)) { continue }
    $parts = $line -split '\|', 3
    if ($parts.Count -lt 3) { continue }
    $t = $null
    if ($parts[2] -like '*\MRT.exe') { $t = 'MRT_LOCK' }
    elseif ($parts[2].TrimEnd('\') -ieq $volumeDevice) { $t = 'VOLUME_HANDLE' }
    elseif ($parts[2] -like '*Microsoft\Windows Defender*') { $t = 'DEFENDER_DIR_HANDLE' }
    else { continue }
    Add-Finding $t ([int]$parts[0]) $parts[1] $parts[2]
}

Out-Log ""
Out-Log "----- HANDLE FINDINGS -----" "Yellow"
if ($findings.Count -eq 0) { Out-Log "(none)" }
foreach ($f in $findings) {
    if ($f.Severity -eq 'High') { $c = 'Red' }
    elseif ($f.Severity -eq 'Medium') { $c = 'DarkYellow' } else { $c = 'Gray' }
    if ($f.Whitelisted) { $tag = "[Info/whitelist: $($f.Why)]" } else { $tag = "[$($f.Severity)]" }
    Out-Log ("{0} {1} :: PID {2} ({3}) handle {4}" -f $tag, $f.Type, $f.PID, $f.Process, $f.Handle) $c
    Out-Log ("      Path: {0}" -f $f.Path)
    Out-Log ("      Obj : {0}" -f $f.ObjectName)
}
Out-Log ""

# IoC 3: buster-files in TEMP
$threshold = [long]$TempSizeThresholdMB * 1MB
$guidRe = '^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$'
$tempHits = @()
foreach ($td in @($env:TEMP, 'C:\Windows\Temp')) {
    if (!(Test-Path $td)) { continue }
    Get-ChildItem -Path $td -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        if ((($_.Attributes -band [IO.FileAttributes]::Hidden) -ne 0) -and ($_.Length -ge $threshold)) {
            $tempHits += [pscustomobject]@{
                Path = $_.FullName; SizeMB = [math]::Round($_.Length / 1MB, 1)
                Hidden = $true; GuidLike = ($_.Name -match $guidRe)
                LastWrite = $_.LastWriteTime.ToString('s')
            }
        }
    }
}
Out-Log "----- GIANT HIDDEN FILES IN TEMP -----" "Yellow"
if ($tempHits.Count -eq 0) { Out-Log "(none >= $TempSizeThresholdMB MB)" }
foreach ($t in $tempHits) {
    Out-Log ("[High] {0}  ({1} MB, GuidLike={2})" -f $t.Path, $t.SizeMB, $t.GuidLike) "Red"
}
Out-Log ""

# verdict.
# False-positive profile (documented):
#   MRT_LOCK alone (non-whitelisted) : very strong, ~nothing legit holds MRT open.
#   VOLUME_HANDLE alone              : WEAK (services hold it) -> never above MEDIUM.
#   buster-file alone                : medium (installers can look similar).
#   Same PID holding MRT+volume      : FP ~ 0 -> CRITICAL. This is the serious rule.
# NOTE: @() wrappers are mandatory - a single match has no .Count.
$suspH = @($findings | Where-Object { !$_.Whitelisted -and $_.Severity -eq 'High' })
$mrtHits = @($suspH | Where-Object { $_.Type -eq 'MRT_LOCK' })
$volHits = @($suspH | Where-Object { $_.Type -eq 'VOLUME_HANDLE' })
$hasMRT = ($mrtHits.Count -gt 0)
$hasVol = ($volHits.Count -gt 0)
$hasTmp = $tempHits.Count -gt 0
$mrtPids = @($mrtHits | ForEach-Object { $_.PID })
$volPids = @($volHits | ForEach-Object { $_.PID })
$samePid = @($mrtPids | Where-Object { $volPids -contains $_ })

if (($samePid.Count -gt 0) -and $hasTmp) { $verdict = 'CRITICAL'; $vmsg = ('Confirmed BigDiskBuster-like activity: PID {0} holds MRT+volume, buster-file present' -f ($samePid -join ',')) }
elseif ($samePid.Count -gt 0)            { $verdict = 'CRITICAL'; $vmsg = ('BigDiskBuster handle pattern in PID {0} (MRT+volume)' -f ($samePid -join ',')) }
elseif ($hasMRT -and $hasVol)            { $verdict = 'CRITICAL'; $vmsg = 'MRT lock + volume handle (different PIDs)' }
elseif ($hasMRT)                         { $verdict = 'HIGH';     $vmsg = 'MRT.exe held open by non-system process' }
elseif ($hasTmp)                         { $verdict = 'MEDIUM';   $vmsg = 'Suspicious buster-file without correlated handles' }
elseif ($hasVol)                         { $verdict = 'MEDIUM';   $vmsg = 'Volume handle in non-whitelisted process (weak alone)' }
else                                     { $verdict = 'CLEAN';    $vmsg = 'No indicators' }
if ($verdict -eq 'CLEAN') { $vc = 'Green' } else { $vc = 'Red' }
Out-Log "================================================================" "Cyan"
Out-Log " VERDICT: $verdict - $vmsg" $vc
Out-Log "================================================================" "Cyan"

$result = [pscustomobject]@{
    timestamp = (Get-Date).ToString('s'); verdict = $verdict; detail = $vmsg
    volumeDevice = $volumeDevice; tempThresholdMB = $TempSizeThresholdMB
    scanSeconds = [math]::Round($sw2.Elapsed.TotalSeconds, 1)
    pidsScanned = $volScanned; pidsTotal = $volTotal; volScanSeconds = $volSeconds
    handleFindings = $findings.ToArray(); tempFiles = @($tempHits)
}
$jsonPath = Join-Path $LogDir "scan-$stamp.json"
$result | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding utf8
Out-Log "[*] JSON: $jsonPath"
if ($ConsoleLogPath) {
    $script:logLines | Out-File -FilePath $ConsoleLogPath -Encoding utf8
    Write-Host "[*] Console: $ConsoleLogPath" -ForegroundColor Gray
}
