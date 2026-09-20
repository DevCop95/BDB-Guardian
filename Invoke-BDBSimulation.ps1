<#
.SYNOPSIS
    SAFE simulator of BigDiskBuster IoCs (to test BDBMonitor).

.DESCRIPTION
    Reproduces the 3 indicators WITHOUT danger:
      1. Opens MRT.exe for reading (like the PoC) and holds it.
      2. Opens a handle to the \\.\C: volume and holds it (requires admin).
      3. Creates a HIDDEN file of CONTROLLED size (def. 256 MB, NOT the whole
         disk) with a GUID name in %TEMP%.
    Writes its state to a file (StatusPath) after each step, so the IoC state
    stays verifiable even if the process dies.
    On exit it releases EVERYTHING and deletes the file. Verifies cleanup.
#>
param(
    [int]$DurationSec = 150,
    [int]$FileSizeMB = 256,
    [string]$StatusPath = "",
    [string]$ConsoleLogPath = ""
)
$ErrorActionPreference = 'Stop'
if ($StatusPath -eq '') { $StatusPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'captures\sim-status.txt'
}
$lines = New-Object System.Collections.Generic.List[string]
function S-Log {
    param([string]$M)
    Write-Host $M
    $lines.Add($M)
    try { Add-Content -Path $StatusPath -Value ((Get-Date).ToString('HH:mm:ss') + ' ' + $M) -Encoding utf8 } catch {}
}

$mrt = $null; $vol = $null; $tmp = $null
try {
    if (Test-Path $StatusPath) { Remove-Item $StatusPath -Force }
    S-Log '=== BigDiskBuster IoC simulator (SAFE) ==='
    S-Log ('Simulator PID: {0}' -f $PID)
    S-Log ('Duration: {0}s | Controlled file: {1} MB (disk is NOT filled)' -f $DurationSec, $FileSizeMB)

    try {
        $mrt = [IO.File]::Open('C:\Windows\System32\MRT.exe', 'Open', 'Read', 'Read')
        S-Log '[1/3] IoC MRT_LOCK ACTIVE: handle open on MRT.exe'
    } catch { S-Log ('[1/3] IoC MRT_LOCK FAILED: ' + $_.Exception.GetType().Name + ': ' + $_.Exception.Message) }

    try {
        $vol = New-Object IO.FileStream('\\.\C:', 'Open', 'Read', 'ReadWrite')
        S-Log '[2/3] IoC VOLUME_HANDLE ACTIVE: handle open on \\.\C:'
    } catch { S-Log ('[2/3] IoC VOLUME_HANDLE FAILED: ' + $_.Exception.GetType().Name + ': ' + $_.Exception.Message) }

    try {
        $guid = [guid]::NewGuid().ToString('B')
        $tmp = Join-Path $env:TEMP $guid
        $fs = [IO.File]::Create($tmp)
        $fs.SetLength([long]$FileSizeMB * 1MB)
        $fs.Close(); $fs.Dispose()
        Start-Sleep -Milliseconds 500
        [IO.File]::SetAttributes($tmp, ([IO.File]::GetAttributes($tmp) -bor [IO.FileAttributes]::Hidden))
        $mb = [math]::Round((Get-Item $tmp -Force).Length / 1MB, 1)
        S-Log ('[3/3] IoC BUSTER-FILE ACTIVE: ' + $tmp + ' (' + $mb + ' MB, hidden)')
    } catch { S-Log ('[3/3] IoC BUSTER-FILE FAILED: ' + $_.Exception.GetType().Name + ': ' + $_.Exception.Message) }

    S-Log 'Detection window: run BDBMonitor.ps1 NOW.'
    $t0 = Get-Date
    while (((Get-Date) - $t0).TotalSeconds -lt $DurationSec) {
        $left = $DurationSec - [int]((Get-Date) - $t0).TotalSeconds
        try { Set-Content -Path ($StatusPath + '.hb') -Value ((Get-Date).ToString('HH:mm:ss') + ' alive, ' + $left + 's left') -Encoding utf8 } catch {}
        Start-Sleep -Seconds 5
    }
} finally {
    S-Log 'Releasing IoCs...'
    if ($mrt) { try { $mrt.Close(); $mrt.Dispose() } catch {}; S-Log '- MRT.exe handle closed' }
    if ($vol) { try { $vol.Close(); $vol.Dispose() } catch {}; S-Log '- volume handle closed' }
    if ($tmp -ne $null -and (Test-Path $tmp)) {
        try { [IO.File]::SetAttributes($tmp, ([IO.File]::GetAttributes($tmp) -band (-bnot [IO.FileAttributes]::Hidden))) } catch {}
        Remove-Item $tmp -Force
        S-Log '- buster-file deleted'
    }
    $left = @(Get-ChildItem $env:TEMP -File -Force -ErrorAction SilentlyContinue |
        Where-Object { ($_.Attributes -band [IO.FileAttributes]::Hidden) -and ($_.Length -ge 50MB) })
    if ($left.Count -eq 0) { S-Log '[OK] Cleanup verified: no hidden files >=50MB left in TEMP.' }
    else { S-Log ('[WARNING] Leftovers: ' + ($left.FullName -join ', ')) }
    if ($ConsoleLogPath -ne '') { $lines | Out-File -FilePath $ConsoleLogPath -Encoding utf8 }
}
