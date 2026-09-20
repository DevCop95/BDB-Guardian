# BDB-Guardian native worker (sacrificial child process).
# ALL native code lives here: volume device resolution, Restart Manager MRT
# query (correct RM_PROCESS_INFO marshaling), and the parallel handle scan
# (which also finds MRT/volume holders by name as backup).
# If native enumeration ever crashes, only this worker dies - the monitor
# (100% managed) always survives and reports degraded mode honestly.
# Output: JSON file with volumeDevice + mrtPids + matches + coverage.
param([int]$MaxSeconds = 70, [string]$MrtPath = 'C:\Windows\System32\MRT.exe', [string]$OutJson = '')
$ErrorActionPreference = 'SilentlyContinue'
. (Join-Path $PSScriptRoot 'bdb-csharp.ps1')
$sw = [Diagnostics.Stopwatch]::StartNew()
$dev = [BdbHandleScan]::GetDevicePath('C:')
$mrt = @([BdbHandleScan]::RmWhoHas($MrtPath))
$r = [BdbHandleScan]::ScanVolumeHandles($MaxSeconds, $dev)
$sw.Stop()
$o = [pscustomobject]@{
    volumeDevice = $dev
    mrtPids = @($mrt)
    matches = @($r)
    scanned = [BdbHandleScan]::ScannedPids
    total = [BdbHandleScan]::TotalPids
    seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
}
$o | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutJson -Encoding utf8
