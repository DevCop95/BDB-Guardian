# Launches the simulator via WMI (survives the end of the launching session).
# Usage: powershell -File launch-sim.ps1 [-DurationSec 300]  -> returns PID immediately.
param([int]$DurationSec = 150)
$dir = $PSScriptRoot
$sim = Join-Path $dir 'Invoke-BDBSimulation.ps1'
$status = Join-Path $dir 'captures\sim-status.txt'
$clog = Join-Path $dir 'captures\capture-02-sim.log'
$cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -File "' + $sim + '" -DurationSec ' + $DurationSec + ' -FileSizeMB 256 -StatusPath "' + $status + '" -ConsoleLogPath "' + $clog + '"'
$r = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $cmd
Write-Output ('WMI Create rc=' + $r.ReturnValue + ' PID=' + $r.ProcessId)
