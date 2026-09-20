# Builds index.html embedding all captures (console logs + JSON verdicts).
$dir = $PSScriptRoot
$cap = Join-Path $dir 'captures'
function EscHtml($s) {
    if ($s -eq $null) { return '' }
    $s = $s -replace '&', '&amp;'
    $s = $s -replace '<', '&lt;'
    $s = $s -replace '>', '&gt;'
    return $s
}
function LogBlock($name, $title, $verdict) {
    $p = Join-Path $cap $name
    $body = if (Test-Path $p) { EscHtml((Get-Content -Raw $p)) } else { '(missing)' }
    $cls = if ($verdict -eq 'CRITICAL') { 'crit' } elseif ($verdict -eq 'CLEAN') { 'clean' } else { 'mid' }
    return "<h2>$title</h2><div class=`"verdict $cls`">$verdict</div><pre>$body</pre>"
}
function JsonVerdict($pattern) {
    $f = Join-Path $cap $pattern
    if (!(Test-Path $f)) { return '(missing)' }
    $j = Get-Content -Raw $f | ConvertFrom-Json
    return ('verdict={0} detail={1} pids={2}/{3} scanSeconds={4}' -f $j.verdict, $j.detail, $j.pidsScanned, $j.pidsTotal, $j.scanSeconds)
}
$jbase = JsonVerdict('scan-20260919-215822.json')
$jdet = JsonVerdict('scan-20260919-223650.json')
$jpost = JsonVerdict('scan-20260919-222744.json')
$b1 = LogBlock 'capture-01-baseline.log' 'Capture 1 - Baseline (idle system)' 'CLEAN'
$b2s = LogBlock 'capture-02-sim.log' 'Capture 2a - Simulator transcript (IoCs active)' 'INFO'
$b2 = LogBlock 'capture-02-detection.log' 'Capture 2b - Detection (live IoCs)' 'CRITICAL'
$b3 = LogBlock 'capture-03-post.log' 'Capture 3 - Post-simulation (auto-cleaned)' 'CLEAN'
$html = @"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>BDB-Guardian - Detection Report</title>
<style>
body{font-family:Consolas,monospace;background:#0d1117;color:#c9d1d9;margin:2em}
h1{color:#58a6ff}h2{color:#79c0ff;margin-top:2em}
pre{background:#161b22;border:1px solid #30363d;padding:1em;overflow-x:auto;white-space:pre-wrap}
.verdict{display:inline-block;padding:.2em .8em;border-radius:6px;font-weight:bold;margin:.5em 0}
.crit{background:#5a0f0f;color:#ff9d9d}.clean{background:#0f3d1f;color:#7ee2a0}.mid{background:#3d2f0f;color:#e2c87e}.INFO{background:#222;color:#ccc}
table{border-collapse:collapse;margin:1em 0}td,th{border:1px solid #30363d;padding:.4em .8em}th{background:#161b22}
.note{color:#8b949e}
</style></head><body>
<h1>BDB-Guardian - Detection Report</h1>
<p class="note">Defensive monitor vs BigDiskBuster technique (Defender-update DoS via disk exhaustion).
Inspired by <a href="https://github.com/MSNightmare/BigDiskBuster">MSNightmare/BigDiskBuster</a> (MIT).
Tested on Windows 11, admin PowerShell 5.1. Simulator used a controlled 256 MB file - the disk was never filled.</p>
<h2>Verdict summary (from JSON reports)</h2>
<table><tr><th>Phase</th><th>JSON summary</th></tr>
<tr><td>Baseline</td><td>$jbase</td></tr>
<tr><td>Detection</td><td>$jdet</td></tr>
<tr><td>Post</td><td>$jpost</td></tr></table>
$b1
$b2s
$b2
$b3
<h2>Method notes</h2>
<ul>
<li>MRT/volume holders: parallel native handle scan (NtQuerySystemInformation + DuplicateHandle + NtQueryObject) in a sacrificial worker process; monitor itself is 100% managed.</li>
<li>Same-PID correlation (MRT+volume in one non-whitelisted process) = CRITICAL, FP ~ 0. Lone volume handle never exceeds MEDIUM.</li>
<li>Restart Manager was evaluated and removed: its array marshaling intermittently corrupted the heap (0xC0000374); the name scan already finds MRT holders.</li>
</ul>
</body></html>
"@
$html | Out-File -FilePath (Join-Path $dir 'index.html') -Encoding utf8
Write-Output 'index.html written'
