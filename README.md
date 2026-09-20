# BDB-Guardian

![BDB-Guardian](docs/banner.png)

Defensive monitor for the **BigDiskBuster** technique (filling the disk so
Windows Defender updates fail).

Inspired by the analysis of [BigDiskBuster](https://github.com/MSNightmare/BigDiskBuster)
by [MSNightmare](https://github.com/MSNightmare) (MIT License).

**Evidence report:** https://devcop95.github.io/BDB-Guardian/ (the
[`index.html`](index.html) in this repo, served with Pages).

## Authors & evidence

| | Who | Role |
|---|---|---|
| <img src="https://github.com/DevCop95.png?s=96" width="96" alt="DevCop95"> | **[DevCop95](https://github.com/DevCop95)** | BDB-Guardian author (this repo) |
| <img src="https://github.com/MSNightmare.png?s=96" width="96" alt="MSNightmare"> | **[MSNightmare](https://github.com/MSNightmare)** | Original BigDiskBuster PoC (MIT) - credited inspiration and technique source |

## Proof: live detection

![Live detection](docs/capture-critical.png)

![Baseline](docs/capture-baseline.png)

Full transcripts + JSON verdicts: [`captures/`](captures/) and the
[evidence report](https://devcop95.github.io/BDB-Guardian/).

Terminal output during the live-detection run:

![Terminal during live detection](docs/shot-detection.png)

## MITRE ATT&CK

| Tactic | Technique | Procedure |
|---|---|---|
| Defense Evasion (TA0005) | [T1562.001 - Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) | Filling the disk so Defender platform/signature updates fail; holds `MRT.exe` and the `C:` volume open while the buster-file exists |

## Detection as code

Portable rules in [`detections/`](detections/) (convert with `sigma-cli`):

```bash
pip install sigma-cli
sigma check detections/bigdiskbuster-filecreate.yml
sigma convert -t splunk detections/bigdiskbuster-filecreate.yml
sigma convert -t kusto detections/bigdiskbuster-filecreate.yml   # Microsoft Sentinel
```

- `detections/bigdiskbuster-filecreate.yml` - Sigma (Sysmon FileCreate): GUID-braced buster-file in TEMP.
- `detections/mde-hunt.kql` - Microsoft Defender for Endpoint Advanced Hunting query for the same stage.
- Handle correlation (MRT.exe + volume held by one PID) is the part EDRs don't see - that's what `BDBMonitor.ps1` does.

## Reproduction (lab only)

Isolated Windows VM with snapshot. Never on production systems.

```powershell
# 1. Start the SAFE simulator (controlled 256 MB file, self-cleaning)
powershell -NoProfile -ExecutionPolicy Bypass -File launch-sim.ps1 -DurationSec 150
# 2. Run the monitor while IoCs are active
powershell -NoProfile -ExecutionPolicy Bypass -File BDBMonitor.ps1 -TempSizeThresholdMB 100
# Expected: VERDICT: CRITICAL - same PID holds MRT+volume, buster-file present
```

## How BigDiskBuster works (threat model)

The PoC watches the whole `C:` volume for Defender update directories
(`ProgramData\Microsoft\Windows Defender\Platform\...` and
`...\Definition Updates\{GUID}`), locks `MRT.exe`, and the moment an update
starts it creates hidden files in `%TEMP%` with `AllocationSize` = all free
disk space (`FILE_DELETE_ON_CLOSE`), so the update fails with disk-full. When
the update gives up, it frees everything and goes back to sleep.

## What BDB-Guardian detects (3 IoCs)

| # | IoC | Method | False-positive profile |
|---|-----|--------|------------------------|
| 1 | Handle open on `C:\Windows\System32\MRT.exe` | Restart Manager (instant, exact) + name-scan backup | Very strong: nothing legit holds MRT open persistently |
| 2 | Handle open on the `C:` volume (`\Device\HarddiskVolumeN`) | Parallel native handle scan | WEAK alone (services hold it) -> OS-service whitelist, never above MEDIUM alone |
| 3 | Giant hidden file in `%TEMP%` (GUID-like name) | Directory scan | Medium (installers can look similar) |

**Verdict engine (same-PID correlation):** `MRT + volume` held by the **same
non-whitelisted PID** = `CRITICAL` (FP ~ 0); with a buster-file present it is
reported as confirmed BigDiskBuster-like activity.

## How it's built

```
BDBMonitor.ps1          plain managed code, no native calls here
  +-- Invoke-VolumeScan.ps1   child process holding ALL the native code
  |     +-- bdb-csharp.ps1    RestartManager / NtQuerySystemInformation /
  |                           DuplicateHandle / NtQueryObject (inline C#)
  +-- verdict + JSON report
```

What bit us along the way (documented so the next person doesn't repeat it):

- `RmGetList` writes **`RM_PROCESS_INFO`** (~668 bytes/entry), not
  `RM_UNIQUE_PROCESS`. Passing the small struct overflows the heap
  (`0xC0000374`) - this was our crash. Every reference implementation
  (MSDN, Roslyn `FileLockCheck`, ironman) uses `RM_PROCESS_INFO` + retry loop.
- Name queries skip non-disk handles (`GetFileType != DISK`, pipes hang
  `NtQueryObject`), per-PID timeouts as backstop. Bonus: full scan went from
  ~45 s to ~6-14 s.
- If the worker ever dies, the monitor survives and reports degraded mode.

Stability: holds up across repeat runs with live IoCs, no `Application Error`
events since the struct fix, consecutive `CRITICAL` verdicts (see `captures/stability-run*.log`).

## Files

- `BDBMonitor.ps1` - the monitor. `-TempSizeThresholdMB` (def. 1024),
  `-MaxScanSeconds` (def. 70), `-LogDir`, `-ConsoleLogPath`.
- `Invoke-VolumeScan.ps1` + `bdb-csharp.ps1` - sacrificial scan worker.
- `Invoke-BDBSimulation.ps1` - SAFE IoC simulator for testing (controlled
  256 MB file, releases everything, verifies cleanup). Never fills the disk.
- `launch-sim.ps1` - launches the simulator via WMI (detached).
- `captures/` - evidence logs (console transcripts + JSON reports).
- `docs/` - banners rendered from real outputs (`render-banners.py`).
- `index.html` - standalone evidence report (GitHub Pages ready).

## Tested (Windows 11, admin PowerShell 5.1)

- Baseline (idle system): `CLEAN`, legit volume holders correctly whitelisted.
- Live simulation (MRT + volume + 256 MB buster-file): `CRITICAL -
  Confirmed BigDiskBuster-like activity: PID xxxx holds MRT+volume,
  buster-file present` (repeated, stable).
- Post-simulation: `CLEAN`, verified no leftovers.

Requires Administrator (to enumerate handles of SYSTEM/protected processes).
