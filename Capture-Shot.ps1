<#
.SYNOPSIS
    Takes a REAL screenshot of this console showing a capture log.
    Usage (run in a VISIBLE console window):
      powershell -NoProfile -ExecutionPolicy Bypass -File Capture-Shot.ps1 -LogFile captures/capture-02-detection.log -OutPng docs/shot-detection.png
      powershell -NoProfile -ExecutionPolicy Bypass -File Capture-Shot.ps1 -LogFile captures/capture-01-baseline.log -OutPng docs/shot-baseline.png
    The PNG is a genuine BitBlt screenshot of your terminal - for README/Pages.
#>
param(
    [string]$LogFile = "captures/capture-02-detection.log",
    [string]$OutPng = "docs/shot-detection.png"
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$logPath = Join-Path $root $LogFile
$pngPath = Join-Path $root $OutPng
if (!(Test-Path $logPath)) { throw "Log not found: $logPath" }

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Shot {
    [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern IntPtr GetDC(IntPtr h);
    [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr h, IntPtr dc);
    [DllImport("gdi32.dll")] public static extern IntPtr CreateCompatibleDC(IntPtr dc);
    [DllImport("gdi32.dll")] public static extern IntPtr CreateCompatibleBitmap(IntPtr dc, int w, int h);
    [DllImport("gdi32.dll")] public static extern IntPtr SelectObject(IntPtr dc, IntPtr o);
    [DllImport("gdi32.dll")] public static extern bool BitBlt(IntPtr dst, int x, int y, int w, int h, IntPtr src, int sx, int sy, int rop);
    [DllImport("gdi32.dll")] public static extern bool DeleteDC(IntPtr dc);
    [DllImport("gdi32.dll")] public static extern bool DeleteObject(IntPtr o);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L; public int T; public int R; public int B; }
}
"@ -ErrorAction Stop
Add-Type -AssemblyName System.Drawing -ErrorAction Stop

function Paint-Line([string]$ln) {
    if ($ln -match '^\[High\]') { Write-Host $ln -ForegroundColor Red }
    elseif ($ln -match '^\[Info') { Write-Host $ln -ForegroundColor Gray }
    elseif ($ln -match '^-----') { Write-Host $ln -ForegroundColor Cyan }
    elseif ($ln -match '^\[\*\]') { Write-Host $ln -ForegroundColor White }
    elseif ($ln -match 'VERDICT: CRITICAL') { Write-Host $ln -ForegroundColor Red -BackgroundColor Black }
    elseif ($ln -match 'VERDICT: CLEAN') { Write-Host $ln -ForegroundColor Green }
    elseif ($ln -match 'BDB-Guardian ::') { Write-Host $ln -ForegroundColor Cyan }
    else { Write-Host $ln }
}

$Host.UI.RawUI.WindowTitle = "BDB-Guardian - REAL TERMINAL CAPTURE"
try {
    $ui = $Host.UI.RawUI
    $ws = $ui.WindowSize; $ws.Width = 125; $ws.Height = 42; $ui.WindowSize = $ws
    $bs = $ui.BufferSize; $bs.Width = 125; $bs.Height = 300; $ui.BufferSize = $bs
} catch {}
Clear-Host
Write-Host "BDB-Guardian - REAL TERMINAL CAPTURE ($LogFile)" -ForegroundColor Cyan
Write-Host ""
Get-Content $logPath | ForEach-Object { Paint-Line $_ }
Write-Host ""
Write-Host "[shot] capturing this console window in 2 s - do not cover it..." -ForegroundColor Yellow

$hwnd = [Shot]::GetConsoleWindow()
[Shot]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Seconds 2
$r = New-Object Shot+RECT
[Shot]::GetWindowRect($hwnd, [ref]$r) | Out-Null
$w = $r.R - $r.L; $h = $r.B - $r.T
$src = [Shot]::GetDC([IntPtr]::Zero)
$dst = [Shot]::CreateCompatibleDC($src)
$bmp = [Shot]::CreateCompatibleBitmap($src, $w, $h)
$old = [Shot]::SelectObject($dst, $bmp)
[Shot]::BitBlt($dst, 0, 0, $w, $h, $src, $r.L, $r.T, 0x00CC0020) | Out-Null
[Shot]::SelectObject($dst, $old) | Out-Null
[Shot]::DeleteDC($dst) | Out-Null
[Shot]::ReleaseDC([IntPtr]::Zero, $src) | Out-Null
$img = [System.Drawing.Bitmap]::FromHbitmap($bmp)
[Shot]::DeleteObject($bmp) | Out-Null
$img.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png)
$img.Dispose()
Write-Host ("[shot] saved REAL screenshot: {0} ({1}x{2})" -f $pngPath, $w, $h) -ForegroundColor Green
