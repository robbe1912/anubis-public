# Anubis self-deploy script — stops daemon, swaps binaries, restarts.
# Run from separate terminal or via Start-Process so it survives daemon restart.
param([string]$SourceDir = "E:\GitRepos\groundwire\packages\daemon-rs\target\release", [string]$DestDir = "$env:LOCALAPPDATA\anubis")
$ErrorActionPreference = "Stop"
function W($m){Write-Host "[deploy] $m" -ForegroundColor Cyan}
function OK($m){Write-Host "[deploy] OK: $m" -ForegroundColor Green}
W "Source: $SourceDir"
W "Dest: $DestDir"
# Stop
Get-Process -Name "anubis","anubis-daemon" -ErrorAction SilentlyContinue | ForEach-Object { W "Stopping $($_.Name) PID $($_.Id)"; Stop-Process -Id $_.Id -Force }
Start-Sleep -Seconds 3
OK "Processes stopped"
# Copy
foreach($n in @("anubis.exe","anubis-daemon.exe")){ try{ Copy-Item (Join-Path $SourceDir $n) (Join-Path $DestDir $n) -Force; OK "Copied $n" }catch{ Write-Host "[deploy] WARN: $n locked" -ForegroundColor Yellow } }
# Copy auxiliary symbol bundles from test fixtures (Spring Boot, npm, etc).
# Primary bundle ~/.anubis/symbol_bundle.jsonl is managed by bootstrap_bundle.py;
# auxiliary bundles ship with the daemon so users get sane defaults for Java/Spring.
$BundleSrc = Join-Path $SourceDir "..\tests\fixtures"
$AnubisHome = Join-Path $env:USERPROFILE ".anubis"
if(-not (Test-Path $AnubisHome)){ New-Item -ItemType Directory -Path $AnubisHome -Force | Out-Null }
if(Test-Path $BundleSrc){
    Get-ChildItem -Path $BundleSrc -Filter "symbol_bundle_*.jsonl" -File -ErrorAction SilentlyContinue | ForEach-Object {
        $dest = Join-Path $AnubisHome $_.Name
        try{ Copy-Item $_.FullName $dest -Force; OK "Copied bundle $($_.Name)" }catch{ Write-Host "[deploy] WARN: $($_.Name) locked" -ForegroundColor Yellow }
    }
}
# Start
Start-Process (Join-Path $DestDir "anubis-daemon.exe") -WindowStyle Hidden
Start-Sleep -Seconds 2
$d = Get-Process -Name "anubis-daemon" -ErrorAction SilentlyContinue
if($d){ OK "Daemon started PID $($d.Id)" }else{ Write-Host "[deploy] ERROR: daemon failed" -ForegroundColor Red; exit 1 }
# Verify
try{ $r = Invoke-RestMethod "http://127.0.0.1:7878/__anubis/ping" -TimeoutSec 5; OK "Version $($r.version) on 7878" }catch{ W "Ping failed (may still be starting)" }
Write-Host "`n[deploy] Done. Reconnect to anubis." -ForegroundColor Green
