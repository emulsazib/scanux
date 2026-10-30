# Canary trip → freeze latency on a real endpoint (driver loaded, sensor running).
# Writes to a deployed canary from a throwaway process. Then:
#   - the write must fail (kernel deny),
#   - the process must be suspended,
#   - the sensor log must report frozen_us < 100000.
param([string]$Canary = (Get-ChildItem "$env:USERPROFILE\Documents" -Force -Filter "!000_archive_*.docx" | Select-Object -First 1).FullName)
if (-not $Canary) { Write-Error "no canary found; is the sensor running with canary_dirs configured?"; exit 1 }
$script = "try { [IO.File]::AppendAllText('$Canary','x'); 'WRITE SUCCEEDED' } catch { 'WRITE DENIED: ' + `$_.Exception.Message }; Start-Sleep 30"
$p = Start-Process powershell -ArgumentList "-NoProfile -Command $script" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2
$threads = (Get-Process -Id $p.Id).Threads | Group-Object WaitReason | ForEach-Object { "$($_.Name)=$($_.Count)" }
"process $($p.Id) thread states: $($threads -join ', ')   (expect Suspended)"
Get-Content "C:\ProgramData\Scanu\data\..\logs\sensor.log" -Tail 50 -ErrorAction SilentlyContinue | Select-String "canary trip"
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
