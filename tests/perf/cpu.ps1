# Sensor CPU/RSS budget (run elevated on the Windows VM).
#   .\cpu.ps1 -Minutes 10                  # idle baseline (budget: avg <= 2%)
#   .\cpu.ps1 -Minutes 10 -WithLoad        # + 1k file ops/s (budget: p95 <= 5%)
param([int]$Minutes = 10, [switch]$WithLoad)
$ErrorActionPreference = "Stop"
$cores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
$load = $null
if ($WithLoad) { $load = Start-Process powershell -ArgumentList "-File `"$PSScriptRoot\fileload.ps1`" -Minutes $Minutes" -PassThru -WindowStyle Hidden }
$samples = Get-Counter -Counter "\Process(scanu-sensor)\% Processor Time", "\Process(scanu-sensor)\Working Set - Private" `
  -SampleInterval 1 -MaxSamples ($Minutes * 60)
$cpu = $samples | ForEach-Object { $_.CounterSamples[0].CookedValue / $cores } | Sort-Object
$rss = ($samples | ForEach-Object { $_.CounterSamples[1].CookedValue } | Measure-Object -Maximum).Maximum / 1MB
$avg = ($cpu | Measure-Object -Average).Average
$p95 = $cpu[[int]([math]::Floor($cpu.Count * 0.95)) - 1]
if ($load) { Stop-Process $load -ErrorAction SilentlyContinue }
"cpu avg {0:N2}%  p95 {1:N2}%  max RSS {2:N0} MB  ({3} samples)" -f $avg, $p95, $rss, $cpu.Count
$ok = if ($WithLoad) { $p95 -le 5 } else { $avg -le 2 }
if (-not $ok -or $rss -gt 150) { Write-Error "BUDGET EXCEEDED"; exit 1 }
"PASS"
