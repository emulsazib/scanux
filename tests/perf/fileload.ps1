# ~1000 file create/write/delete operations per second in a temp dir.
param([int]$Minutes = 10)
$dir = Join-Path $env:TEMP "scanu-load"; New-Item -ItemType Directory -Force $dir | Out-Null
$end = (Get-Date).AddMinutes($Minutes); $buf = [byte[]]::new(4096)
while ((Get-Date) -lt $end) {
  $t0 = Get-Date
  for ($i = 0; $i -lt 333; $i++) {
    $p = Join-Path $dir "f$i.bin"; [IO.File]::WriteAllBytes($p, $buf); Remove-Item $p
  }
  $sleep = 1000 - ((Get-Date) - $t0).TotalMilliseconds; if ($sleep -gt 0) { Start-Sleep -Milliseconds $sleep }
}
