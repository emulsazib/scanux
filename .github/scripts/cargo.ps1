# Runs cargo; on failure, surfaces the compiler/test errors as a GitHub annotation
# (readable from the public checks API without downloading logs).
$ErrorActionPreference = 'Continue'
$log = New-TemporaryFile
& cargo @args 2>&1 | Tee-Object -FilePath $log
$code = $LASTEXITCODE
if ($code -ne 0) {
  $lines = Get-Content $log | Where-Object { $_ -match '^(error|warning: unused)|^\s+-->|^\s*\d* \|.*\S|^---- |panicked at|^failures:' } | Select-Object -First 120
  $msg = (($lines | ForEach-Object { $_ -replace '%', '%25' }) -join '%0A')
  Write-Output "::error title=cargo $($args[0]) failed::$msg"
}
exit $code
