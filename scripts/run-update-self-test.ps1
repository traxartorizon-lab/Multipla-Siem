param([Parameter(Mandatory=$true)][string]$Application,[Parameter(Mandatory=$true)][string]$Repository)
$ErrorActionPreference='Stop'
$appPath=(Resolve-Path -LiteralPath $Application).Path
$repositoryPath=(Resolve-Path -LiteralPath $Repository).Path
# The test only uses its own TEMP cache, fake HTTP and a process runner which
# refuses execution. Its receipt stays outside the published payload.
$receipt=Join-Path ([IO.Path]::GetTempPath()) ('multipla-update-test-'+[guid]::NewGuid().ToString('N')+'.txt')
$process=Start-Process -FilePath $appPath -ArgumentList '--update-self-test',('"'+$repositoryPath+'"') -WindowStyle Hidden -RedirectStandardOutput $receipt -PassThru
# Windows PowerShell 5 can otherwise release the redirected child's handle
# before ExitCode is queried, returning null even after a successful wait.
$null=$process.Handle
try {
    if(!$process.WaitForExit(60000)) { $process.Kill();$process.WaitForExit();throw 'Isolated update test exceeded 60 seconds; only its own process was stopped.' }
    if($process.ExitCode -ne 0) { throw 'Isolated update self-test failed.' }
    $result=Get-Content -LiteralPath $receipt -Raw
    if($result -notmatch '^PASS: [0-9]+ isolated update checks;') { throw 'Update self-test receipt missing.' }
    Write-Output $result
} finally { $process.Dispose();if(Test-Path -LiteralPath $receipt){Remove-Item -LiteralPath $receipt} }
