param([Parameter(Mandatory=$true)][string]$Application,[Parameter(Mandatory=$true)][string]$Frontend)
$ErrorActionPreference='Stop'
$appPath=(Resolve-Path -LiteralPath $Application).Path
$frontendPath=(Resolve-Path -LiteralPath $Frontend).Path
# Keep the PID returned by our own launch. Never enumerate or kill another app.
$process=Start-Process -FilePath $appPath -ArgumentList '--audio-bridge-self-test',('"'+$frontendPath+'"') -WindowStyle Hidden -PassThru
try {
    if(!$process.WaitForExit(60000)) { $process.Kill();$process.WaitForExit();throw 'Isolated WebView test exceeded60seconds; its own process was stopped.' }
    if($process.ExitCode -ne 0) { throw 'Isolated WebView audio bridge test failed.' }
} finally { $process.Dispose() }
