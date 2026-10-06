param([switch]$Install,[switch]$Uninstall,[string]$Server,[string]$DeviceIP)
$ErrorActionPreference='Stop'
$collectorRoot=Join-Path $env:ProgramData 'MultiplaSIEM-Collector'
$taskName='MultiplaSIEM-Metrics'
if($Uninstall){Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue;Write-Output 'Coletor desativado. Revogue a chave no SIEM; remova a pasta protegida se não for reutilizar.';exit}
if($Install){
 if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Execute como administrador'}
 $origin=[Uri]$Server
 if($origin.Scheme -ne 'https' -or $origin.UserInfo -or $origin.Query -or $origin.Fragment -or $origin.AbsolutePath -ne '/'){throw 'Informe somente a origem HTTPS do SIEM, com certificado confiável'}
 $parsedIP=$null;if(-not [Net.IPAddress]::TryParse($DeviceIP,[ref]$parsedIP)){throw 'Informe o IP exatamente como cadastrado no SIEM'}
 if(Test-Path -LiteralPath $collectorRoot){throw 'A pasta do coletor já existe. Para reinstalar, desative a tarefa e remova a pasta como administrador após verificar seu conteúdo.'}
 New-Item -ItemType Directory -Path $collectorRoot|Out-Null
 # Restrict local script/config/token to Administrators and SYSTEM before writing any credential.
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){$id=New-Object Security.Principal.SecurityIdentifier($sid);$rule=New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.AddAccessRule($rule)}
 $localService=New-Object Security.Principal.SecurityIdentifier('S-1-5-19');$readRule=New-Object Security.AccessControl.FileSystemAccessRule($localService,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow');$acl.AddAccessRule($readRule)
 Set-Acl -LiteralPath $collectorRoot -AclObject $acl
 $secret=Read-Host 'Cole a chave exclusiva gerada no cadastro do dispositivo' -AsSecureString
 $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
 try{$plain=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer);if($plain.Length -lt 32 -or $plain.Length -gt 128){throw 'Chave inválida'};Add-Type -AssemblyName System.Security;$raw=[Text.Encoding]::UTF8.GetBytes($plain);$protected=[Security.Cryptography.ProtectedData]::Protect($raw,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine);[IO.File]::WriteAllBytes((Join-Path $collectorRoot 'token.dpapi'),$protected);[Array]::Clear($raw,0,$raw.Length)}finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer);$plain=$null}
 @{server=$origin.GetLeftPart([UriPartial]::Authority);ip=$DeviceIP}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $collectorRoot 'config.json') -Encoding UTF8
 $destination=Join-Path $collectorRoot 'collector.ps1';if([IO.Path]::GetFullPath($PSCommandPath) -ne [IO.Path]::GetFullPath($destination)){Copy-Item -LiteralPath $PSCommandPath -Destination $destination -Force}
 $psExe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $action=New-ScheduledTaskAction -Execute $psExe -Argument ('-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "'+$destination+'"')
 $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 50) -MultipleInstances IgnoreNew -StartWhenAvailable
 Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal (New-ScheduledTaskPrincipal -UserId 'S-1-5-19' -LogonType ServiceAccount -RunLevel Limited) -Force|Out-Null
 Write-Output 'Coletor instalado: envia somente métricas por HTTPS a cada minuto. Nenhuma porta de entrada foi aberta.';exit
}
try{
 $config=Get-Content -LiteralPath (Join-Path $collectorRoot 'config.json') -Raw|ConvertFrom-Json
 Add-Type -AssemblyName System.Security
 $secretBytes=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes((Join-Path $collectorRoot 'token.dpapi')),$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
 $agentKey=[Text.Encoding]::UTF8.GetString($secretBytes);[Array]::Clear($secretBytes,0,$secretBytes.Length)
 $processor=Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -OperationTimeoutSec 8
 $os=Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 8
 $disks=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -OperationTimeoutSec 8|Where-Object {$_.Size -gt 0}|ForEach-Object {@{drive=$_.DeviceID;used_percent=[Math]::Round(100*(1-($_.FreeSpace/$_.Size)),2)}})
 $interfaces=Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface -OperationTimeoutSec 8
 $data=@{hostname=$env:COMPUTERNAME;cpu=[double]$processor.PercentProcessorTime;memory=[Math]::Round(100*(1-($os.FreePhysicalMemory/$os.TotalVisibleMemorySize)),2);disks=$disks;receive_bytes_per_second=[double](($interfaces|Measure-Object BytesReceivedPersec -Sum).Sum);send_bytes_per_second=[double](($interfaces|Measure-Object BytesSentPersec -Sum).Sum)}
 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
 $url=$config.server+'/api/device-metrics/'+[Uri]::EscapeDataString($config.ip)
 # Keep default certificate validation. No redirects that could transmit the bearer key to another host.
 Invoke-RestMethod -Uri $url -Method Post -Headers @{Authorization='Bearer '+$agentKey} -ContentType 'application/json' -Body ($data|ConvertTo-Json -Depth 5 -Compress) -TimeoutSec 10 -MaximumRedirection 0|Out-Null
}catch{Write-Error 'Não foi possível coletar/enviar as métricas. Verifique certificado, URL, chave e acesso ao SIEM.'}finally{$agentKey=$null}
