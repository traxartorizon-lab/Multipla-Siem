param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$PublisherSubject,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$CertificateSha256,
    [Parameter(Mandatory=$true)][string]$SignTool
)
$ErrorActionPreference = 'Stop'
# Verification only. Never imports a certificate or accesses a private key.
$file = Get-Item -LiteralPath $Path
if ($file.PSIsContainer -or $file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Arquivo de assinatura inválido.' }
if ($file.Name -notin @('Multipla.Siem.exe','Multipla.Siem.dll')) { throw 'Verifique componentes de terceiros separadamente, sem reassiná-los.' }
$signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) { throw 'Assinatura Authenticode ausente, inválida ou não confiável.' }
if ($signature.SignerCertificate.Subject -cne $PublisherSubject) { throw 'Publicador diferente do aprovado.' }
$actual = $signature.SignerCertificate.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256)
if ($actual -ine $CertificateSha256) { throw 'Certificado diferente da identidade aprovada.' }
if ($null -eq $signature.TimeStamperCertificate) { throw 'Timestamp confiável obrigatório.' }
& $SignTool verify /pa /all /v /tw $file.FullName
if ($LASTEXITCODE -ne 0) { throw 'SignTool rejeitou cadeia, política ou timestamp.' }
Write-Output ('PASS Authenticode: ' + $file.Name + ' · ' + $signature.SignerCertificate.Subject)
