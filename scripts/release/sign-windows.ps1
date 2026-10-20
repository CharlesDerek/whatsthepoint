[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Directory,[Parameter(Mandatory=$true)][string]$PublisherThumbprint,[string]$TimestampUrl='http://timestamp.digicert.com')
$ErrorActionPreference='Stop'
$SignTool=(Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1).FullName
if (!$SignTool) { throw 'Install Windows SDK SignTool.' }
$Files=@(Get-ChildItem -LiteralPath $Directory -File -Filter '*.exe')
if (!$Files.Count) { throw 'No executables to sign.' }
foreach ($File in $Files) {
    & $SignTool sign /sha1 $PublisherThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $File.FullName
    if ($LASTEXITCODE) { throw 'Authenticode signing failed.' }
    & $SignTool verify /pa /all $File.FullName
    if ($LASTEXITCODE) { throw 'Authenticode verification failed.' }
    $Signature=Get-AuthenticodeSignature -LiteralPath $File.FullName
    if ($Signature.Status -ne 'Valid' -or $Signature.SignerCertificate.Thumbprint -ne $PublisherThumbprint) { throw 'Publisher validation failed.' }
}
