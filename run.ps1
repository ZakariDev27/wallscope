# Builds the engine if needed and starts the WallScope dashboard.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not (Test-Path 'src/FirewallDetector.Cli/bin/Release/net8.0/wallscope.dll')) {
    Write-Host 'Building the WallScope engine...'
    dotnet build src/FirewallDetector.Cli -c Release --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw 'Engine build failed.' }
}

$env:PYTHONPATH = (Join-Path $PSScriptRoot 'python')
$python = if (Get-Command py -ErrorAction SilentlyContinue) { 'py' } else { 'python' }
& $python -m wallscope serve @args
