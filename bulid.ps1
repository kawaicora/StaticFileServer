[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$scriptDir = $PSScriptRoot
Set-Location $scriptDir

$venvPython = Join-Path $scriptDir ".venv\Scripts\python.exe"

Write-Host "===== Pack StaticFileServer =====" -ForegroundColor Cyan
Write-Host "WorkDir: $scriptDir"
Write-Host "Python : $venvPython"
Write-Host "--------------------------------`n"

if (-not (Test-Path $venvPython)) {
    Write-Host "Virtual env not found. Run: python -m venv .venv" -ForegroundColor Red
    exit 1
}

if (Test-Path "build") { Remove-Item build -Recurse -Force }
if (Test-Path "dist")  { Remove-Item dist -Recurse -Force }

& $venvPython -m PyInstaller -F --name StaticFileServer --specpath build main.py `
    --paths (Join-Path $scriptDir "src") `
    --additional-hooks-dir (Join-Path $scriptDir "packaging\hooks") `
    --collect-all wsgidav `
    --collect-all cheroot `
    --collect-all pyftpdlib

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nBuild OK" -ForegroundColor Green
    Write-Host "Output: $(Join-Path $scriptDir 'dist\StaticFileServer.exe')"
    Write-Host "First run: StaticFileServer.exe --init-config" -ForegroundColor Yellow
}
else {
    Write-Host "`nBuild FAILED, exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}