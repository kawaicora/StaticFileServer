
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$scriptDir = $PSScriptRoot
Set-Location $scriptDir

$venvPython = Join-Path $scriptDir ".venv\Scripts\python.exe"

Write-Host "===== 打包 StaticFileServer =====" -ForegroundColor Cyan
Write-Host "工作目录: $scriptDir"
Write-Host "Python: $venvPython"
Write-Host "--------------------------------`n"


if(Test-Path "build"){ Remove-Item build -Recurse -Force }
if(Test-Path "dist"){ Remove-Item dist -Recurse -Force }
if(Test-Path "*.spec"){ Remove-Item *.spec -Force }

& $venvPython -m PyInstaller -F main.py

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n? 打包成功！" -ForegroundColor Green
    Write-Host "输出文件在: $scriptDir\dist\main.exe"
}
else {
    Write-Host "`n? 打包失败，退出码 $LASTEXITCODE" -ForegroundColor Red
}
