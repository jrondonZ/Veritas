# Builds dist/NotesCli.exe with the C# compiler that ships with Windows (.NET Framework 4.x):
#   powershell -NoProfile -File labs/notes-cli/tools/build.ps1
# This is the lab owner's tooling. The compiler stamps a time and a module ID into every build, so a rebuild
# changes the file's hash: put the sha256 this prints into ../veritas.charter.yaml. Veritas never runs the result.
$ErrorActionPreference = "Stop"
$lab = Split-Path -Parent $PSScriptRoot
$csc = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) { throw "the .NET Framework 4 C# compiler isn't installed: $csc" }
New-Item -ItemType Directory -Force (Join-Path $lab "dist") | Out-Null
& $csc /nologo /target:exe /platform:anycpu /optimize+ /debug- `
    "/out:$(Join-Path $lab 'dist\NotesCli.exe')" /reference:System.Data.dll /reference:System.Xml.dll `
    (Join-Path $lab "src\NotesCli.cs")
if ($LASTEXITCODE -ne 0) { throw "csc failed with exit code $LASTEXITCODE" }
$hash = (Get-FileHash (Join-Path $lab "dist\NotesCli.exe") -Algorithm SHA256).Hash.ToLower()
"dist/NotesCli.exe sha256 $hash"
