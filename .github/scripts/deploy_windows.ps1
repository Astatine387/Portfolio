param(
    [Parameter(Mandatory)][string] $ProjectDir,  # e.g. Projects/PasswordManager
    [Parameter(Mandatory)][string] $AppName      # e.g. PasswordManager
)

$ErrorActionPreference = 'Stop'

# PowerShell raises nothing when an external command fails, so every one of them below
# is followed by a $LASTEXITCODE check. Without that a broken package still uploads.

$project = Resolve-Path $ProjectDir
$deploy = Join-Path $project 'deploy'

if (Test-Path $deploy) {
    Remove-Item $deploy -Recurse -Force
}

# The application, every non-Qt DLL it imports and the MSVC runtime, as the CMake install rules describe them
cmake --install (Join-Path $project 'build') --config Release --prefix $deploy
if ($LASTEXITCODE -ne 0) { throw 'cmake --install failed' }

# Qt libraries and plugins
& "$env:QT_ROOT_DIR\bin\windeployqt.exe" --no-translations --no-system-d3d-compiler --no-opengl-sw (Join-Path $deploy "$AppName.exe")
if ($LASTEXITCODE -ne 0) { throw 'windeployqt failed' }

Get-ChildItem $deploy -Recurse | Format-Table Name, Length

# Refuse a package that imports a DLL it does not carry
python -m pip install --quiet --require-hashes --only-binary=:all: -r (Join-Path $PSScriptRoot 'requirements-deploy.txt')
if ($LASTEXITCODE -ne 0) { throw 'pip install pefile failed' }

python (Join-Path $PSScriptRoot 'check_deploy.py') $deploy
if ($LASTEXITCODE -ne 0) { throw 'deploy folder is incomplete' }
