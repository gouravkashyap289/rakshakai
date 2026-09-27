param([switch]$SkipInstall, [int]$BackendPort=8002, [int]$FrontendPort=5173)
$ErrorActionPreference = 'Stop'
$rakshakRoot = $PSScriptRoot
$rakshakPython = Join-Path $rakshakRoot '.venv/Scripts/python.exe'
$rakshakPreparedPython = Join-Path $rakshakRoot '../../work/venv/Scripts/python.exe'
if ((Test-Path -LiteralPath $rakshakPreparedPython) -and !(Test-Path -LiteralPath $rakshakPython)) { $rakshakPython = (Resolve-Path -LiteralPath $rakshakPreparedPython).Path }
if (!(Test-Path -LiteralPath $rakshakPython)) {
    $rakshakPythonCommand = Get-Command python -ErrorAction SilentlyContinue
    $rakshakPythonBase = if ($rakshakPythonCommand) { $rakshakPythonCommand.Source } else { Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe' }
    if (!(Test-Path -LiteralPath $rakshakPythonBase)) { throw 'Install Python 3.12+ before launching Rakshak.' }
    & $rakshakPythonBase -m venv (Join-Path $rakshakRoot '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.12+ is required.' }
}
$rakshakPnpmCommand = Get-Command pnpm -ErrorAction SilentlyContinue
$rakshakPnpm = if ($rakshakPnpmCommand) { $rakshakPnpmCommand.Source } else { Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/bin/fallback/pnpm.cmd' }
if (!$SkipInstall) {
    & $rakshakPython -m pip install -r (Join-Path $rakshakRoot 'backend/requirements.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Backend dependency installation failed.' }
    Push-Location (Join-Path $rakshakRoot 'frontend')
    try {
        & $rakshakPnpm install
        if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
        & $rakshakPnpm build
        if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
    } finally { Pop-Location }
}
$rakshakEnvArgs = if (Test-Path -LiteralPath (Join-Path $rakshakRoot '.env')) { @('--env-file', '../.env') } else { @() }
$env:PUBLIC_BASE_URL = "http://127.0.0.1:$FrontendPort"
$env:RAKSHAK_BACKEND_URL = "http://127.0.0.1:$BackendPort"
$rakshakBackendArgs = @('-m','uvicorn','app.main:app','--host','127.0.0.1','--port',"$BackendPort") + $rakshakEnvArgs
$rakshakBackend = Start-Process -FilePath $rakshakPython -ArgumentList $rakshakBackendArgs -WorkingDirectory (Join-Path $rakshakRoot 'backend') -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $rakshakRoot 'backend/server.log') -RedirectStandardError (Join-Path $rakshakRoot 'backend/server-error.log')
$rakshakNodeCommand = Get-Command node -ErrorAction SilentlyContinue
$rakshakNode = if ($rakshakNodeCommand) { $rakshakNodeCommand.Source } else { Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe' }
if (!(Test-Path -LiteralPath $rakshakNode)) { throw 'Node.js 22+ is required.' }
$rakshakFrontend = Start-Process -FilePath $rakshakNode -ArgumentList "node_modules/vite/bin/vite.js preview --host 127.0.0.1 --port $FrontendPort --strictPort --configLoader runner" -WorkingDirectory (Join-Path $rakshakRoot 'frontend') -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $rakshakRoot 'frontend/server.log') -RedirectStandardError (Join-Path $rakshakRoot 'frontend/server-error.log')
Write-Host "Rakshak: http://127.0.0.1:$FrontendPort"
Write-Host "Server process IDs: $($rakshakBackend.Id), $($rakshakFrontend.Id). Stop these processes when finished."
