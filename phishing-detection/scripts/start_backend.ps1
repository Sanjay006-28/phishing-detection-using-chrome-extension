param(
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$workspaceRoot = Split-Path -Parent $root
$backendDir = Join-Path $root "backend"

$pythonCandidates = @(
    (Join-Path (Join-Path $root ".venv") "Scripts\python.exe"),
    (Join-Path (Join-Path $workspaceRoot ".venv") "Scripts\python.exe")
)

$pythonExe = $null
foreach ($candidate in $pythonCandidates) {
    if (Test-Path $candidate) {
        $pythonExe = $candidate
        break
    }
}

if (-not (Test-Path $pythonExe)) {
    Write-Error "Python executable not found. Tried: $($pythonCandidates -join ', ')"
}

$conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($conn) {
    Write-Output "Stopping process on port $Port (PID=$($conn.OwningProcess))"
    Stop-Process -Id $conn.OwningProcess -Force
    Start-Sleep -Seconds 1
}

Set-Location $backendDir
Write-Output "Starting backend on http://$BindHost`:$Port"
& $pythonExe -m uvicorn main:app --host $BindHost --port $Port
