# Build self-describing hardly image and register with Docker MCP Toolkit + Cursor.
# Usage: powershell -File scripts/deploy-docker.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

$Image = "hardly-mcp:latest"
$Workspace = if ($env:HARDLY_WORKSPACE_HOST) { $env:HARDLY_WORKSPACE_HOST } else { "D:/code" }

Write-Host "==> Waiting for Docker..."
$deadline = (Get-Date).AddMinutes(3)
while ($true) {
    docker info 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { break }
    if ((Get-Date) -gt $deadline) {
        throw "Docker is not ready. Start Docker Desktop and re-run."
    }
    Start-Sleep -Seconds 3
}

Write-Host "==> Building $Image via scripts/build_image.py"
$py = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }
& $py (Join-Path $Root "scripts\build_image.py")
if ($LASTEXITCODE -ne 0) { throw "docker build failed" }

Write-Host "==> Smoke test path mapping + HAR open"
# Use container path (always works); also verify host-path mapping.
$code = @"
from hardly.session import open_har, resolve_path
assert str(resolve_path(r'D:\code\payhoa\x.har')).replace('\\','/') == '/workspace/payhoa/x.har'
r = open_har('/workspace/payhoa/app.payhoa.com.har')
assert r.get('entries') == 346, r
print('ok', r['entries'], 'entries')
"@
$codeFile = Join-Path $env:TEMP "hardly-smoke.py"
Set-Content -Path $codeFile -Value $code -Encoding UTF8
& docker run --rm --entrypoint python `
    -v "${Workspace}:/workspace" `
    -v "${codeFile}:/tmp/smoke.py:ro" `
    -e HARDLY_WORKSPACE=/workspace `
    -e HARDLY_RUNTIME_DIR=/workspace/.hardly-cache `
    $Image /tmp/smoke.py
if ($LASTEXITCODE -ne 0) { throw "smoke test failed" }

Write-Host "==> Adding hardly to Docker MCP profile ai_coding"
& docker mcp profile server add ai_coding --server "docker://hardly-mcp:latest"
if ($LASTEXITCODE -ne 0) {
    Write-Warning "profile add failed - Cursor still works via direct mcp.json entry"
} else {
    Write-Host "Enabled in profile ai_coding (MCP_DOCKER gateway)"
}

Write-Host ""
Write-Host "Image:     $Image"
Write-Host "Workspace: $Workspace -> /workspace"
Write-Host "Cache:     /workspace/.hardly-cache (on host under workspace)"
Write-Host ""
Write-Host "Cursor uses ~/.cursor/mcp.json entry hardly (docker run stdio)."
Write-Host "Reload MCP in Cursor Settings if tools do not appear."
