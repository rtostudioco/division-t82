# DIVISION T82 · Constructor del instalador Windows (.exe)
#
# Ejecutar en Windows (PowerShell):
#   ./deploy/windows/build-installer.ps1
#   ./deploy/windows/build-installer.ps1 -Port 8080
#
# Requisitos: Node.js >= 20 en PATH (para compilar), NSIS 3 (makensis en PATH).
#   NSIS: winget install NSIS.NSIS  |  choco install nsis  |  https://nsis.sourceforge.io
#
# Qué produce:
#   dist/vulncheck-t82-<versión>-win64-setup.exe   (instalador NSIS con build compilado)
#   → registra el servicio Windows "VulncheckT82", datos en %ProgramData%\VULNCHECK-T82
#
# Descargas usadas (cacheables con variables de entorno para CI/air-gap):
#   NODE_WIN_ZIP   ruta local a node-vXX-win-x64.zip      (https://nodejs.org/dist)
#   WINSW_EXE      ruta local a WinSW-x64.exe             (https://github.com/winsw/winsw)
[CmdletBinding()]
param(
  [string]$Port = "3000",
  [switch]$SkipAppBuild
)

$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$NodeVer = '22.14.0'
$WinSwVer = '2.12.0'
$App = 'vulncheck-t82'

function Step($msg) { Write-Host "`n[T82-win] $msg" -ForegroundColor Cyan }

Set-Location $Repo
$Version = (Get-Content "$Repo/package.json" -Raw | ConvertFrom-Json).version
$Dist = Join-Path $Repo 'dist'
$Payload = Join-Path $Dist 'win-payload' $App
Write-Host "[T82-win] DIVISION T82 v$Version · instalador Windows x64 (puerto $Port)"

# ─── [1/6] Compilar la app (Next.js standalone) ───────────────────────────────
if (-not $SkipAppBuild) {
  Step 'npm ci + prisma generate + next build'
  npm ci --no-audit --no-fund
  if ($LASTEXITCODE) { throw "npm ci falló ($LASTEXITCODE)" }
  npx prisma generate
  if ($LASTEXITCODE) { throw 'prisma generate falló' }
  npx next build
  if ($LASTEXITCODE) { throw 'next build falló' }
} else {
  Step 'build de app OMITIDO (-SkipAppBuild)'
}

# ─── [2/6] Ensamblar el payload ───────────────────────────────────────────────
Step 'Ensamblando el payload (app standalone + runtime + herramientas)'
if (Test-Path (Join-Path $Dist 'win-payload')) {
  Remove-Item (Join-Path $Dist 'win-payload') -Recurse -Force
}
New-Item -ItemType Directory -Force -Path "$Payload/app", "$Payload/node", "$Payload/tools/prisma-cli", "$Payload/prisma" | Out-Null

Copy-Item "$Repo/.next/standalone/*" "$Payload/app/" -Recurse -Force
Copy-Item "$Repo/.next/static" "$Payload/app/.next/static" -Recurse -Force
if (Test-Path "$Repo/public") { Copy-Item "$Repo/public" "$Payload/app/public" -Recurse -Force }
Copy-Item "$Repo/prisma/schema.prisma" "$Payload/prisma/" -Force
Copy-Item "$Repo/deploy/windows/start-vulncheck.bat" $Payload -Force
Copy-Item "$Repo/deploy/windows/db-push.js" "$Payload/tools/" -Force

# ─── [3/6] Runtime Node para Windows ──────────────────────────────────────────
Step "Runtime Node v$NodeVer (win-x64)"
$NodeZip = $env:NODE_WIN_ZIP
if (-not $NodeZip) {
  $NodeZip = Join-Path $Dist "node-v$NodeVer-win-x64.zip"
  Invoke-WebRequest "https://nodejs.org/dist/v$NodeVer/node-v$NodeVer-win-x64.zip" -OutFile $NodeZip
}
$NodeTmp = Join-Path $Dist 'node-win-tmp'
Expand-Archive $NodeZip $NodeTmp -Force
Copy-Item "$NodeTmp/node-v$NodeVer-win-x64/*" "$Payload/node/" -Recurse -Force
Remove-Item $NodeTmp -Recurse -Force

# ─── [4/6] CLI de Prisma (para db push sin npm en destino) ────────────────────
Step 'CLI de Prisma (tools/prisma-cli)'
$PrismaCliDir = $env:PRISMA_CLI_DIR
if ($PrismaCliDir) {
  Copy-Item "$PrismaCliDir/node_modules" "$Payload/tools/prisma-cli/node_modules" -Recurse -Force
} else {
  New-Item -ItemType Directory -Force -Path "$Payload/tools/prisma-cli" | Out-Null
  Push-Location "$Payload/tools/prisma-cli"
  npm install "prisma@$((Get-Content "$Repo/package.json" -Raw | ConvertFrom-Json).dependencies.prisma)" --prefix . --no-audit --no-fund --loglevel=error
  if ($LASTEXITCODE) { Pop-Location; throw 'npm install prisma falló' }
  Pop-Location
}

# ─── [5/6] WinSW (envoltorio de servicio Windows, MIT) ────────────────────────
Step "WinSW v$WinSwVer (vulncheck-t82-service.exe)"
$WinSw = $env:WINSW_EXE
if (-not $WinSw) {
  $WinSw = Join-Path $Dist "WinSW-x64-$WinSwVer.exe"
  Invoke-WebRequest "https://github.com/winsw/winsw/releases/download/v$WinSwVer/WinSW-x64.exe" -OutFile $WinSw
}
Copy-Item $WinSw "$Payload/vulncheck-t82-service.exe" -Force

# ─── [6/6] Compilar el instalador con NSIS ────────────────────────────────────
Step 'makensis → dist\vulncheck-t82-win64-setup.exe'
New-Item -ItemType Directory -Force -Path $Dist | Out-Null

# Resolver makensis: PATH primero; si el shim de choco no llegó a PATH
# (fallo intermitente del paquete), probar las rutas estándar de NSIS 3.
$Makensis = (Get-Command makensis -ErrorAction SilentlyContinue).Source
if (-not $Makensis) {
  $Candidatos = @(
    "${env:ProgramFiles(x86)}\NSIS\makensis.exe",
    "${env:ProgramFiles}\NSIS\makensis.exe",
    "$env:ProgramData\chocolatey\bin\makensis.exe"
  )
  $Makensis = $Candidatos | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Makensis) { throw 'makensis no encontrado: instala NSIS 3 (choco install nsis) o añádelo al PATH' }
Write-Host "[T82-win] makensis: $Makensis"

$PayloadPath = $Payload
$OutFile = Join-Path $Dist "vulncheck-t82-$Version-win64-setup.exe"
$NsiFile = Join-Path $Repo 'deploy/windows/installer.nsi'
$NsisArgs = @(
  "/DVERSION=$Version",
  "/DPORT=$Port",
  "/DPAYLOAD=$PayloadPath",
  "/DOUTFILE=$OutFile",
  $NsiFile
)
& $Makensis @NsisArgs
if ($LASTEXITCODE) { throw "makensis falló ($LASTEXITCODE)" }

# ─── Checksums ────────────────────────────────────────────────────────────────
Step 'SHA256SUMS'
$Setup = "vulncheck-t82-$Version-win64-setup.exe"
$Hash = (Get-FileHash "$Dist/$Setup" -Algorithm SHA256).Hash.ToLower()
$Sums = Join-Path $Dist 'SHA256SUMS'
$Lines = @()
if (Test-Path $Sums) { $Lines = Get-Content $Sums | Where-Object { $_ -notmatch [regex]::Escape($Setup) } }
$Lines += "$Hash  $Setup"
Set-Content $Sums ($Lines -join "`n") -Encoding ascii

Remove-Item "$Repo/dist/win-payload" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n[T82-win] LISTO: dist/$Setup" -ForegroundColor Green
Write-Host "[T82-win] sha256: $Hash"
Write-Host '[T82-win] El instalador registra el servicio VulncheckT82 y abre http://127.0.0.1:' -NoNewline
Write-Host "$Port al terminar."
