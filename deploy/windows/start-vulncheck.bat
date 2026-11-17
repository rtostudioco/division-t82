@echo off
rem DIVISION T82 · arranque manual (modo portable Windows)
rem Lee la ruta de datos del registro (instalador) o usa %LOCALAPPDATA% por defecto.
cd /d "%~dp0"
set "DATA_DIR="
for /f "tokens=1,2*" %%A in ('reg query "HKLM\SOFTWARE\DIVISION T82" /v DataDir 2^>nul') do (
  if /i "%%A"=="DataDir" set "DATA_DIR=%%C"
)
if "%DATA_DIR%"=="" set "DATA_DIR=%LOCALAPPDATA%\VULNCHECK-T82"
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"

set "DATABASE_URL=file:%DATA_DIR:\=/%/vulncheck.db"
set "PORT=3000"
set "HOSTNAME=127.0.0.1"
set "NODE_ENV=production"

if not exist "app\server.js" (
  echo Falta la app compilada ^(app\server.js^). Usa el instalador completo.
  pause
  exit /b 1
)

echo DIVISION T82 · http://127.0.0.1:%PORT% · datos: %DATA_DIR%
timeout /t 2 /nobreak >nul
start "" "http://127.0.0.1:%PORT%"
"node\node.exe" "app\server.js"
