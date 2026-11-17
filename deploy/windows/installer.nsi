; DIVISION T82 · Instalador nativo Windows x64 (NSIS 3, Unicode)
;
; Compilación (en Windows, o desde Linux con makensis para validar la sintaxis):
;   makensis /DVERSION=0.2.1 /DPAYLOAD="dist/win-payload/vulncheck-t82" deploy/windows/installer.nsi
;   → dist/vulncheck-t82-<VERSION>-win64-setup.exe
;
; El payload (build compilado + node.exe + CLI Prisma + WinSW) lo ensambla
; deploy/windows/build-installer.ps1. Modelo: instalador CON build compilado —
; instalación rápida sin npm en destino (diferente del modelo fuente de Linux).
;
; Qué hace:
;   · Copia la app a "%PROGRAMFILES64%\DIVISION T82"
;   · Datos SQLite en "%ProgramData%\VULNCHECK-T82" (ACL: Usuarios con modify)
;   · Servicio Windows "VulncheckT82" vía WinSW (arranque automático, restart)
;   · db push de Prisma al terminar (idempotente) y en cada arranque (prestart)
;   · Escuchas en 127.0.0.1 por defecto (postura local-first, sin firewall)
;   · Desinstalador que conserva la base de datos

!include "MUI2.nsh"
!include "x64.nsh"
!include "StrFunc.nsh"

${StrRep}

; ─── Parámetros de compilación ────────────────────────────────────────────────
!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef PORT
  !define PORT "3000"
!endif
!ifndef PAYLOAD
  !define PAYLOAD "payload\vulncheck-t82"
!endif
!ifndef OUTFILE
  !define OUTFILE "..\..\dist\vulncheck-t82-${VERSION}-win64-setup.exe"
!endif

!define APPNAME "DIVISION T82"
!define SVCID "VulncheckT82"
!define REGKEY "SOFTWARE\DIVISION T82"
!define UNINSTKEY "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DIVISION T82"
!define SMFOLDER "DIVISION T82"

Name "${APPNAME} ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\${APPNAME}"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
Unicode true
ShowInstDetails show
ShowUnInstDetails show
ManifestDPIAware true

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "DIVISION T82"
VIAddVersionKey "CompanyName" "RTO Studio — Ramón Taboada Olivella"
VIAddVersionKey "FileDescription" "DIVISION T82 — instalador de la plataforma de auditoría de postura"
VIAddVersionKey "LegalCopyright" "By: Ramón Taboada Olivella - RTO Studio"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"

Var SMFOLDERVAL   ; carpeta del menú Inicio (MUI_PAGE_STARTMENU) — debe declararse antes del macro
Var DATA_DIR
Var DATA_URL

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION "OpenAppInBrowser"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_STARTMENU Application $SMFOLDERVAL
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "Spanish"
!insertmacro MUI_LANGUAGE "English"

LangString DataKept ${LANG_SPANISH} "Los datos de auditoría (SQLite) se conservan en %ProgramData%\VULNCHECK-T82. Elimínalos manualmente si no los necesitas."
LangString DataKept ${LANG_ENGLISH} "Audit data (SQLite) is preserved in %ProgramData%\VULNCHECK-T82. Remove it manually if you no longer need it."
LangString SvcStopFail ${LANG_SPANISH} "El servicio no se detuvo limpiamente (continúa la desinstalación)."
LangString SvcStopFail ${LANG_ENGLISH} "The service did not stop cleanly (uninstall continues)."

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "DIVISION T82 ${VERSION} requiere Windows x64 de 64 bits."
    Abort
  ${EndIf}
FunctionEnd

; ─── Instalación ──────────────────────────────────────────────────────────────
Section "DIVISION T82" SecMain
  SectionIn RO

  ; Datos: %ProgramData%\VULNCHECK-T82
  ReadEnvStr $DATA_DIR "ProgramData"
  ${If} "$DATA_DIR" == ""
    StrCpy $DATA_DIR "C:\ProgramData"
  ${EndIf}
  StrCpy $DATA_DIR "$DATA_DIR\VULNCHECK-T82"
  ${StrRep} $DATA_URL "$DATA_DIR" "\" "/"
  CreateDirectory "$DATA_DIR"
  CreateDirectory "$DATA_DIR\logs"
  ; Usuarios locales pueden escribir (servicio de máquina + modo portable)
  nsExec::ExecToLog 'icacls "$DATA_DIR" /inheritance:e /grant "*S-1-5-32-545:(OI)(CI)M"'
  Pop $0

  SetOutPath "$INSTDIR"
  File /r "${PAYLOAD}\*.*"

  WriteRegStr HKLM "${REGKEY}" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "${REGKEY}" "DataDir" "$DATA_DIR"
  WriteRegStr HKLM "${REGKEY}" "Port" "${PORT}"

  DetailPrint "Aplicando el esquema de base de datos (prisma db push)…"
  nsExec::ExecToLog '"$INSTDIR\node\node.exe" "$INSTDIR\tools\db-push.js" "$DATA_DIR"'
  Pop $0
  ${If} $0 != 0
    ; C3: un fallo de esquema aborta la instalación con error honesto —
    ; nunca se continúa con una BD sin aplicar (los datos no se han tocado).
    MessageBox MB_ICONSTOP "prisma db push falló (código $0). La instalación se detiene; la base de datos NO ha sido modificada. Revisa el log de instalación."
    Abort
  ${EndIf}

  ; service.xml para WinSW (valores absolutos escritos en tiempo de instalación)
  FileOpen $4 "$INSTDIR\vulncheck-t82-service.xml" w
  FileWrite $4 "<?xml version='1.0' encoding='utf-8'?>$\r$\n"
  FileWrite $4 "<service>$\r$\n"
  FileWrite $4 "  <id>${SVCID}</id>$\r$\n"
  FileWrite $4 "  <name>${APPNAME}</name>$\r$\n"
  FileWrite $4 "  <description>DIVISION T82 · auditoria local-first de postura de seguridad (By: Ramon Taboada Olivella - RTO Studio)</description>$\r$\n"
  FileWrite $4 "  <executable>$INSTDIR\node\node.exe</executable>$\r$\n"
  FileWrite $4 "  <arguments>server.js</arguments>$\r$\n"
  FileWrite $4 "  <workingdirectory>$INSTDIR\app</workingdirectory>$\r$\n"
  FileWrite $4 "  <env name='NODE_ENV' value='production'/>$\r$\n"
  FileWrite $4 "  <env name='PORT' value='${PORT}'/>$\r$\n"
  FileWrite $4 "  <env name='HOSTNAME' value='127.0.0.1'/>$\r$\n"
  FileWrite $4 "  <env name='DATABASE_URL' value='file:$DATA_URL/vulncheck.db'/>$\r$\n"
  FileWrite $4 "  <prestart>$\r$\n"
  FileWrite $4 "    <executable>$INSTDIR\node\node.exe</executable>$\r$\n"
  FileWrite $4 "    <arguments>tools\db-push.js &quot;$DATA_DIR&quot;</arguments>$\r$\n"
  FileWrite $4 "    <workingdirectory>$INSTDIR</workingdirectory>$\r$\n"
  FileWrite $4 "  </prestart>$\r$\n"
  FileWrite $4 "  <startmode>Automatic</startmode>$\r$\n"
  FileWrite $4 "  <stoptimeout>15 sec</stoptimeout>$\r$\n"
  FileWrite $4 "  <stopparentprocessfirst>true</stopparentprocessfirst>$\r$\n"
  FileWrite $4 "  <onfailure action='restart' delay='10 sec'/>$\r$\n"
  FileWrite $4 "  <logpath>$DATA_DIR\logs</logpath>$\r$\n"
  FileWrite $4 "  <log mode='roll-by-size'><sizeThreshold>10240</sizeThreshold><keepFiles>3</keepFiles></log>$\r$\n"
  FileWrite $4 "</service>$\r$\n"
  FileClose $4

  DetailPrint "Registrando el servicio Windows '${SVCID}'…"
  nsExec::ExecToLog '"$INSTDIR\vulncheck-t82-service.exe" install'
  Pop $0
  nsExec::ExecToLog '"$INSTDIR\vulncheck-t82-service.exe" start'
  Pop $0

  ; Registro de desinstalación + accesos directos
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayName" "${APPNAME}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTKEY}" "Publisher" "RTO Studio — Ramón Taboada Olivella"
  WriteRegStr HKLM "${UNINSTKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTKEY}" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoRepair" 1

  !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
    CreateDirectory "$SMPROGRAMS\$STARTMENU_FOLDER"
    CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\DIVISION T82.lnk" "$INSTDIR\start-vulncheck.bat" "" "$INSTDIR\node\node.exe" 0
    CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\Desinstalar DIVISION T82.lnk" "$INSTDIR\uninstall.exe"
  !insertmacro MUI_STARTMENU_WRITE_END
SectionEnd

Function OpenAppInBrowser
  ExecShell "open" "http://127.0.0.1:${PORT}"
FunctionEnd

; ─── Desinstalación (conserva los datos) ──────────────────────────────────────
Section "Uninstall"
  nsExec::Exec '"$INSTDIR\vulncheck-t82-service.exe" stop'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONEXCLAMATION|MB_OK "$(SvcStopFail)"
  ${EndIf}
  nsExec::Exec '"$INSTDIR\vulncheck-t82-service.exe" uninstall'
  Pop $0

  !insertmacro MUI_STARTMENU_GETFOLDER Application $SMFOLDERVAL
  RMDir /r "$SMPROGRAMS\$SMFOLDERVAL"

  RMDir /r "$INSTDIR"
  DeleteRegKey HKLM "${UNINSTKEY}"
  DeleteRegKey HKLM "${REGKEY}"

  MessageBox MB_ICONINFORMATION|MB_OK "$(DataKept)"
SectionEnd
