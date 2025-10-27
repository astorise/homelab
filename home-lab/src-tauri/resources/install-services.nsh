; Optional: force showing the details view and start a simple file log
Var LOG_FILE
Var LOG_HANDLE
Var UNINS_HTTP_OK
Var UNINS_DNS_OK

!macro NSIS_HOOK_PREINSTALL
  ; SetDetailsPrint is valid in sections; ShowInstDetails must be outside.
  ; Avoid ShowInstDetails here to keep NSIS happy in CI.
  SetDetailsPrint both
  StrCpy $LOG_FILE "$INSTDIR\installer.log"
  ClearErrors
  FileOpen $LOG_HANDLE $LOG_FILE w
  ${If} ${Errors}
    DetailPrint "[installer] Unable to open $LOG_FILE for writing"
  ${Else}
    DetailPrint "[installer] Logging to $LOG_FILE"
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  CreateDirectory "$INSTDIR\conf"
  ${IfNot} ${FileExists} "$INSTDIR\conf\dns.yaml"
    ; Si, pour une raison X, la ressource n'a pas été copiée :
    CopyFiles /SILENT "$INSTDIR\dns.yaml" "$INSTDIR\conf\dns.yaml"
  ${EndIf}
  ${IfNot} ${FileExists} "$INSTDIR\conf\http.yaml"
    ; Si, pour une raison X, la ressource n'a pas été copiée :
    CopyFiles /SILENT "$INSTDIR\http.yaml" "$INSTDIR\conf\http.yaml"
  ${EndIf}
  DetailPrint "Installing Windows services..."
  nsExec::ExecToStack '"$INSTDIR\bin\home-dns.exe" install'
  Pop $0
  Pop $1
  DetailPrint "home-dns.exe install => rc=$0 out=$1"
  ${If} $0 != 0
    DetailPrint "[WARN] home-dns.exe install returned $0"
  ${EndIf}
  StrCmp $LOG_HANDLE "" +2
  FileWrite $LOG_HANDLE "home-dns.exe install => rc=$0 out=$1$\r$\n"
  nsExec::ExecToStack '"$INSTDIR\bin\home-http.exe" install'
  Pop $0
  Pop $1
  DetailPrint "home-http.exe install => rc=$0 out=$1"
  ${If} $0 != 0
    DetailPrint "[WARN] home-http.exe install returned $0"
  ${EndIf}
  StrCmp $LOG_HANDLE "" +2
  FileWrite $LOG_HANDLE "home-http.exe install => rc=$0 out=$1$\r$\n"
  ; Try starting services right after install (best effort)
  nsExec::ExecToStack 'sc.exe start HomeDnsService'
  Pop $0
  Pop $1
  DetailPrint "sc start HomeDnsService => rc=$0 out=$1"
  StrCmp $LOG_HANDLE "" +2
  FileWrite $LOG_HANDLE "sc start HomeDnsService => rc=$0 out=$1$\r$\n"
  nsExec::ExecToStack 'sc.exe start HomeHttpService'
  Pop $0
  Pop $1
  DetailPrint "sc start HomeHttpService => rc=$0 out=$1"
  StrCmp $LOG_HANDLE "" +2
  FileWrite $LOG_HANDLE "sc start HomeHttpService => rc=$0 out=$1$\r$\n"
    ; Exécution après installation
  ; Forcer l’élévation (si pas déjà perMachine)
  ; et lancer WSL sans distribution
  nsExec::ExecToLog 'powershell -ExecutionPolicy Bypass -Command "wsl --install --no-distribution"'
  ; Close log file if opened
  StrCmp $LOG_HANDLE "" +2
  FileClose $LOG_HANDLE
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; Post-uninstall: just close the log if opened in PREUNINSTALL
  StrCmp $LOG_HANDLE "" +2
  FileClose $LOG_HANDLE
!macroend


; Ensure services are stopped and deleted BEFORE files are removed
!macro NSIS_HOOK_PREUNINSTALL
  SetDetailsPrint both
  StrCpy $LOG_FILE "$INSTDIR\installer.log"
  ClearErrors
  FileOpen $LOG_HANDLE $LOG_FILE a
  ${If} ${Errors}
    DetailPrint "[uninstall] Unable to open $LOG_FILE for appending"
  ${Else}
    DetailPrint "[uninstall] Logging to $LOG_FILE"
  ${EndIf}

  ; Track per-service uninstall success to avoid duplicate sc.exe calls
  StrCpy $UNINS_HTTP_OK 0
  StrCpy $UNINS_DNS_OK 0

  DetailPrint "Invoking service uninstallers..."
  ${If} ${FileExists} "$INSTDIR\bin\home-http.exe"
    nsExec::ExecToStack '"$INSTDIR\bin\home-http.exe" uninstall'
    Pop $0
    Pop $1
    DetailPrint "home-http.exe uninstall => rc=$0 out=$1"
    StrCmp $LOG_HANDLE "" +2
    FileWrite $LOG_HANDLE "home-http.exe uninstall => rc=$0 out=$1$\r$\n"
    ${If} $0 == 0
      StrCpy $UNINS_HTTP_OK 1
    ${EndIf}
  ${EndIf}
  ${If} ${FileExists} "$INSTDIR\bin\home-dns.exe"
    nsExec::ExecToStack '"$INSTDIR\bin\home-dns.exe" uninstall'
    Pop $0
    Pop $1
    DetailPrint "home-dns.exe uninstall => rc=$0 out=$1"
    StrCmp $LOG_HANDLE "" +2
    FileWrite $LOG_HANDLE "home-dns.exe uninstall => rc=$0 out=$1$\r$\n"
    ${If} $0 == 0
      StrCpy $UNINS_DNS_OK 1
    ${EndIf}
  ${EndIf}

  ; Fallback stopping only if the uninstaller failed or binary is missing
  ${If} $UNINS_HTTP_OK != 1
    DetailPrint "Stopping HomeHttpService (fallback)..."
    nsExec::ExecToStack 'sc.exe stop HomeHttpService'
    Pop $0
    Pop $1
    DetailPrint "sc stop HomeHttpService => rc=$0 out=$1"
    StrCmp $LOG_HANDLE "" +2
    FileWrite $LOG_HANDLE "sc stop HomeHttpService => rc=$0 out=$1$\r$\n"
  ${EndIf}
  ${If} $UNINS_DNS_OK != 1
    DetailPrint "Stopping HomeDnsService (fallback)..."
    nsExec::ExecToStack 'sc.exe stop HomeDnsService'
    Pop $0
    Pop $1
    DetailPrint "sc stop HomeDnsService => rc=$0 out=$1"
    StrCmp $LOG_HANDLE "" +2
    FileWrite $LOG_HANDLE "sc stop HomeDnsService => rc=$0 out=$1$\r$\n"
  ${EndIf}

  ; Small grace period if we had to stop via SCM
  ${If} $UNINS_HTTP_OK != 1
    Sleep 400
  ${EndIf}
  ${If} $UNINS_DNS_OK != 1
    Sleep 400
  ${EndIf}

  ; Legacy HTTP service name (older builds) — only if HTTP uninstall failed
  ${If} $UNINS_HTTP_OK != 1
    nsExec::ExecToStack 'sc.exe stop homehttp'
    Pop $0
    Pop $1
    DetailPrint "sc stop homehttp => rc=$0 out=$1"
    StrCmp $LOG_HANDLE "" +2
    FileWrite $LOG_HANDLE "sc stop homehttp => rc=$0 out=$1$\r$\n"
  ${EndIf}

  ; Best-effort: restore DNS settings explicitly (service also restores on stop)
  ${If} ${FileExists} "$INSTDIR\bin\home-dns.exe"
    nsExec::ExecToStack '"$INSTDIR\bin\home-dns.exe" restore'
    Pop $0
    Pop $1
    DetailPrint "home-dns.exe restore => rc=$0 out=$1"
    StrCmp $LOG_HANDLE "" +2
    FileWrite $LOG_HANDLE "home-dns.exe restore => rc=$0 out=$1$\r$\n"
  ${EndIf}

  ; Fallback deletion only if the uninstaller failed or binary is missing
  ${If} $UNINS_HTTP_OK != 1
    DetailPrint "Deleting HomeHttpService (fallback)..."
    nsExec::ExecToStack 'sc.exe delete HomeHttpService'
    Pop $0
    Pop $1
    DetailPrint "sc delete HomeHttpService => rc=$0 out=$1"
    StrCmp $LOG_HANDLE "" +2
    FileWrite $LOG_HANDLE "sc delete HomeHttpService => rc=$0 out=$1$\r$\n"
    ; Legacy cleanup
    nsExec::ExecToStack 'sc.exe delete homehttp'
    Pop $0
    Pop $1
    DetailPrint "sc delete homehttp => rc=$0 out=$1"
    StrCmp $LOG_HANDLE "" +2
    FileWrite $LOG_HANDLE "sc delete homehttp => rc=$0 out=$1$\r$\n"
  ${EndIf}

  ${If} $UNINS_DNS_OK != 1
    DetailPrint "Deleting HomeDnsService (fallback)..."
    nsExec::ExecToStack 'sc.exe delete HomeDnsService'
    Pop $0
    Pop $1
    DetailPrint "sc delete HomeDnsService => rc=$0 out=$1"
    StrCmp $LOG_HANDLE "" +2
    FileWrite $LOG_HANDLE "sc delete HomeDnsService => rc=$0 out=$1$\r$\n"
  ${EndIf}
!macroend


