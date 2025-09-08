; Optional: force showing the details view and start a simple file log
Var LOG_FILE
Var LOG_HANDLE

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
  nsExec::ExecToStack 'sc.exe start homehttp'
  Pop $0
  Pop $1
  DetailPrint "sc start homehttp => rc=$0 out=$1"
  StrCmp $LOG_HANDLE "" +2
  FileWrite $LOG_HANDLE "sc start homehttp => rc=$0 out=$1$\r$\n"
    ; Exécution après installation
  ; Forcer l’élévation (si pas déjà perMachine)
  ; et lancer WSL sans distribution
  nsExec::ExecToLog 'powershell -ExecutionPolicy Bypass -Command "wsl --install --no-distribution"'
  ; Close log file if opened
  StrCmp $LOG_HANDLE "" +2
  FileClose $LOG_HANDLE
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  DetailPrint "Uninstalling Windows services..."
  nsExec::ExecToStack '"$INSTDIR\bin\home-dns.exe" uninstall'
  Pop $0
  Pop $1
  DetailPrint "home-dns.exe uninstall => rc=$0 out=$1"
  StrCmp $LOG_HANDLE "" +2
  FileWrite $LOG_HANDLE "home-dns.exe uninstall => rc=$0 out=$1$\r$\n"
  nsExec::ExecToStack '"$INSTDIR\bin\home-http.exe" uninstall'
  Pop $0
  Pop $1
  DetailPrint "home-http.exe uninstall => rc=$0 out=$1"
  StrCmp $LOG_HANDLE "" +2
  FileWrite $LOG_HANDLE "home-http.exe uninstall => rc=$0 out=$1$\r$\n"
  StrCmp $LOG_HANDLE "" +2
  FileClose $LOG_HANDLE
!macroend


