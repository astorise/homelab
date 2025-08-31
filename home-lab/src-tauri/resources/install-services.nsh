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
  nsExec::ExecToStack '"$INSTDIR\\home-dns.exe" install'
  Pop $0
  Pop $1
  DetailPrint "home-dns.exe install => rc=$0 out=$1"
  nsExec::ExecToStack '"$INSTDIR\\home-http.exe" install'
  Pop $0
  Pop $1
  DetailPrint "home-http.exe install => rc=$0 out=$1"
    ; Exécution après installation
  ; Forcer l’élévation (si pas déjà perMachine)
  ; et lancer WSL sans distribution
  nsExec::ExecToLog 'powershell -ExecutionPolicy Bypass -Command "wsl --install --no-distribution"'
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  DetailPrint "Uninstalling Windows services..."
  nsExec::ExecToStack '"$INSTDIR\\home-dns.exe" uninstall'
  Pop $0
  Pop $1
  DetailPrint "home-dns.exe uninstall => rc=$0 out=$1"
  nsExec::ExecToStack '"$INSTDIR\\home-http.exe" uninstall'
  Pop $0
  Pop $1
  DetailPrint "home-http.exe uninstall => rc=$0 out=$1"
!macroend


