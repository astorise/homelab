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
  nsExec::Exec '"$INSTDIR\\home-dns.exe" install'
  nsExec::Exec '"$INSTDIR\\home-proxy.exe" install'
    ; Exécution après installation
  ; Forcer l’élévation (si pas déjà perMachine)
  ; et lancer WSL sans distribution
  nsExec::ExecToLog 'powershell -ExecutionPolicy Bypass -Command "wsl --install --no-distribution"'
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  nsExec::Exec '"$INSTDIR\\home-dns.exe" uninstall'
  nsExec::Exec '"$INSTDIR\\home-proxy.exe" uninstall'
!macroend


