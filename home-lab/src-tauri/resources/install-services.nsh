!macro NSIS_HOOK_POSTINSTALL
  nsExec::Exec '"$INSTDIR\\home-dns.exe" install'
  nsExec::Exec '"$INSTDIR\\home-proxy.exe" install'
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  nsExec::Exec '"$INSTDIR\\home-dns.exe" uninstall'
  nsExec::Exec '"$INSTDIR\\home-proxy.exe" uninstall'
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Exécution après installation
  ; Forcer l’élévation (si pas déjà perMachine)
  ; et lancer WSL sans distribution
  nsExec::ExecToLog 'powershell -ExecutionPolicy Bypass -Command "wsl --install --no-distribution"'
!macroend
