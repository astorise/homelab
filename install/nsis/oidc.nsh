!macro OIDC_SETUP_POSTINSTALL
  DetailPrint "Configuring OIDC provider..."
  nsExec::ExecToStack '"$INSTDIR\\bin\\setup-oidc.exe"'
  Pop $0
  Pop $1
  DetailPrint "setup-oidc.exe => rc=$0 out=$1"
  StrCmp $LOG_HANDLE "" +2
  FileWrite $LOG_HANDLE "setup-oidc.exe => rc=$0 out=$1$\r$\n"
!macroend

!macro OIDC_SETUP_PREUNINSTALL
  DetailPrint "Stopping oidc-service..."
  nsExec::ExecToStack 'sc.exe stop oidc-service'
  Pop $0
  Pop $1
  DetailPrint "sc stop oidc-service => rc=$0 out=$1"
  StrCmp $LOG_HANDLE "" +2
  FileWrite $LOG_HANDLE "sc stop oidc-service => rc=$0 out=$1$\r$\n"
  DetailPrint "Deleting oidc-service..."
  nsExec::ExecToStack 'sc.exe delete oidc-service'
  Pop $0
  Pop $1
  DetailPrint "sc delete oidc-service => rc=$0 out=$1"
  StrCmp $LOG_HANDLE "" +2
  FileWrite $LOG_HANDLE "sc delete oidc-service => rc=$0 out=$1$\r$\n"
!macroend
