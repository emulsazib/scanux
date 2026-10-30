; Scanu installer hooks (Tauri NSIS). Installs/updates the ScanuSensor Windows
; service that ships next to the app as a sidecar (scanu-sensor.exe).

!macro NSIS_HOOK_PREINSTALL
  ; Upgrade: stop the running sensor so its binary can be replaced.
  nsExec::ExecToLog '"$SYSDIR\sc.exe" stop ScanuSensor'
  Sleep 3000
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ReadEnvStr $0 PROGRAMDATA
  CreateDirectory "$0\Scanu\data"
  CreateDirectory "$0\Scanu\logs"
  ; Only SYSTEM and Administrators may read the sensor's state (vault, spool, keys).
  nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$0\Scanu" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F'
  nsExec::ExecToLog '"$SYSDIR\sc.exe" create ScanuSensor binPath= "\"$INSTDIR\scanu-sensor.exe\"" start= auto obj= LocalSystem DisplayName= "Scanu Sensor"'
  nsExec::ExecToLog '"$SYSDIR\sc.exe" config ScanuSensor binPath= "\"$INSTDIR\scanu-sensor.exe\"" start= auto'
  nsExec::ExecToLog '"$SYSDIR\sc.exe" description ScanuSensor "Scanu endpoint protection: detects, freezes and scans for threats."'
  nsExec::ExecToLog '"$SYSDIR\sc.exe" failure ScanuSensor reset= 86400 actions= restart/5000/restart/5000/restart/30000'
  nsExec::ExecToLog '"$SYSDIR\sc.exe" start ScanuSensor'
  ; Start the tray app for every user at sign-in.
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "Scanu" '"$INSTDIR\Scanu.exe"'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToLog '"$SYSDIR\sc.exe" stop ScanuSensor'
  Sleep 3000
  nsExec::ExecToLog '"$SYSDIR\sc.exe" delete ScanuSensor'
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "Scanu"
  ; C:\ProgramData\Scanu is intentionally kept: it holds the quarantine vault
  ; (files you may want to restore) and logs. Delete it manually if you want.
!macroend
