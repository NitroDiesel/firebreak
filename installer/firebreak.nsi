; NSIS installer for Firebreak, the Rust port of simplewall by Henry++.
; It installs beside the original simplewall, never over it: its own folder,
; uninstall entry, and Start menu shortcut. Filters stay installed after
; uninstall. Turn filtering off in the app first.

Unicode true
RequestExecutionLevel admin
SetCompressor /SOLID lzma
ManifestDPIAware true

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"

!ifndef VERSION
  !define VERSION "4.0.0"
!endif

!define NAME "Firebreak"
!define PUBLISHER "NitroDiesel"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\Firebreak"
!define TRAY_CLASS "firebreak-tray"
; Before the rename to Firebreak (4.0) this was "simplewall (Rust)". 3.9.4 used
; its own folder and key; 3.9.3 and older used the original's.
!define LEGACY_TRAY_CLASS "simplewall-rust-tray"
!define LEGACY_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\simplewall-rust"
!define LEGACY_PUBLISHER "NitroDiesel"
!define OLDER_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\simplewall"
!define OLDER_PUBLISHER "simplewall Rust port"

Name "${NAME}"
OutFile "..\dist\firebreak-${VERSION}-setup.exe"
InstallDir "$PROGRAMFILES64\Firebreak"
InstallDirRegKey HKLM "Software\Firebreak" "InstallDir"
BrandingText "${NAME} ${VERSION}"
Icon "firebreak.ico"
UninstallIcon "firebreak.ico"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${NAME}"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "FileDescription" "${NAME} setup"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "GPL-3.0. Based on simplewall by Henry++"

!define MUI_ABORTWARNING
!define MUI_ICON "firebreak.ico"
!define MUI_UNICON "firebreak.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "welcome.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "welcome.bmp"
!define MUI_WELCOMEPAGE_TEXT "Setup will install ${NAME} ${VERSION}, a firewall based on simplewall by Henry++.$\r$\n$\r$\nIf ${NAME} or simplewall (Rust) is running, Setup closes it first. Installed filters stay on the whole time, and your settings carry over.$\r$\n$\r$\nThe original simplewall is left as it is.$\r$\n$\r$\nClick Next to continue."
!define MUI_FINISHPAGE_RUN "$INSTDIR\firebreak.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Start ${NAME}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "payload\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

; Ask a running copy to quit, then end the process that owns its tray window if
; it has not exited after five seconds. 3.9.3 and older only drop the tray icon
; on this request, so wait on the process, not the window.
!macro CloseRunning CLASS
  FindWindow $0 "${CLASS}"
  ${If} $0 <> 0
    System::Call "user32::GetWindowThreadProcessId(p r0, *i .r1)"
    ; SYNCHRONIZE | PROCESS_TERMINATE
    System::Call "kernel32::OpenProcess(i 0x100001, i 0, i r1) p .r3"
    SendMessage $0 ${WM_CLOSE} 0 0 /TIMEOUT=2000
    ${If} $3 P<> 0
      System::Call "kernel32::WaitForSingleObject(p r3, i 5000) i .r4"
      ${If} $4 <> 0
        System::Call "kernel32::TerminateProcess(p r3, i 0)"
        System::Call "kernel32::WaitForSingleObject(p r3, i 5000)"
      ${EndIf}
      System::Call "kernel32::CloseHandle(p r3)"
    ${EndIf}
  ${EndIf}
!macroend

; Remove a simplewall (Rust) install found under KEY with PUBLISHER. Its own
; uninstaller is not run: 3.9.4's deletes the startup and skip-UAC tasks, which
; Firebreak carries over on its first start.
!macro RemoveLegacy KEY PUBLISHER
  ReadRegStr $4 HKLM "${KEY}" "Publisher"
  ReadRegStr $6 HKLM "${KEY}" "DisplayName"
  ${If} $4 == "${PUBLISHER}"
  ${AndIf} $6 != "${NAME}"
    ReadRegStr $5 HKLM "${KEY}" "InstallLocation"
    ${If} $5 != ""
    ${AndIf} ${FileExists} "$5\simplewall.exe"
      DetailPrint "Removing simplewall (Rust) from $5"
      Delete "$5\simplewall.exe"
      Delete "$5\simplewall.exe.manifest"
      Delete "$5\simplewall.ico"
      Delete "$5\LICENSE"
      Delete "$5\README.md"
      Delete "$5\uninstall.exe"
      RMDir "$5"
    ${EndIf}
    DeleteRegKey HKLM "${KEY}"
  ${EndIf}
!macroend

Function .onInit
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Function un.onInit
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Section "Install"
  !insertmacro CloseRunning "${TRAY_CLASS}"
  !insertmacro CloseRunning "${LEGACY_TRAY_CLASS}"

  !insertmacro RemoveLegacy "${LEGACY_KEY}" "${LEGACY_PUBLISHER}"
  !insertmacro RemoveLegacy "${OLDER_KEY}" "${OLDER_PUBLISHER}"
  DeleteRegKey HKLM "Software\simplewall-rust"
  Delete "$SMPROGRAMS\simplewall (Rust).lnk"
  ; 3.9.3 and older put their shortcuts in the installing user's Start menu.
  SetShellVarContext current
  Delete "$SMPROGRAMS\simplewall\simplewall.lnk"
  Delete "$SMPROGRAMS\simplewall\Uninstall simplewall.lnk"
  RMDir "$SMPROGRAMS\simplewall"
  SetShellVarContext all

  SetOutPath "$INSTDIR"
  File "payload\firebreak.exe"
  File "payload\firebreak.ico"
  File "payload\LICENSE"
  File "payload\README.md"

  WriteUninstaller "$INSTDIR\uninstall.exe"

  WriteRegStr HKLM "Software\Firebreak" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "${NAME}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "URLInfoAbout" "https://github.com/NitroDiesel/firebreak"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINSTALL_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\firebreak.exe"
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1

  CreateShortcut "$SMPROGRAMS\${NAME}.lnk" "$INSTDIR\firebreak.exe"
SectionEnd

Section "Uninstall"
  !insertmacro CloseRunning "${TRAY_CLASS}"

  ; The startup and skip-UAC tasks would point at a missing file. The old names
  ; are there if Firebreak was never started after an upgrade.
  nsExec::Exec 'schtasks.exe /Delete /TN "Firebreak" /F'
  nsExec::Exec 'schtasks.exe /Delete /TN "Firebreak-SkipUAC" /F'
  nsExec::Exec 'schtasks.exe /Delete /TN "simplewall-rust" /F'
  nsExec::Exec 'schtasks.exe /Delete /TN "simplewall-rust-skipuac" /F'

  Delete "$INSTDIR\firebreak.exe"
  Delete "$INSTDIR\firebreak.ico"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\${NAME}.lnk"

  DeleteRegKey HKLM "${UNINSTALL_KEY}"
  DeleteRegKey HKLM "Software\Firebreak"
SectionEnd
