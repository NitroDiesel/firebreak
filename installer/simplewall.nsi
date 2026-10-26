; NSIS installer for simplewall (Rust).
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
  !define VERSION "3.9.4"
!endif

!define NAME "simplewall (Rust)"
!define PUBLISHER "NitroDiesel"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\simplewall-rust"
; 3.9.3 and older installed into the original's folder under the original's key.
!define OLD_UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\simplewall"
!define OLD_PUBLISHER "simplewall Rust port"
!define TRAY_CLASS "simplewall-rust-tray"

Name "${NAME}"
OutFile "..\dist\simplewall-${VERSION}-setup.exe"
InstallDir "$PROGRAMFILES64\simplewall-rust"
InstallDirRegKey HKLM "Software\simplewall-rust" "InstallDir"
BrandingText "${NAME} ${VERSION}"
Icon "simplewall.ico"
UninstallIcon "simplewall.ico"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${NAME}"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "FileDescription" "${NAME} setup"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "GPL-3.0"

!define MUI_ABORTWARNING
!define MUI_ICON "simplewall.ico"
!define MUI_UNICON "simplewall.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "welcome.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "welcome.bmp"
!define MUI_WELCOMEPAGE_TEXT "Setup will install ${NAME} ${VERSION}.$\r$\n$\r$\nIf ${NAME} is running, Setup closes it first. Installed filters stay on the whole time.$\r$\n$\r$\nThe original simplewall is left as it is.$\r$\n$\r$\nClick Next to continue."
!define MUI_FINISHPAGE_RUN "$INSTDIR\simplewall.exe"
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
!macro CloseRunning
  FindWindow $0 "${TRAY_CLASS}"
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

Function .onInit
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Function un.onInit
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Section "Install"
  !insertmacro CloseRunning

  ; Remove a 3.9.3-or-older install of this port from the original's folder.
  ReadRegStr $4 HKLM "${OLD_UNINSTALL_KEY}" "Publisher"
  ${If} $4 == "${OLD_PUBLISHER}"
    ReadRegStr $5 HKLM "${OLD_UNINSTALL_KEY}" "InstallLocation"
    ${If} ${FileExists} "$5\uninstall.exe"
      DetailPrint "Removing simplewall (Rust) from $5"
      ExecWait '"$5\uninstall.exe" /S _?=$5'
      Delete "$5\uninstall.exe"
      RMDir "$5"
    ${EndIf}
    DeleteRegKey HKLM "${OLD_UNINSTALL_KEY}"
    DeleteRegKey HKLM "Software\simplewall"
  ${EndIf}

  SetOutPath "$INSTDIR"
  File "payload\simplewall.exe"
  File "payload\simplewall.ico"
  File "payload\LICENSE"
  File "payload\README.md"
  ; Older builds shipped an external manifest that demanded elevation.
  Delete "$INSTDIR\simplewall.exe.manifest"

  WriteUninstaller "$INSTDIR\uninstall.exe"

  WriteRegStr HKLM "Software\simplewall-rust" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "${NAME}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "URLInfoAbout" "https://github.com/NitroDiesel/simplewall"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINSTALL_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\simplewall.exe"
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1

  CreateShortcut "$SMPROGRAMS\${NAME}.lnk" "$INSTDIR\simplewall.exe"
SectionEnd

Section "Uninstall"
  !insertmacro CloseRunning

  ; The startup and skip-UAC tasks would point at a missing file.
  nsExec::Exec 'schtasks.exe /Delete /TN "simplewall-rust" /F'
  nsExec::Exec 'schtasks.exe /Delete /TN "simplewall-rust-skipuac" /F'

  Delete "$INSTDIR\simplewall.exe"
  Delete "$INSTDIR\simplewall.ico"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\${NAME}.lnk"

  DeleteRegKey HKLM "${UNINSTALL_KEY}"
  DeleteRegKey HKLM "Software\simplewall-rust"
SectionEnd
