; NSIS installer for the Rust simplewall port.
; Filters stay installed after uninstall. Remove them in the app first.

Unicode true
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "x64.nsh"

Icon "simplewall.ico"
UninstallIcon "simplewall.ico"

!ifndef VERSION
  !define VERSION "3.9.2"
!endif

Name "simplewall"
OutFile "..\dist\simplewall-${VERSION}-setup.exe"
InstallDir "$PROGRAMFILES64\simplewall"
InstallDirRegKey HKLM "Software\simplewall" "InstallDir"

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  ${If} ${RunningX64}
    SetRegView 64
  ${EndIf}

  SetOutPath "$INSTDIR"
  File "payload\simplewall.exe"
  File "payload\simplewall.exe.manifest"
  File "payload\simplewall.ico"
  File "payload\LICENSE"
  File "payload\README.md"

  WriteUninstaller "$INSTDIR\uninstall.exe"

  WriteRegStr HKLM "Software\simplewall" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\simplewall" "DisplayName" "simplewall"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\simplewall" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\simplewall" "Publisher" "simplewall Rust port"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\simplewall" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\simplewall" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\simplewall" "DisplayIcon" "$INSTDIR\simplewall.ico"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\simplewall" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\simplewall" "NoRepair" 1

  CreateDirectory "$SMPROGRAMS\simplewall"
  CreateShortcut "$SMPROGRAMS\simplewall\simplewall.lnk" "$INSTDIR\simplewall.exe" "" "$INSTDIR\simplewall.ico"
  CreateShortcut "$SMPROGRAMS\simplewall\Uninstall simplewall.lnk" "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
  ${If} ${RunningX64}
    SetRegView 64
  ${EndIf}

  Delete "$INSTDIR\simplewall.exe"
  Delete "$INSTDIR\simplewall.exe.manifest"
  Delete "$INSTDIR\simplewall.ico"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\simplewall\simplewall.lnk"
  Delete "$SMPROGRAMS\simplewall\Uninstall simplewall.lnk"
  RMDir "$SMPROGRAMS\simplewall"

  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\simplewall"
  DeleteRegKey HKLM "Software\simplewall"
SectionEnd
