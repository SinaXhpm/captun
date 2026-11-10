; Captun's additions to Tauri's NSIS installer (tauri.conf.json: bundle >
; windows > nsis > installerHooks). Captun installs for all users, in
; Program Files by default: its service runs with administrator rights and
; runs the programs beside it (xray.exe, WinDivert.dll), so only
; administrators may change that folder. These hooks make sure of it, for a
; folder chosen by hand too.

!define CAPTUN_STOP_PER_USER "An older Captun is installed for this user only. Remove it in Settings > Apps > Installed apps, then run this installer again."
!define CAPTUN_STOP_EARLIER_PER_USER "An older version (OmniHub) is installed for this user only. Remove it in Settings > Apps > Installed apps, then run this installer again."

; Where a copy installed for one user only keeps its entry in Installed apps:
; Tauri's installer writes HKCU\${UNINSTKEY}, which is this key with the
; product name at the end. Captun was called OmniHub before, so a copy from
; then is found under that name.
!define CAPTUN_EARLIER_UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\OmniHub"
!define CAPTUN_STOP_FOLDER "Choose an empty folder for Captun, or the folder it is already installed in. Only administrators will be able to change it."
!define CAPTUN_STOP_LOCK "Captun could not make its folder changeable by administrators only, so it was not installed. Run this installer again, or choose another folder."
!define CAPTUN_STOP_FILES "Captun could not make its files changeable by administrators only. Remove it in Settings > Apps > Installed apps, then run this installer again."
!define CAPTUN_WARN_USB_DRIVER "Captun is installed, but its USB driver for Android phones could not be installed. Everything else works. If a phone does not show under USB to phone, install the USB driver from the phone maker's website."

; The folder's owner and permissions, set as one whole: Administrators own
; it; SYSTEM and Administrators may do anything, Users may read and run;
; whoever owns a file gets no more than that (OW), so a file is safe even
; before its owner is set; nothing comes from the folder above (P).
!define CAPTUN_FOLDER_SDDL "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;OW)"

; Says why the install stops, then stops it. A silent install has no window,
; so the reason goes to the console it was started from.
!macro CAPTUN_STOP message
  ${If} ${Silent}
    System::Call 'kernel32::AttachConsole(i -1) i .r0'
    ${If} $0 <> 0
      System::Call 'kernel32::GetStdHandle(i -11) p .r0'
      FileWrite $0 "${message}$\r$\n"
    ${EndIf}
  ${Else}
    MessageBox MB_ICONSTOP|MB_OK "${message}"
  ${EndIf}
  Abort "${message}"
!macroend

; Says what went wrong without stopping the install, in the installer's log
; and, as CAPTUN_STOP does, in a window or on the console. A passive install
; (/P, as the app's own updates run) gets no window that waits for a click:
; there it goes to the log and the console only. $PassiveMode is Tauri's.
; Changes $0.
!macro CAPTUN_WARN message
  DetailPrint "${message}"
  ${If} ${Silent}
  ${OrIf} $PassiveMode = 1
    System::Call 'kernel32::AttachConsole(i -1) i .r0'
    ${If} $0 <> 0
      System::Call 'kernel32::GetStdHandle(i -11) p .r0'
      FileWrite $0 "${message}$\r$\n"
    ${EndIf}
  ${Else}
    MessageBox MB_ICONEXCLAMATION|MB_OK "${message}"
  ${EndIf}
!macroend

; The same, first removing the folder if it is empty: the installer made it
; just before the hooks run. Only for a folder known not to be a link.
!macro CAPTUN_STOP_AND_TIDY message
  SetOutPath "$TEMP"
  RMDir "$INSTDIR"
  !insertmacro CAPTUN_STOP "${message}"
!macroend

; Stops the install, as CAPTUN_STOP_AND_TIDY, if the entry in Installed apps
; under HKCU\`key` names an uninstaller that is still there. Tauri's
; installer writes it in quotes ("<folder>\uninstall.exe"). An entry whose
; uninstaller is gone (its folder was deleted by hand) cannot be removed in
; Settings either, so it is left alone and does not stop the install. Keeps
; $R0 and $R1.
!macro CAPTUN_STOP_IF_INSTALLED key message
  Push $R0
  Push $R1
  ReadRegStr $R0 HKCU "${key}" "UninstallString"
  StrCpy $R1 $R0 1
  ${If} $R1 == '"'
    StrCpy $R1 $R0 "" -1
    ${If} $R1 == '"'
      StrCpy $R0 $R0 -1 1
    ${EndIf}
  ${EndIf}
  ${If} $R0 != ""
  ${AndIf} ${FileExists} "$R0"
    Pop $R1
    Pop $R0
    !insertmacro CAPTUN_STOP_AND_TIDY "${message}"
  ${EndIf}
  Pop $R1
  Pop $R0
!macroend

; Gives $INSTDIR the owner and permissions of CAPTUN_FOLDER_SDDL in one
; call, which also passes them on to whatever is inside. Sets `result` to 0
; on success (a Windows error code otherwise); keeps $R0-$R4.
!macro CAPTUN_LOCK_FOLDER result
  Push $R0
  Push $R1
  Push $R2
  Push $R3
  Push $R4
  StrCpy $R4 "$INSTDIR"
  StrCpy ${result} 1
  ; SDDL_REVISION_1 = 1
  System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w "${CAPTUN_FOLDER_SDDL}", i 1, *p .R0, p 0) i .R1'
  ${If} $R1 <> 0
    System::Call 'advapi32::GetSecurityDescriptorOwner(p R0, *p .R2, *i .R1) i .R1'
    ${If} $R1 <> 0
      System::Call 'advapi32::GetSecurityDescriptorDacl(p R0, *i .R1, *p .R3, *i .R1) i .R1'
      ${If} $R1 <> 0
        ; SE_FILE_OBJECT = 1; OWNER (1) | DACL (4) | PROTECTED_DACL (0x80000000)
        System::Call 'advapi32::SetNamedSecurityInfoW(w R4, i 1, i 0x80000005, p R2, p 0, p R3, p 0) i .R1'
        StrCpy ${result} $R1
      ${EndIf}
    ${EndIf}
    System::Call 'kernel32::LocalFree(p R0)'
  ${EndIf}
  Pop $R4
  Pop $R3
  Pop $R2
  Pop $R1
  Pop $R0
!macroend

; Makes $INSTDIR with the owner and permissions of CAPTUN_FOLDER_SDDL from
; the moment it exists. Sets `result` (not one of $R0-$R3, which it keeps)
; to 0 on success, 1 otherwise: it fails if anything is already there.
!macro CAPTUN_CREATE_FOLDER result
  Push $R0
  Push $R1
  Push $R2
  Push $R3
  StrCpy $R3 "$INSTDIR"
  StrCpy ${result} 1
  ; SDDL_REVISION_1 = 1
  System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w "${CAPTUN_FOLDER_SDDL}", i 1, *p .R0, p 0) i .R1'
  ${If} $R1 <> 0
    ; SECURITY_ATTRIBUTES { size, descriptor, not inherited }, laid out as
    ; Windows expects for this installer's pointer size.
    !if ${NSIS_PTR_SIZE} > 4
      System::Call '*(i 24, i 0, p R0, i 0, i 0) p .R2'
    !else
      System::Call '*(i 12, p R0, i 0) p .R2'
    !endif
    System::Call 'kernel32::CreateDirectoryW(w R3, p R2) i .R1'
    ${If} $R1 <> 0
      StrCpy ${result} 0
    ${EndIf}
    System::Free $R2
    System::Call 'kernel32::LocalFree(p R0)'
  ${EndIf}
  Pop $R3
  Pop $R2
  Pop $R1
  Pop $R0
!macroend

; Sets `result` (not one of $R0-$R3, which it keeps) to 1 if SYSTEM or
; Administrators own $INSTDIR, else 0.
!macro CAPTUN_OWNED_BY_ADMINS result
  Push $R0
  Push $R1
  Push $R2
  Push $R3
  StrCpy $R3 "$INSTDIR"
  StrCpy $R2 0
  ; SE_FILE_OBJECT = 1; OWNER_SECURITY_INFORMATION = 1
  System::Call 'advapi32::GetNamedSecurityInfoW(w R3, i 1, i 1, *p .R0, p 0, p 0, p 0, *p .R1) i .R3'
  ${If} $R3 = 0
    ; WinBuiltinAdministratorsSid = 26, WinLocalSystemSid = 22
    System::Call 'advapi32::IsWellKnownSid(p R0, i 26) i .R2'
    ${If} $R2 = 0
      System::Call 'advapi32::IsWellKnownSid(p R0, i 22) i .R2'
    ${EndIf}
    System::Call 'kernel32::LocalFree(p R1)'
  ${EndIf}
  ${If} $R2 <> 0
    StrCpy ${result} 1
  ${Else}
    StrCpy ${result} 0
  ${EndIf}
  Pop $R3
  Pop $R2
  Pop $R1
  Pop $R0
!macroend

!macro NSIS_HOOK_PREINSTALL
  Push $0
  Push $1
  Push $2

  ; 1. The folder becomes administrators-only, so it must be a folder of its
  ;    own: not a whole drive, and not a link to a folder somewhere else (its
  ;    maker could point it at another folder later).
  StrCpy $0 "$INSTDIR" "" -1
  ${If} $0 == "\"
    !insertmacro CAPTUN_STOP "${CAPTUN_STOP_FOLDER}"
  ${EndIf}
  StrCpy $1 "$INSTDIR"
  ; FILE_ATTRIBUTE_REPARSE_POINT = 0x400
  System::Call 'kernel32::GetFileAttributesW(w r1) i .r0'
  ${If} $0 <> -1
    IntOp $0 $0 & 0x400
    ${If} $0 <> 0
      !insertmacro CAPTUN_STOP "${CAPTUN_STOP_FOLDER}"
    ${EndIf}
  ${EndIf}

  ; 2. An older Captun installed for this user only (Tauri's default until
  ;    now) runs from a folder any of the user's programs can change, and its
  ;    shortcuts would keep starting it. Its uninstaller is not run from here:
  ;    any such program could have replaced it, and this installer runs as
  ;    administrator.
  !insertmacro CAPTUN_STOP_IF_INSTALLED "${UNINSTKEY}" "${CAPTUN_STOP_PER_USER}"
  ;    The same for OmniHub, as Captun was called before, installed for this
  ;    user only: it would keep running from that folder beside this copy.
  !insertmacro CAPTUN_STOP_IF_INSTALLED "${CAPTUN_EARLIER_UNINSTKEY}" "${CAPTUN_STOP_EARLIER_PER_USER}"

  ; 3. It must hold nothing but Captun: empty, or an earlier Captun, which
  ;    this installer gave to Administrators. A folder another account made
  ;    is still theirs, and anything they put in it would stay (a library
  ;    beside the service would run with its rights).
  ${DirState} "$INSTDIR" $2
  ${If} $2 = 1
    ${IfNot} ${FileExists} "$INSTDIR\${MAINBINARYNAME}.exe"
      !insertmacro CAPTUN_STOP "${CAPTUN_STOP_FOLDER}"
    ${EndIf}
    !insertmacro CAPTUN_OWNED_BY_ADMINS $0
    ${If} $0 <> 1
      !insertmacro CAPTUN_STOP "${CAPTUN_STOP_FOLDER}"
    ${EndIf}
  ${EndIf}

  ; 4. An empty folder (usually one the installer has just made) is deleted
  ;    and made again, administrators-only from the moment it exists.
  ;    Windows checks rights only when something is opened: whoever made an
  ;    empty folder beforehand could keep it open with the right to change
  ;    its permissions, or to rename it, whatever is set on it later. Such a
  ;    handle makes the delete fail, or leaves its holder with a folder that
  ;    is gone; and making it again fails if anyone made it meanwhile.
  ${If} $2 <> 1
    SetOutPath "$TEMP"
    RMDir "$INSTDIR"
    !insertmacro CAPTUN_CREATE_FOLDER $1
    ${If} $1 <> 0
      !insertmacro CAPTUN_STOP "${CAPTUN_STOP_LOCK}"
    ${EndIf}
    SetOutPath "$INSTDIR"
  ${EndIf}

  ; 5. Locked before anything is copied in, and in one step: owner and
  ;    permissions are replaced as a whole, so nothing someone else put on a
  ;    folder they made beforehand survives.
  !insertmacro CAPTUN_LOCK_FOLDER $1
  ${If} $1 <> 0
    !insertmacro CAPTUN_STOP_AND_TIDY "${CAPTUN_STOP_LOCK}"
  ${EndIf}

  ; 6. A folder that was empty (made again above) must still be: anything
  ;    that came in before the lock is not Captun's.
  ${If} $2 <> 1
    ${DirState} "$INSTDIR" $0
    ${If} $0 <> 0
      !insertmacro CAPTUN_STOP "${CAPTUN_STOP_FOLDER}"
    ${EndIf}
  ${EndIf}

  Pop $2
  Pop $1
  Pop $0
!macroend

!macro NSIS_HOOK_POSTINSTALL
  Push $0
  ; Administrators own every file, so no one else holds an owner's rights to
  ; one. Without /C: with it, icacls reports success even when a file failed.
  nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$INSTDIR" /setowner *S-1-5-32-544 /T /Q'
  Pop $0
  ${If} $0 == "0"
    ; SYSTEM and Administrators may do anything, Users may read and run, and
    ; nothing comes from the folder above, as locked before the copy. The
    ; owner-rights entry goes once the owner has changed; files owned by
    ; Administrators need none.
    nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$INSTDIR" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F /grant:r *S-1-5-32-544:(OI)(CI)F /grant:r *S-1-5-32-545:(OI)(CI)RX /Q'
    Pop $0
  ${EndIf}
  ${If} $0 != "0"
    !insertmacro CAPTUN_STOP "${CAPTUN_STOP_FILES}"
  ${EndIf}

  ; Captun's USB driver for Android phones, for USB to phone: Windows' own
  ; WinUSB for a phone's USB debugging interface, signed on this computer
  ; with a certificate made for it alone, whose key is destroyed once it has
  ; signed (see docs/ARCHITECTURE.md). Run from the folder locked above.
  ; Without it only phones with a driver of their own work, so a failure
  ; warns and the install goes on.
  nsExec::ExecToLog '"$INSTDIR\captun-daemon.exe" --install-usb-driver'
  Pop $0
  ${If} $0 != "0"
    !insertmacro CAPTUN_WARN "${CAPTUN_WARN_USB_DRIVER}"
  ${EndIf}
  Pop $0
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; Tauri asks to close a running Captun only after this hook. Asked here
  ; first, so whoever cancels at that question keeps Captun and its driver
  ; whole. Changes $R0-$R3 and $0-$3, which Tauri's own check after this
  ; changes too.
  !insertmacro CheckIfAppIsRunning "$INSTDIR\${MAINBINARYNAME}.exe" "${PRODUCTNAME}"
  Push $0
  ; The USB driver for phones and the certificate it was signed with go
  ; first, while the service that knows what it installed is still here.
  ; Nothing to tell anyone if they were never installed. An update
  ; (/UPDATE) keeps them, as it keeps the shortcuts.
  ${If} $UpdateMode <> 1
    nsExec::ExecToLog '"$INSTDIR\captun-daemon.exe" --remove-usb-driver'
    Pop $0
    ${If} $0 != "0"
      DetailPrint "Captun could not remove its USB driver for Android phones."
    ${EndIf}
  ${EndIf}
  Pop $0
!macroend
