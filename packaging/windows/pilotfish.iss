; Inno Setup script. Build with: ISCC /DAppVersion=0.1.0 /DExePath=C:\path\to\pilotfish.exe packaging\windows\pilotfish.iss
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

#ifndef ExePath
  #define ExePath "..\..\target\x86_64-pc-windows-msvc\release\pilotfish.exe"
#endif

[Setup]
AppId={{E7E4F40C-7177-4CFD-92C6-BD7FF9858297}}
AppName=pilotfish
AppVersion={#AppVersion}
AppPublisher=anyhowfeel
AppPublisherURL=https://github.com/anyhowfeel/pilotfish
DefaultDirName={autopf}\pilotfish
DefaultGroupName=pilotfish
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE
SetupIconFile=..\..\assets\logo\pilotfish.ico
UninstallDisplayIcon={app}\pilotfish.exe
OutputDir=..\..\dist
OutputBaseFilename=pilotfish-{#AppVersion}-windows-x86_64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
UninstallDisplayName=pilotfish

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "{#ExePath}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\pilotfish"; Filename: "{app}\pilotfish.exe"
Name: "{autodesktop}\pilotfish"; Filename: "{app}\pilotfish.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\pilotfish.exe"; Description: "Launch pilotfish"; Flags: nowait postinstall skipifsilent

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
  if not FileExists(ExpandConstant('{commonpf64}\Wireshark\tshark.exe')) then
    MsgBox('Wireshark (tshark) was not found in its default folder. pilotfish needs it to read ' +
           'captures; install it from https://www.wireshark.org and make sure tshark is on PATH.',
           mbInformation, MB_OK);
end;
