; Inno Setup script. Build with: ISCC /DAppVersion=0.1.0 packaging\windows\wirelens.iss
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{E7E4F40C-7177-4CFD-92C6-BD7FF9858297}}
AppName=wirelens
AppVersion={#AppVersion}
AppPublisher=anyhowfeel
AppPublisherURL=https://github.com/anyhowfeel/wirelens
DefaultDirName={autopf}\wirelens
DefaultGroupName=wirelens
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE
SetupIconFile=..\..\assets\logo\wirelens.ico
UninstallDisplayIcon={app}\wirelens.exe
OutputDir=..\..\dist
OutputBaseFilename=wirelens-{#AppVersion}-windows-x86_64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
UninstallDisplayName=wirelens

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "..\..\target\x86_64-pc-windows-msvc\release\wirelens.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\wirelens"; Filename: "{app}\wirelens.exe"
Name: "{autodesktop}\wirelens"; Filename: "{app}\wirelens.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\wirelens.exe"; Description: "Launch wirelens"; Flags: nowait postinstall skipifsilent

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
  if not FileExists(ExpandConstant('{commonpf64}\Wireshark\tshark.exe')) then
    MsgBox('Wireshark (tshark) was not found in its default folder. wirelens needs it to read ' +
           'captures; install it from https://www.wireshark.org and make sure tshark is on PATH.',
           mbInformation, MB_OK);
end;
