; Inno Setup script for the SIEM desktop application.
; Build the app first (packaging\build-desktop.ps1), then compile with:
;   iscc installer\SIEM.iss
; Produces installer\Output\SIEM-Setup-<version>.exe.

#define AppName "SIEM"
#define AppVersion "1.0.0"
#define AppPublisher "SIEM Log Correlation Engine Project"
#define AppExe "SIEM.exe"
#define TaskName "SIEM Desktop"

[Setup]
AppId={{A6D9C4E2-7B3F-4E2A-9C1D-8F5A2B6E4D10}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\SIEM
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=SIEM-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
UninstallDisplayName={#AppName} {#AppVersion}
UninstallDisplayIcon={app}\{#AppExe}
VersionInfoVersion=1.0.0.0

#if FileExists(AddBackslash(SourcePath) + "..\src\siem\web\static\img\siem.ico")
SetupIconFile=..\src\siem\web\static\img\siem.ico
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "service"; Description: "Start SIEM at sign-in with administrator privileges (recommended for Security log monitoring)"; GroupDescription: "Startup:"; Flags: checkedonce
Name: "firewall"; Description: "Open Windows Firewall for syslog (UDP/TCP 514)"; GroupDescription: "Network:"; Flags: checkedonce
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: checkedonce

[Files]
Source: "..\dist\SIEM\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "install.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "uninstall.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "INSTALL-README.txt"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\SIEM"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"; IconFilename: "{app}\{#AppExe}"
Name: "{autodesktop}\SIEM"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"; IconFilename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\install.ps1"" -InstallDir ""{app}""{code:GetServiceFlag}{code:GetFirewallFlag}"; \
  StatusMsg: "Configuring startup, firewall and shortcuts..."; Flags: runhidden waituntilterminated

[UninstallRun]
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\uninstall.ps1"" -InstallDir ""{app}"" -Force"; \
  Flags: runhidden waituntilterminated; RunOnceId: "UninstallSIEM"

[Code]
function GetServiceFlag(Param: String): String;
begin
  if WizardIsTaskSelected('service') then Result := '' else Result := ' -NoTask';
end;

function GetFirewallFlag(Param: String): String;
begin
  if WizardIsTaskSelected('firewall') then Result := '' else Result := ' -NoFirewall';
end;
