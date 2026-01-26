<#
.SYNOPSIS
    PC Onboarding Automation Script (Revised)
.DESCRIPTION
    v2.0 - Improved reliability for Taskbar, Default Apps, Network, and Printer.
    Added WhatsApp installation via winget.
#>

# --- Core Functions ---

function Write-Step {
    param([string]$Message)
    Write-Host "`n[STEP] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-ErrorMsg {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Set-TaskbarPins {
    Write-Step "Configuring Taskbar Pins..."
    # For Windows 10/11, LayoutModification.xml is the cleanest official way
    $LayoutPath = "$env:TEMP\TaskbarLayout.xml"
    $LayoutContent = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
  <CustomTaskbarLayoutCollection PinListPlacement="Replace">
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout">
        <taskbar:DesktopApp DesktopApplicationID="Microsoft.Office.OUTLOOK.EXE.15" />
        <taskbar:DesktopApp DesktopApplicationID="Microsoft.Office.WINWORD.EXE.15" />
        <taskbar:DesktopApp DesktopApplicationID="Microsoft.Office.EXCEL.EXE.15" />
        <taskbar:DesktopApp DesktopApplicationID="com.squirrel.Teams.Teams" />
        <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk" />
      </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
  </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
"@
    $LayoutContent | Out-File $LayoutPath -Encoding utf8
    # Import for next user profile and try to force for current
    try {
        Import-StartLayout -LayoutPath $LayoutPath -MountPath $env:SystemDrive\
        Write-Host "Taskbar layout imported. Note: Changes may only appear after Logoff/Login." -ForegroundColor Yellow
    } catch {
        Write-ErrorMsg "Failed to import Taskbar layout."
    }
}

function Set-DefaultApps {
    Write-Step "Setting Default Apps (Chrome, Acrobat)..."
    $AssocPath = "$env:TEMP\AppAssoc.xml"
    $AssocContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<DefaultAssociations>
  <Association Identifier=".html" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier=".htm" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier="http" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier="https" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier=".pdf" ProgId="Acrobat.Document.DC" ApplicationName="Adobe Acrobat Reader" />
</DefaultAssociations>
"@
    $AssocContent | Out-File $AssocPath -Encoding utf8
    $DismResult = Dism /Online /Import-DefaultAppAssociations:$AssocPath
    if ($DismResult -like "*The operation completed successfully*") {
        Write-Success "Default applications set."
    } else {
        Write-ErrorMsg "Dism failed to set default applications."
    }
}

function Connect-Wifi {
    param($SSID, $Password)
    Write-Step "Configuring WiFi Profile for $SSID..."
    $ProfileXml = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$SSID</name>
    <SSIDConfig>
        <SSID>
            <name>$SSID</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>$Password</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>
"@
    $Path = "$env:TEMP\wifi.xml"
    $ProfileXml | Out-File $Path
    netsh wlan add profile filename=$Path | Out-Null
    netsh wlan connect name=$SSID | Out-Null
    
    # Wait for connection
    Start-Sleep -Seconds 5
    $Status = netsh wlan show interfaces | Select-String "State"
    if ($Status -like "*connected*") {
        Write-Success "WiFi connected to $SSID."
    } else {
        Write-ErrorMsg "WiFi failed to connect to $SSID. Please check password."
    }
}

# --- Initialization ---

# Check for Admin Privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-ErrorMsg "Script must be run as Administrator."
    exit
}

$ScriptDir = $PSScriptRoot
$InstallersDir = Join-Path $ScriptDir "Installers"

# --- User Data Collection ---

Write-Host "==========================================" -ForegroundColor Green
Write-Host "   PC ONBOARDING AUTOMATION SYSTEM v2.0   " -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green

$UserEmail = Read-Host "Enter User Email address"
$UserPassword = Read-Host "Enter User Password"
$PrinterIP = "10.58.197.197"
$WifiSSID = "Barriera"
$WifiPass = "MeSD05o818"

$InstallOffice = Read-Host "Install Office 365? (Yes/No)"

# --- 1. Install Office 365 ---
if ($InstallOffice -eq "Yes" -or $InstallOffice -eq "y") {
    Write-Step "Installing Office 365..."
    $OfficeSetup = Join-Path $InstallersDir "Office\setup.exe"
    $OfficeConfig = Join-Path $InstallersDir "Office\configuration.xml"

    if (Test-Path $OfficeSetup) {
        Start-Process -FilePath $OfficeSetup -ArgumentList "/configure `"$OfficeConfig`"" -Wait
        Write-Success "Office 365 installation finished."
    } else {
        Write-ErrorMsg "Office Setup not found at $OfficeSetup"
    }
} else {
    Write-Step "Skipping Office 365 installation as requested."
}

# --- 3. Email Signature (VBS from Zip) ---
Write-Step "Configuring Email Signature..."
$SigZip = Join-Path $InstallersDir "SignatureSetup.zip"
$SigTemp = Join-Path $env:TEMP "SignatureSetup"
$SigVbsName = "Gov_Corporate_Email_Signature.vbs"

if (Test-Path $SigZip) {
    if (Test-Path $SigTemp) { Remove-Item $SigTemp -Recurse -Force }
    Expand-Archive -Path $SigZip -DestinationPath $SigTemp -Force
    $VbsPath = Join-Path $SigTemp $SigVbsName
    if (Test-Path $VbsPath) {
        Start-Process "wscript.exe" -ArgumentList "`"$VbsPath`"" -Wait
        Write-Success "Email Signature script executed."
    } else {
        Write-ErrorMsg "VBS script $SigVbsName not found inside zip."
    }
}

# --- 4. VPN Installation ---
Write-Step "Installing VPN..."
$VpnExe = Get-ChildItem -Path $InstallersDir -Filter "*VPN*" | Select-Object -First 1
if ($VpnExe) {
    # Using more aggressive silent flags
    Start-Process -FilePath $VpnExe.FullName -ArgumentList "/S /VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Wait
    Write-Success "VPN installation triggered."
} else {
    Write-ErrorMsg "VPN installer not found."
}

# --- 5. 7-Zip & 6. VLC ---
Write-Step "Installing Utilities (7-Zip, VLC)..."
Start-Process -FilePath (Join-Path $InstallersDir "7z.exe") -ArgumentList "/S" -Wait
Start-Process -FilePath (Join-Path $InstallersDir "vlc.exe") -ArgumentList "/S" -Wait

# --- 7. Windows Updates ---
Write-Step "Triggering Windows Updates..."
Start-Process -FilePath "usoclient" -ArgumentList "StartInteractiveScan"

# --- 8. HP Support Assistant ---
Write-Step "Installing HP Support Assistant..."
$HpExe = Join-Path $InstallersDir "HPSupportAssistant.exe"
if (Test-Path $HpExe) {
    Start-Process -FilePath $HpExe -ArgumentList "/s /v`"/qn`"" -Wait
}

# --- WhatsApp (msstore) ---
Write-Step "Installing WhatsApp from Microsoft Store..."
try {
    winget install --id 9NKSQGP7F2NH --source msstore --accept-package-agreements --accept-source-agreements --silent
    Write-Success "WhatsApp installation finished."
} catch {
    Write-ErrorMsg "Failed to install WhatsApp via winget."
}

# --- 9-10. Taskbar & Defaults ---
Set-TaskbarPins
Set-DefaultApps

# --- 11. Printer Installation ---
Write-Step "Installing Printer ($PrinterIP)..."
try {
    if (!(Get-PrinterPort -Name "IP_$PrinterIP" -ErrorAction SilentlyContinue)) {
        Add-PrinterPort -Name "IP_$PrinterIP" -PrinterHostAddress $PrinterIP
    }
    # Try generic driver
    $DriverName = "Generic / Text Only"
    if (!(Get-PrinterDriver -Name $DriverName -ErrorAction SilentlyContinue)) {
       # Try finding any HP driver if available
       $Driver = Get-PrinterDriver | Where-Object { $_.Name -like "*HP*" } | Select-Object -First 1
       if ($Driver) { $DriverName = $Driver.Name }
    }
    
    Add-Printer -Name "Office Printer" -PortName "IP_$PrinterIP" -DriverName $DriverName
    Write-Success "Printer 'Office Printer' added using driver '$DriverName'."
} catch {
    Write-ErrorMsg "Failed to install printer automatically. Please add manually."
}

# --- 14. Ethernet/WiFi Check & GPUpdate ---
Write-Step "Running gpupdate /force..."
$Connection = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
if ($Connection) {
    gpupdate /force
    Write-Success "GPUpdate completed."
} else {
    Write-ErrorMsg "No active network connection found! GPUpdate skipped."
}

# --- 15. Configuration Manager Actions ---
Write-Step "Triggering Configuration Manager Actions..."
if (Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue) {
    try {
        $SmsClient = [wmiclass]"\\.\root\ccm:SMS_Client"
        $Actions = @("{00000000-0000-0000-0000-000000000001}","{00000000-0000-0000-0000-000000000002}","{00000000-0000-0000-0000-000000000021}")
        foreach ($Action in $Actions) { $SmsClient.TriggerSchedule($Action) | Out-Null }
        Write-Success "ConfigMgr actions triggered."
    } catch { Write-ErrorMsg "Failed to trigger ConfigMgr actions." }
} else {
    Write-ErrorMsg "Configuration Manager client not found."
}

# --- 17. WiFi Connection ---
Connect-Wifi -SSID $WifiSSID -Password $WifiPass

# --- Final Manual Steps ---
Write-Host "`nLaunching Apps for Manual Sign-in..." -ForegroundColor Yellow
Start-Process "onedrive"
Start-Process "msteams"

# --- Power & Clock ---
Write-Step "Setting Power Options & Clock..."
# Lid actions
powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 1
powercfg /setactive SCHEME_CURRENT

# Clock format (12-hour)
$RegPath = "HKCU:\Control Panel\International"
Set-ItemProperty -Path $RegPath -Name sShortTime -Value "h:mm tt"
Set-ItemProperty -Path $RegPath -Name sTimeFormat -Value "h:mm:ss tt"
# Force refresh
& rundll32.exe user32.dll,UpdatePerUserSystemParameters

Write-Host "`nSETUP FINISHED!" -ForegroundColor Cyan
Write-Host "Please check Taskbar and Defaults after logging off/in." -ForegroundColor Yellow
pause
