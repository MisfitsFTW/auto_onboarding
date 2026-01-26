<#
.SYNOPSIS
    PC Onboarding Automation Script (Revised)
.DESCRIPTION
    v2.0 - Improved reliability for Taskbar, Default Apps, Network, and Printer.
    Added WhatsApp installation via winget.
#>

# --- Core Functions ---

$LogDir = Join-Path $PSScriptRoot "logs"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir "Setup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Log-Message {
    param([string]$Type, [string]$Message)
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$TimeStamp] [$Type] $Message" | Out-File -FilePath $LogFile -Append
}

function Write-Step {
    param([string]$Message)
    Write-Host "`n[STEP] $Message" -ForegroundColor Cyan
    Log-Message "STEP" $Message
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
    Log-Message "SUCCESS" $Message
}

function Write-ErrorMsg {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
    Log-Message "ERROR" $Message
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
    try {
        # Note: Import-StartLayout is notoriously finicky on active systems.
        # It usually targets the Default User profile for NEW users.
        Import-StartLayout -LayoutPath $LayoutPath -MountPath $env:SystemDrive\ -ErrorAction Stop
        Write-Success "Taskbar layout imported to system."
    } catch {
        Write-Host "Taskbar layout import failed. This is common on active Windows 11 systems. Pins may need manual setup or a restart of Explorer." -ForegroundColor Yellow
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
    
    # Wait for connection and verify
    Start-Sleep -Seconds 5
    $WifiCheck = netsh wlan show profile name=$SSID | Select-String "SSID name"
    if ($WifiCheck) {
        Write-Success "WiFi Profile '$SSID' successfully added/verified."
    } else {
        Write-ErrorMsg "WiFi Profile '$SSID' was NOT found after import."
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
$ZipExe = Join-Path $InstallersDir "7z.exe"
$VlcExe = Join-Path $InstallersDir "vlc.exe"

if (Test-Path $ZipExe) {
    Start-Process -FilePath $ZipExe -ArgumentList "/S" -Wait
    Write-Success "7-Zip installation triggered."
} else { Write-ErrorMsg "7z.exe not found." }

if (Test-Path $VlcExe) {
    Write-Host "Attempting VLC install from: $VlcExe" -ForegroundColor Gray
    $Process = Start-Process -FilePath $VlcExe -ArgumentList "/S" -Wait -PassThru -ErrorAction SilentlyContinue
    if ($Process.ExitCode -eq 0) {
        Write-Success "VLC installation completed successfully."
    } else {
        Write-ErrorMsg "VLC installer returned error code: $($Process.ExitCode). Check if another installation is in progress."
    }
} else { 
    Write-ErrorMsg "vlc.exe NOT FOUND at expected path: $VlcExe" 
    Write-Host "Check if your USB drive letter changed (e.g., from D: to F:)." -ForegroundColor Yellow
}

# --- 7. Windows Updates ---
Write-Step "Triggering Windows Updates..."
Start-Process -FilePath "usoclient" -ArgumentList "StartInteractiveScan"

# --- 8. HP Support Assistant ---
Write-Step "Installing HP Support Assistant..."
$HpExe = Join-Path $InstallersDir "HPSupportAssistant.exe"
if (Test-Path $HpExe) {
    # Based on the usage message: /s /f <target>
    $HpTarget = "$env:TEMP\HPSupportAssistant"
    Start-Process -FilePath $HpExe -ArgumentList "/s /f `"$HpTarget`"" -Wait
    Write-Success "HP Support Assistant extraction/install triggered."
}

# --- WhatsApp (msstore) ---
Write-Step "Installing WhatsApp from Microsoft Store..."
try {
    # Added --accept-source-agreements to skip prompt
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
    # Try to install driver from INF file if provided
    $InfPath = Join-Path $InstallersDir "UNIV_5.1076.3.0_PCL6_x64_Driver.inf"
    $DriverName = "UNIV_5.1076.3.0_PCL6_x64" # This is the target name

    if (Test-Path $InfPath) {
        Write-Step "Installing printer driver from INF: $InfPath"
        # pnputil /add-driver adds it to the store. /install attempts to install it.
        $PnpResult = pnputil /add-driver $InfPath /install
        Log-Message "INFO" "pnputil result: $PnpResult"
    }

    $DriverCheck = Get-PrinterDriver | Where-Object { $_.Name -like "*$DriverName*" -or $_.Name -like "*Universal Printing PCL 6*" }
    
    if (!$DriverCheck) {
        Write-Host "Driver not found in store after attempt. Checking for any 'HP Universal' or 'Generic'..." -ForegroundColor Yellow
        $DriverCheck = Get-PrinterDriver | Where-Object { $_.Name -like "*Universal*" -or $_.Name -like "*Generic*" } | Select-Object -First 1
        if ($DriverCheck) { $DriverName = $DriverCheck.Name }
        else {
            Write-ErrorMsg "No suitable printer drivers found. Driver installation from INF might have failed or driver name is different."
            return
        }
    } else {
        $DriverName = $DriverCheck.Name # Use the exact name found (e.g., "HP Universal Printing PCL 6")
    }
    
    Add-Printer -Name "Office Printer" -PortName "IP_$PrinterIP" -DriverName $DriverName
    Write-Success "Printer 'Office Printer' added using driver '$DriverName'."
} catch {
    Write-ErrorMsg "Failed to install printer automatically: $($_.Exception.Message)"
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
# Using full paths or standard names for OneDrive/Teams
$OneDrivePath = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
if (Test-Path $OneDrivePath) { Start-Process $OneDrivePath } else { Start-Process "OneDrive.exe" -ErrorAction SilentlyContinue }

$TeamsPath = "$env:LOCALAPPDATA\Microsoft\Teams\current\Teams.exe"
if (Test-Path $TeamsPath) { Start-Process $TeamsPath } else { Start-Process "ms-teams.exe" -ErrorAction SilentlyContinue }

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
