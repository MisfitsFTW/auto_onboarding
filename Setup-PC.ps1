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
    }
    else {
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



$WifiSSID = "BARRIERA"
$WifiPass = "MeSD05o818"

$InstallOffice = Read-Host "Install Office 365? (Yes/No)"
$OfficeProcess = $null

Write-Host "`nSelect Laptop Brand for System Tool installation:" -ForegroundColor Yellow
Write-Host "1. HP (HP Support Assistant)"
Write-Host "2. Dell (Dell Command Centre)"
Write-Host "3. ASUS (MyASUS)"
Write-Host "4. Skip / Other"
$BrandChoice = Read-Host "Enter Choice (1-4)"

# --- 1. Install Office 365 ---
if ($InstallOffice -eq "Yes" -or $InstallOffice -eq "y") {
    # Collect credentials only when needed
    $UserEmail = Read-Host "Enter User Email address"
    $SecurePassword = Read-Host "Enter User Password" -AsSecureString
    # Convert SecureString to plain text for use in script
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $UserPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    Write-Step "Installing Office 365..."
    $OfficeSetup = Join-Path $InstallersDir "Office\setup.exe"
    $OfficeConfig = Join-Path $InstallersDir "Office\configuration.xml"

    if (Test-Path $OfficeSetup) {
        Write-Step "Starting Office 365 installation in background..."
        $OfficeProcess = Start-Process -FilePath $OfficeSetup -ArgumentList "/configure `"$OfficeConfig`"" -PassThru
        Write-Success "Office 365 installation started."
    }
    else {
        Write-ErrorMsg "Office Setup not found at $OfficeSetup"
    }
}
else {
    Write-Step "Skipping Office 365 installation as requested."
}

# --- 3. Email Signature (VBS from Zip) ---
Write-Step "Configuring Email Signature..."
$SigZip = Join-Path $InstallersDir "SignatureSetup.zip"
$SigTemp = Join-Path $env:TEMP "SignatureSetup"
$SigVbsName = "Gov_Corporate_Email_Signature.vbs"

if (Test-Path $SigZip) {
    # It is crucial to wait for Office/Outlook to be ready before firing the signature script
    if ($OfficeProcess) {
        Write-Step "Waiting for Office 365 background installation to finish before setting email signature..."
        $OfficeProcess | Wait-Process
        Write-Success "Office 365 installation finished. Proceeding with signature."
    }

    if (Test-Path $SigTemp) { Remove-Item $SigTemp -Recurse -Force }
    Expand-Archive -Path $SigZip -DestinationPath $SigTemp -Force
    $VbsPath = Join-Path $SigTemp $SigVbsName
    if (Test-Path $VbsPath) {
        Start-Process "wscript.exe" -ArgumentList "`"$VbsPath`""
        Write-Success "Email Signature script executed."
    }
    else {
        Write-ErrorMsg "VBS script $SigVbsName not found inside zip."
    }
}

# --- 4. VPN Automated Download & Install ---
Write-Step "Handling VPN Installation..."
$VpnFileName = "FortiClientVPNSetup_7.2.12.1269_x64.exe"
$VpnLocalPath = Join-Path $InstallersDir $VpnFileName
$VpnDownloadUrl = "https://vpn.mita.gov.mt/Software/FortiClient%20VPN%20for%20Windows/$VpnFileName"

if (!(Test-Path $VpnLocalPath)) {
    Write-Host "VPN Installer not found locally. Attempting to download specific version from portal..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $VpnDownloadUrl -OutFile $VpnLocalPath -ErrorAction Stop
        Write-Success "VPN Installer downloaded successfully."
    }
    catch {
        Write-Warning "Failed to download VPN installer from $VpnDownloadUrl. Proceeding with local install if possible."
    }
}

$VpnToInstall = Get-ChildItem -Path $InstallersDir -Filter "FortiClientVPNSetup*.exe" | Select-Object -First 1
if ($VpnToInstall) {
    Write-Step "Installing VPN ($($VpnToInstall.Name))..."
    # Using /quiet /norestart for reliable silent installation
    Start-Process -FilePath $VpnToInstall.FullName -ArgumentList "/quiet /norestart" -Wait
    Write-Success "VPN installation command executed."
}
else {
    Write-ErrorMsg "No VPN installer (FortiClientVPNSetup*.exe) found."
}


# --- 5. 7-Zip & 6. VLC (Winget) ---
Write-Step "Installing Utilities (7-Zip, VLC)..."
$ZipExe = Join-Path $InstallersDir "7z.exe"

if (Test-Path $ZipExe) {
    Start-Process -FilePath $ZipExe -ArgumentList "/S" -Wait
    Write-Success "7-Zip installation triggered."
}
else { Write-ErrorMsg "7z.exe not found." }

Write-Step "Installing VLC via Winget..."
winget install VideoLAN.VLC --silent --accept-package-agreements --accept-source-agreements
if ($LASTEXITCODE -eq 0) {
    Write-Success "VLC installation via Winget finished."
}
else {
    Write-ErrorMsg "VLC installation via Winget failed or was already present."
}

# --- 7. Windows Updates ---
Write-Step "Triggering Windows Updates..."
Start-Process -FilePath "usoclient" -ArgumentList "StartInteractiveScan"

# --- 8. Brand Specific System Tools ---
Write-Step "Installing System Specific Software..."
switch ($BrandChoice) {
    "1" {
        $HpExe = Join-Path $InstallersDir "HPSupportAssistant.exe"
        if (Test-Path $HpExe) {
            # Based on the usage message: /s /f <target>
            $HpTarget = "$env:TEMP\HPSupportAssistant"
            Start-Process -FilePath $HpExe -ArgumentList "/s /f `"$HpTarget`"" -Wait
            Write-Success "HP Support Assistant extraction/install triggered."
        }
        else {
            Write-ErrorMsg "HP Support Assistant installer not found at $HpExe"
        }
    }
    "2" {
        $DellExe = Join-Path $InstallersDir "DellCommandCentre.exe"
        if (Test-Path $DellExe) {
            Start-Process -FilePath $DellExe -ArgumentList "/S" -Wait
            Write-Success "Dell Command Centre installation triggered."
        }
        else {
            Write-ErrorMsg "Dell Command Centre installer not found at $DellExe"
        }
    }
    "3" {
        $AsusExe = Join-Path $InstallersDir "MyASUS.exe"
        if (Test-Path $AsusExe) {
            Start-Process -FilePath $AsusExe -ArgumentList "/S" -Wait
            Write-Success "MyASUS installation triggered."
        }
        else {
            Write-ErrorMsg "MyASUS installer not found at $AsusExe"
        }
    }
    Default { Write-Step "Skipping system-specific tool installation." }
}

# --- WhatsApp (Local) ---
Write-Step "Installing WhatsApp from local file..."
$WhatsAppExe = Join-Path $InstallersDir "WhatsApp.exe"
if (Test-Path $WhatsAppExe) {
    Start-Process -FilePath $WhatsAppExe -ArgumentList "/S" -Wait
    Write-Success "WhatsApp installation triggered."
}
else {
    Write-ErrorMsg "WhatsApp installer not found at $WhatsAppExe"
}

# --- Printer Installation (Follow Me via Print Server) ---
Write-Step "Installing 'Follow Me' printer from print server..."

$PrintServer = "10.58.197.197"
$ShareName = "FollowMe"
$Connection = "\\$PrintServer\$ShareName"

try {
    # Check if printer already exists
    if (Get-Printer -Name $ShareName -ErrorAction SilentlyContinue) {
        Write-Host "Printer '$ShareName' already installed."
        return
    }

    Write-Host "Connecting to shared printer $Connection ..."
    Add-Printer -ConnectionName $Connection -ErrorAction Stop

    Write-Success "Printer '$ShareName' installed successfully from $PrintServer."

    # Give spooler a moment to fully register the printer
    Start-Sleep -Seconds 3
    
    # Send test page
    $cim = Get-CimInstance Win32_Printer -Filter "Name LIKE '%$ShareName%'"
    if ($cim) {
        Invoke-CimMethod -InputObject $cim -MethodName PrintTestPage | Out-Null
        Write-Success "Test page sent to '$ShareName'."
    }
    else {
        Write-ErrorMsg "Printer CIM object not found for test page."
    }

}
catch {
    Write-ErrorMsg "Follow Me printer setup failed: $($_.Exception.Message)"
}



# --- 14. Ethernet/WiFi Check & GPUpdate ---
Write-Step "Running gpupdate /force..."
$Connection = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
if ($Connection) {
    # Use Start-Process with a timeout to prevent hanging
    $gpProcess = Start-Process "gpupdate.exe" -ArgumentList "/force" -PassThru -NoNewWindow
    $gpProcess | Wait-Process -Timeout 30 -ErrorAction SilentlyContinue
    if (!$gpProcess.HasExited) {
        Write-Warning "GPUpdate is taking too long, continuing to next steps..."
    }
    else {
        Write-Success "GPUpdate completed."
    }
}
else {
    Write-ErrorMsg "No active network connection found! GPUpdate skipped."
}

# --- 15. Configuration Manager Actions ---
Write-Step "Triggering Configuration Manager Actions..."
if (Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue) {
    try {
        $SmsClient = [wmiclass]"\\.\root\ccm:SMS_Client"
        $Actions = @("{00000000-0000-0000-0000-000000000001}", "{00000000-0000-0000-0000-000000000002}", "{00000000-0000-0000-0000-000000000021}")
        foreach ($Action in $Actions) { $SmsClient.TriggerSchedule($Action) | Out-Null }
        Write-Success "ConfigMgr actions triggered."
    }
    catch { Write-ErrorMsg "Failed to trigger ConfigMgr actions." }
}
else {
    Write-ErrorMsg "Configuration Manager client not found."
}

# --- 17. WiFi Connection ---
Write-Step "Configuring WiFi Profile for $WifiSSID ..."
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
& rundll32.exe user32.dll, UpdatePerUserSystemParameters

Write-Host "`nSETUP FINISHED!" -ForegroundColor Cyan
Write-Host "Please check Taskbar and Defaults after logging off/in." -ForegroundColor Yellow
pause
