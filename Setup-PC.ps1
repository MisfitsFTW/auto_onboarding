<#
.SYNOPSIS
    PC Onboarding Automation Script (Refactored to Menu)
.DESCRIPTION
    v3.0 - Modular menu-driven onboarding system.
#>

# --- Core Functions & Initialization ---

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

# --- Initialization ---

# Check for Admin Privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-ErrorMsg "Script must be run as Administrator."
    pause
    exit
}

$ScriptDir = $PSScriptRoot
$InstallersDir = Join-Path $ScriptDir "Installers"
$WifiSSID = "BARRIERA"
$WifiPass = "MeSD05o818"

# --- Setup Step Functions ---

function Step-WiFi {
    Write-Step "Configuring WiFi Profile for $WifiSSID..."
    $ProfileXml = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$WifiSSID</name>
    <SSIDConfig>
        <SSID>
            <name>$WifiSSID</name>
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
                <keyMaterial>$WifiPass</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>
"@
    $Path = "$env:TEMP\wifi.xml"
    $ProfileXml | Out-File $Path
    netsh wlan add profile filename=$Path | Out-Null
    netsh wlan connect name=$WifiSSID | Out-Null
    
    Start-Sleep -Seconds 5
    $WifiCheck = netsh wlan show profile name=$WifiSSID | Select-String "SSID name"
    if ($WifiCheck) {
        Write-Success "WiFi Profile '$WifiSSID' successfully added/verified."
    }
    else {
        Write-ErrorMsg "WiFi Profile '$WifiSSID' was NOT found after import."
    }
}

function Step-Office {
    $InstallChoice = Read-Host "Install Office 365? (Yes/No)"
    if ($InstallChoice -match "^y") {
        # Collect credentials
        $UserEmail = Read-Host "Enter User Email address"
        $SecurePassword = Read-Host "Enter User Password" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $UserPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        Write-Step "Installing Office 365 (this may take several minutes)..."
        $OfficeSetup = Join-Path $InstallersDir "Office\setup.exe"
        $OfficeConfig = Join-Path $InstallersDir "Office\configuration.xml"

        if (Test-Path $OfficeSetup) {
            Start-Process -FilePath $OfficeSetup -ArgumentList "/configure `"$OfficeConfig`"" -Wait
            Write-Success "Office 365 installation finished."
        }
        else {
            Write-ErrorMsg "Office Setup not found at $OfficeSetup"
        }
    }
    else {
        Write-Step "Skipping Office 365 installation."
    }
}

function Step-Utilities {
    Write-Step "Installing Utilities (7-Zip, VLC, WhatsApp)..."
    
    # 7-Zip
    $ZipExe = Join-Path $InstallersDir "7z.exe"
    if (Test-Path $ZipExe) {
        Start-Process -FilePath $ZipExe -ArgumentList "/S" -Wait
        Write-Success "7-Zip installation completed."
    }

    # VLC
    Write-Step "Installing VLC via Winget..."
    winget install VideoLAN.VLC --silent --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -eq 0) { Write-Success "VLC installed." }

    # WhatsApp
    Write-Step "Installing WhatsApp via Winget..."
    winget install WhatsApp.WhatsApp --silent --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -eq 0) { Write-Success "WhatsApp installed." }
}

function Step-VPN {
    Write-Step "Handling VPN Installation..."
    $VpnFileName = "FortiClientVPNSetup_7.2.12.1269_x64.exe"
    $VpnLocalPath = Join-Path $InstallersDir $VpnFileName
    $VpnDownloadUrl = "https://vpn.mita.gov.mt/Software/FortiClient%20VPN%20for%20Windows/$VpnFileName"

    if (!(Test-Path $VpnLocalPath)) {
        Write-Host "Downloading VPN Installer..." -ForegroundColor Yellow
        try {
            Invoke-WebRequest -Uri $VpnDownloadUrl -OutFile $VpnLocalPath -ErrorAction Stop
            Write-Success "VPN downloaded."
        }
        catch {
            Write-Warning "VPN download failed."
        }
    }

    $VpnToInstall = Get-ChildItem -Path $InstallersDir -Filter "FortiClientVPNSetup*.exe" | Select-Object -First 1
    if ($VpnToInstall) {
        Write-Step "Installing VPN..."
        Start-Process -FilePath $VpnToInstall.FullName -ArgumentList "/quiet /norestart" -Wait
        Write-Success "VPN installed."
    }
}

function Step-BrandTools {
    Write-Host "`nSelect Laptop Brand:" -ForegroundColor Yellow
    Write-Host "1. HP (HP Support Assistant)"
    Write-Host "2. Dell (Dell Command Centre)"
    Write-Host "3. ASUS (MyASUS)"
    Write-Host "4. Skip"
    $Choice = Read-Host "Enter Choice (1-4)"

    switch ($Choice) {
        "1" {
            $HpExe = Join-Path $InstallersDir "HPSupportAssistant.exe"
            if (Test-Path $HpExe) {
                Start-Process -FilePath $HpExe -ArgumentList "/s /f `"$env:TEMP\HPSupportAssistant`"" -Wait
                Write-Success "HP tools installed."
            }
        }
        "2" {
            $DellExe = Join-Path $InstallersDir "DellCommandCentre.exe"
            if (Test-Path $DellExe) {
                Start-Process -FilePath $DellExe -ArgumentList "/S" -Wait
                Write-Success "Dell tools installed."
            }
        }
        "3" {
            $AsusExe = Join-Path $InstallersDir "MyASUS.exe"
            if (Test-Path $AsusExe) {
                Start-Process -FilePath $AsusExe -ArgumentList "/S" -Wait
                Write-Success "ASUS tools installed."
            }
        }
    }
}

function Step-Signature {
    Write-Step "Configuring Email Signature..."
    $SigZip = Join-Path $InstallersDir "SignatureSetup.zip"
    $SigTemp = Join-Path $env:TEMP "SignatureSetup"

    if (Test-Path $SigZip) {
        if (Test-Path $SigTemp) { Remove-Item $SigTemp -Recurse -Force }
        Expand-Archive -Path $SigZip -DestinationPath $SigTemp -Force
        $VbsPath = Join-Path $SigTemp "Gov_Corporate_Email_Signature.vbs"
        if (Test-Path $VbsPath) {
            Write-Step "Executing Signature script (30s timeout)..."
            $sigProc = Start-Process "wscript.exe" -ArgumentList "`"$VbsPath`"" -PassThru
            $sigProc | Wait-Process -Timeout 30 -ErrorAction SilentlyContinue
            Write-Success "Signature step processed."
        }
    }
}

function Step-Printer {
    Write-Step "Installing 'Follow Me' printer (Non-admin context)..."
    $PrinterPath = "\\10.58.197.197\FollowMe"
    Write-Host "Triggering connection for $PrinterPath ..."
    Start-Process "explorer.exe" -ArgumentList "rundll32.exe printui.dll,PrintUIEntry /in /n `"$PrinterPath`"" -Wait
    Write-Success "Printer connection triggered."
    Start-Sleep -Seconds 5
    $cim = Get-CimInstance Win32_Printer -Filter "Name LIKE '%FollowMe%'"
    if ($cim) {
        Invoke-CimMethod -InputObject $cim -MethodName PrintTestPage | Out-Null
        Write-Success "Test page sent."
    }
}

function Step-Maintenance {
    Write-Step "Running Maintenance (GPUpdate, WU Trigger)..."
    $Connection = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
    if ($Connection) {
        $gp = Start-Process "gpupdate.exe" -ArgumentList "/force" -PassThru -NoNewWindow
        $gp | Wait-Process -Timeout 30 -ErrorAction SilentlyContinue
        Write-Success "GPUpdate triggered."
    }
    Start-Process -FilePath "usoclient" -ArgumentList "StartInteractiveScan"
    Write-Success "Windows Updates scan triggered."
}

function Step-ConfigMgr {
    Write-Step "Triggering Configuration Manager Actions..."
    if (Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue) {
        try {
            $SmsClient = [wmiclass]"\\.\root\ccm:SMS_Client"
            $Actions = @("{00000000-0000-0000-0000-000000000001}", "{00000000-0000-0000-0000-000000000002}", "{00000000-0000-0000-0000-000000000021}")
            foreach ($Action in $Actions) { $SmsClient.TriggerSchedule($Action) | Out-Null }
            Write-Success "ConfigMgr actions triggered."
        }
        catch { Write-ErrorMsg "Failed to trigger ConfigMgr." }
    }
}

function Step-Finalize {
    Write-Step "Finalizing (OneDrive, Teams, Power/Clock)..."
    $OneDrivePath = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
    if (Test-Path $OneDrivePath) { Start-Process $OneDrivePath } else { Start-Process "OneDrive.exe" -ErrorAction SilentlyContinue }
    Start-Process "ms-teams.exe" -ErrorAction SilentlyContinue

    powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
    powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 1
    powercfg /setactive SCHEME_CURRENT

    $RegPath = "HKCU:\Control Panel\International"
    Set-ItemProperty -Path $RegPath -Name sShortTime -Value "h:mm tt"
    Set-ItemProperty -Path $RegPath -Name sTimeFormat -Value "h:mm:ss tt"
    & rundll32.exe user32.dll, UpdatePerUserSystemParameters
    Write-Success "System settings applied."
}

# --- Main Menu Loop ---

$Continue = $true
while ($Continue) {
    Clear-Host
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host "   PC ONBOARDING INTERACTIVE MENU v3.0  " -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "1.  Connect to WiFi ($WifiSSID)"
    Write-Host "2.  Install Office 365"
    Write-Host "3.  Install Utilities (7-Zip, VLC, WhatsApp)"
    Write-Host "4.  Download & Install VPN"
    Write-Host "5.  Install Brand Specific Tools"
    Write-Host "6.  Configure Email Signature"
    Write-Host "7.  Install 'Follow Me' Printer"
    Write-Host "8.  Run GPUpdate & Windows Update scan"
    Write-Host "9.  Trigger ConfigMgr Actions"
    Write-Host "10. Finalize (OneDrive, Teams, Power, Clock)"
    Write-Host "A.  Run ALL Steps Sequentially"
    Write-Host "X.  Exit"
    Write-Host ""

    $Selection = Read-Host "Select an option"

    switch ($Selection) {
        "1" { Step-WiFi }
        "2" { Step-Office }
        "3" { Step-Utilities }
        "4" { Step-VPN }
        "5" { Step-BrandTools }
        "6" { Step-Signature }
        "7" { Step-Printer }
        "8" { Step-Maintenance }
        "9" { Step-ConfigMgr }
        "10" { Step-Finalize }
        "A" { 
            Step-WiFi; Step-Office; Step-Utilities; Step-VPN; 
            Step-BrandTools; Step-Signature; Step-Printer; 
            Step-Maintenance; Step-ConfigMgr; Step-Finalize 
        }
        "X" { $Continue = $false; Write-Host "Exiting..." }
        Default { Write-Host "Invalid Selection. Please try again." -ForegroundColor Yellow }
    }

    if ($Continue -and ($Selection -ne "X")) {
        Write-Host "`nStep(s) completed. Press Enter to return to menu..."
        Read-Host
    }
}
