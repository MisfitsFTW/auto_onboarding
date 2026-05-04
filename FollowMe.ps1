<#
.SYNOPSIS
    Stand-alone Printer Setup Script for 'Follow Me'
.DESCRIPTION
    Adds the 'Follow Me' printer, sets it as default, and sends a test page.
    Runs in the user context (no admin required).
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

# --- Initialization ---

$PrinterPath = "\\10.58.197.197\FollowMe"

Write-Host "==========================================" -ForegroundColor Green
Write-Host "      PRINTER SETUP: FOLLOW ME            " -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green

Write-Step "Installing 'Follow Me' printer..."
Write-Host "Connecting to $PrinterPath..."

try {
    # 1. Map the printer (/in)
    Write-Host "Step 1/3: Mapping printer..."
    & rundll32.exe printui.dll,PrintUIEntry /in /n "$PrinterPath" /q
    
    # 2. Wait for connection to register
    Start-Sleep -Seconds 5
    
    # 3. Set as default (/y)
    Write-Host "Step 2/3: Setting as default..."
    & rundll32.exe printui.dll,PrintUIEntry /y /n "$PrinterPath"
    
    # 4. Send test page (/k)
    Write-Host "Step 3/3: Sending test page..."
    & rundll32.exe printui.dll,PrintUIEntry /k /n "$PrinterPath"
    
    Write-Success "Printer mapping and test page triggered successfully."
}
catch {
    Write-ErrorMsg "An error occurred during printer setup: $($_.Exception.Message)"
}

Write-Host "`nScript finished. Press Enter to exit..."
Read-Host
