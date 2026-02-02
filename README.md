# PC Onboarding Automation

Efficiently automate the setup and configuration of new Windows PCs. This script handles common installations, network configuration, and system tweaks.

## 🚀 Quick Start Walkthrough

Follow these steps to set up a new PC using this tool:

### 1. Preparation
Ensure you have the following in the project root:
- **`Installers/` Folder**: This folder must contain the necessary installers:
  - `Office/setup.exe` & `configuration.xml`
  - `7z.exe` (7-Zip)
  - `WhatsApp.exe`
  - Brand tools (optional): `HPSupportAssistant.exe`, `DellCommandCentre.exe`, and `MyASUS.exe`.
- **Admin Rights**: You must run the script as an administrator.

### 2. Execution
1.  **Run `Start-Setup.bat`**: Double-click this file. It will automatically request Administrator privileges and launch the main PowerShell script.
2.  **Follow the Prompts**:
    - **WiFi**: The script will try to connect to the "BARRIERA" network automatically.
    - **Office 365**: Choose whether to install Office. If "Yes", you'll be prompted for the user's email and password.
    - **Brand Selection**: Select the laptop brand (HP, Dell, ASUS) to install specific support tools.
3.  **Automatic Tasks**: The script will then:
    - Install VLC and 7-Zip.
    - Install and configure the VPN.
    - Set up the "Follow Me" printer.
    - Run `gpupdate /force` and trigger Configuration Manager actions.
    - Apply system tweaks (Power options, 12-hour clock).

### 3. Manual Steps
Once the script finishes:
- **Sign in**: OneDrive and Teams will launch automatically. Sign in with the user's credentials.
- **Log off/in**: Some changes (like Taskbar and Default Apps) may require a logout or restart to take full effect.

---

## 🛠 Key Features

- **Silent Installations**: Most software is installed silently using `winget` or silent flags.
- **Network Configuration**: Automatic WiFi profile creation and connection.
- **Printer Setup**: Maps the corporate "Follow Me" printer and sends a test page.
- **System Hardening & Tweaks**: Configures lid actions and time formats.
- **Logging**: All actions are logged to the `logs/` directory for troubleshooting.

## 📁 File Structure

- `Setup-PC.ps1`: The main automation logic.
- `Start-Setup.bat`: A helper script to launch PowerShell with the correct execution policy and admin rights.
- `logs/`: (Generated) Contains timestamped log files.
- `Installers/`: (Required) Storage for offline installers.
