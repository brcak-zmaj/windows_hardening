# Windows Cleanup and Hardening Script

This PowerShell script is designed to clean up unnecessary files, debloat Windows by removing unwanted applications, and perform security hardening tasks on your Windows machine. It requires administrator privileges to run. This script is designed to run on a schedule in the event that a Windows Update causes some of these packages to be reinstalled, and to keep your filesystem clean. Some tasks may still work on Windows 11

## Features

- **Clean up unnecessary files**: Removes temporary files, logs, and caches from various system directories.
- **Debloat Windows**: Uninstalls unwanted applications (e.g., OneDrive, Microsoft Teams, Zoom, etc.).
- **Additional cleanup operations**: Disables unwanted Windows features and performs registry tweaks to disable telemetry and other tracking features.
- **Disable unnecessary services and scheduled tasks**: Disables background tasks and services that are not needed.
- **Security Hardening**: Disables weak ciphers, SSLv3, and TLS 1.0, Sets stronger password policies, etc..
- **Disable Telemetry and Tracking**: Disables a lot of windows server tracking and telemetry  
- **Logs**: Keeps a log of all actions performed for auditing and troubleshooting.

## Prerequisites

- **Windows OS**: The script works on most modern versions of Windows 10/11.
- **Administrator privileges**: The script must be run as an administrator to perform all tasks.
- **PowerShell version 5.1 or higher**: This version is pre-installed on Windows 10/11.

## Usage

### 1. Download the Script:

Clone the repository or download the script as a `.ps1` file.

### 2. Run the Script:

- Open PowerShell as Administrator (right-click and choose "Run as Administrator").
- Navigate to the directory where the script is located.
- Run the script by typing:

```powershell
.\tune10.ps1
```

## Usage
The script logs all actions it performs to a log file located at C:\Temp\cleanup_log.txt. If the log file path doesn't exist, the script will create the necessary directory.

## What the script does

### 1. File Cleanup:
The script removes temporary files and logs from various system directories, including:
- %TEMP%
- C:\Windows\Temp
- C:\Windows\Prefetch
- C:\ProgramData\Microsoft\Windows\WER\ReportArchive
- And more...

It targets files with the following extensions:
- .log
- .tmp
- .dmp
- .bak
- .old

### 2. Application Debloating:
Uninstalls a predefined list of applications and Windows components, such as:
- Microsoft OneDrive
- Microsoft Teams
- Skype
- Zoom
- Adobe Acrobat Reader DC
- Preinstalled Microsoft Apps (e.g., 3dbuilder, bingnews, solitairecollection, etc.)

### 3. System Cleanup:
- Disables Windows features such as MiracastReceiver, Cortana, and XPSServices.
- Modifies registry settings to disable telemetry and tracking features.
- Disables unnecessary scheduled tasks (e.g., Compatibility Appraiser, ProgramDataUpdater).
- Disables services like Xbox-related services, Windows Error Reporting, and Windows Search.

### 4. Security Hardening:
- Disables weak ciphers (e.g., DES, RC2).
- Disables old protocols like SSLv3 and TLS 1.0.
- Configures stronger password policies:
- Minimum password length of 12 characters.
- Password complexity enabled.
- Maximum password age set to 90 days.
- Bad password attempts limited to 5.

### 5. Cleaning Recycle Bin:
- Clears all files from the recycle bin that are older than 30 days