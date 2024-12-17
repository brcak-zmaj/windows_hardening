# Check if running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  Write-Host "Please run this script as an administrator."
  Exit
}

#########################################################
# Vars
#########################################################

# Set log file path
$logFilePath = "C:\Temp\cleanup_log.txt"

# Define list of directories to clean up
$directories = @(
    "$env:TEMP",
    "$env:LOCALAPPDATA\Temp",
    "$env:USERPROFILE\Downloads",
    #"$env:USERPROFILE\Documents",
    "C:\Windows\Temp",
    "C:\Windows\Prefetch",
    "C:\Windows\SoftwareDistribution\Download",
    "C:\Windows\Logs",
    "C:\ProgramData\Microsoft\Windows\WER\ReportArchive",
    "C:\ProgramData\Microsoft\Windows\WER\ReportQueue",
    "C:\ProgramData\Microsoft\Windows Defender\Scans\History",
    "C:\ProgramData\Microsoft\Windows Defender\LocalCopy",
    "C:\ProgramData\Package Cache",
    "C:\Program Files (x86)\Google\Update\Download",
    "C:\Windows\Installer\$PatchCache$"
)

# Define list of file extensions to delete
$fileExtensions = @(
    "*.log",
    "*.tmp",
    "*.dmp",
    "*.bak",
    "*.old"
)

# Define list of applications to uninstall
$applications = @(
    "Microsoft OneDrive",
    "Microsoft Teams",
    "Skype",
    "Zoom",
    "Adobe Acrobat Reader DC",
    "*3dbuilder*",
    "*bingfinance*",
    "*bingnews*",
    "*bingsports*",
    "*bingweather*",
    "*getstarted*",
    "*officehub*",
    "*onenote*",
    "*people*",
    "*skypeapp*",
    "*solitairecollection*",
    "*windowsmaps*",
    "*xbox*",
    "XboxGameOverlay",
    "*ACGMediaPlayer*",
    "*ActiproSoftwareLLC*",
    "*AdobePhotoshopExpress*",
    "*AdobeSystemsIncorporated.AdobePhotoshopExpress*",
    "*BubbleWitch3Saga*",
    "*CandyCrush*",
    "*CommsPhone*",
    "*ConnectivityStore*",
    "*Dolby*",
    "*Duolingo-LearnLanguagesforFree*",
    "*EclipseManager*",
    "*Facebook*",
    "*FarmHeroesSaga*",
    "*Flipboard*",
    "*HiddenCity*",
    "*Hulu*",
    "*LinkedInforWindows*",
    "*Microsoft.549981C3F5F10*",
    "*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*",
    "*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*",
    "*Microsoft.Appconnector*",
    "*Microsoft.Asphalt8Airborne*",
    "*Microsoft.BingNews*",
    "*Microsoft.BingWeather*",
    "*Microsoft.DrawboardPDF*",
    "*Microsoft.GamingApp*",
    "*Microsoft.GetHelp*",
    "*Microsoft.MSPaint*",
    "*Microsoft.Messaging*",
    "*Microsoft.Microsoft3DViewer*",
    "*Microsoft.MicrosoftOfficeHub*",
    "*Microsoft.MicrosoftOfficeOneNote*",
    "*Microsoft.MicrosoftSolitaireCollection*",
    "*Microsoft.MicrosoftStickyNotes*",
    "*Microsoft.MixedReality.Portal*",
    "*Microsoft.OneConnect*",
    "*Microsoft.People*",
    "*Microsoft.Print3D*",
    "*Microsoft.SkypeApp*",
    "*Microsoft.Wallet*",
    "*Microsoft.Whiteboard*",
    "*Microsoft.WindowsAlarms*",
    "*Microsoft.WindowsCommunicationsApps*",
    "*Microsoft.WindowsFeedbackHub*",
    "*Microsoft.WindowsMaps*",
    "*Microsoft.WindowsSoundRecorder*",
    "*Microsoft.YourPhone*",
    "*Microsoft.ZuneMusic*",
    "*Microsoft.ZuneVideo*",
    "*MinecraftUWP*",
    "*Netflix*",
    "*Office.Sway*",
    "*OneCalendar*",
    "*PandoraMediaInc*",
    "*RoyalRevolt*",
    "*SpeedTest*",
    "*Sway*",
    "*Todos*",
    "*Twitter*",
    "*Viber*",
    "*WindowsScan*",
    "*Wunderlist*",
    "*bingsports*",
    "*empires*",
    "*spotify*",
    "*windowsphone*",
    "*xing*",
    "2FE3CB00.PicsArt-PhotoStudio",
    "46928bounde.EclipseManager",
    "4DF9E0F8.Netflix",
    "613EBCEA.PolarrPhotoEditorAcademicEdition",
    "6Wunderkinder.Wunderlist",
    "7EE7776C.LinkedInforWindows",
    "89006A2E.AutodeskSketchBook",
    "9E2F88E3.Twitter",
    "A278AB0D.DisneyMagicKingdoms",
    "A278AB0D.MarchofEmpires",
    "ActiproSoftwareLLC.562882FEEB491",
    "CAF9E577.Plex",
    "ClearChannelRadioDigital.iHeartRadio",
    "D52A8D61.FarmVille2CountryEscape",
    "D5EA27B7.Duolingo-LearnLanguagesforFree",
    "DB6EA5DB.CyberLinkMediaSuiteEssentials",
    "DolbyLaboratories.DolbyAccess",
    "Drawboard.DrawboardPDF",
    "Facebook.Facebook",
    "Fitbit.FitbitCoach",
    "Flipboard.Flipboard",
    "GAMELOFTSA.Asphalt8Airborne",
    "KeeperSecurityInc.Keeper",
    "Microsoft.BingFinance",
    "Microsoft.BingFoodAndDrink",
    "Microsoft.BingHealthAndFitness",
    "Microsoft.BingTranslator",
    "Microsoft.BingTravel",
    "Microsoft.CommsPhone",
    "Microsoft.ConnectivityStore",
    "Microsoft.GamingServices",
    "Microsoft.Getstarted",
    "Microsoft.Messaging",
    "Microsoft.MicrosoftPowerBIForWindows",
    "Microsoft.MinecraftUWP",
    "Microsoft.NetworkSpeedTest",
    "Microsoft.News",
    "Microsoft.Office.Lens",
    "Microsoft.Office.Sway",
    "Microsoft.OneConnect",
    "Microsoft.ScreenSketch",
    "Microsoft.SkypeApp",
    "Microsoft.Whiteboard",
    "Microsoft.WindowsCamera",
    "Microsoft.WindowsPhone",
    "Microsoft.WindowsReadingList",
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxApp",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.ZuneMusic",
    "NORDCURRENT.COOKINGFEVER",
    "PandoraMediaInc.29680B314EFC2",
    "Playtika.CaesarsSlotsFreeCasino",
    "ShazamEntertainmentLtd.Shazam",
    "SlingTVLLC.SlingTV",
    "SpotifyAB.SpotifyMusic",
    "TheNewYorkTimes.NYTCrossword",
    "ThumbmunkeysLtd.PhototasticCollage",
    "TuneIn.TuneInRadio",
    "WinZipComputing.WinZipUniversal",
    "XINGAG.XING",
    "flaregamesGmbH.RoyalRevolt2",
    "king.com.BubbleWitch3Saga",
    "king.com.CandyCrushSaga",
    "king.com.CandyCrushSodaSaga",
    "microsoft.windowscommunicationsapps"
)

# Set variables for additional system cleanup operations
$additionalCleanup = @(
    # Disable Telemetry, Privacy, and Related Features
    "Disable-WindowsOptionalFeature -Online -FeatureName Microsoft.Windows.Client.Shell.MiracastReceiver",
    "Disable-WindowsOptionalFeature -Online -FeatureName Microsoft.Windows.Cortana",
    "Disable-WindowsOptionalFeature -Online -FeatureName Printing-XPSServices-Features",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'AITEnable' -Type DWord -Value 0",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'DisableInventory' -Type DWord -Value 1",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'DisablePCA' -Type DWord -Value 1",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'DisableUAR' -Type DWord -Value 1",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'DisableSR' -Type DWord -Value 1",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'DisableOTJLogging' -Type DWord -Value 1",
    "Set-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener' -Name 'Start' -Type DWord -Value 0",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableWindowsLocationProvider' -Type 'DWORD' -Value '1' -Force"
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocationScripting' -Type 'DWORD' -Value '1' -Force"
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation' -Value '1' -Type 'DWORD' -Force"
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity' -Name 'Value' -Value 'Deny' -Force"
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics' -Name 'Value' -Value 'Deny' -Type 'String' -Force"
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsGetDiagnosticInfo' -Type 'DWORD' -Value 2 -Force"
    "New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP' -Name 'RomeSdkChannelUserAuthzPolicy' -PropertyType 'DWord' -Value 1 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableWindowsLocationProvider' -Type 'DWORD' -Value 1 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocationScripting' -Type 'DWORD' -Value 1 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation' -Value 1 -Type 'DWORD' -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Name 'SensorPermissionState' -Value 0 -Type 'DWORD' -Force",
    "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Name 'Value' -Type 'String' -Value 'Deny' -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name 'Value' -Value 'Deny' -Force",
    "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration' -Name 'Status' -Value 0 -Type 'DWORD' -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity' -Name 'Value' -Value 'Deny' -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessMotion' -Type 'DWORD' -Value 2 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessPhone' -Type 'DWORD' -Value 2 -Force",
    "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}' -Type 'String' -Name 'Value' -Value 'DENY' -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessTrustedDevices' -Type 'DWORD' -Value 2 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsSyncWithDevices' -Type 'DWORD' -Value 2 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics' -Name 'Value' -Value 'Deny' -Type 'String' -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsGetDiagnosticInfo' -Type 'DWORD' -Value 2 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts' -Name 'Value' -Value 'Deny' -Type 'String' -Force",
    "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}' -Type 'String' -Name 'Value' -Value 'DENY' -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessContacts' -Type 'DWORD' -Value 2 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener' -Name 'Value' -Value 'Deny' -Type 'String' -Force",
    "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}' -Type 'String' -Name 'Value' -Value 'DENY' -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessNotifications' -Type 'DWORD' -Value 2 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments' -Name 'Value' -Value 'Deny' -Type 'String' -Force",
    "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}' -Type 'String' -Name 'Value' -Value 'DENY' -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessCalendar' -Type 'DWORD' -Value 2 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory' -Name 'Value' -Value 'Deny' -Type 'String' -Force",
    "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}' -Type 'String' -Name 'Value' -Value 'DENY' -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessCallHistory' -Type 'DWORD' -Value 2 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email' -Name 'Value' -Value 'Deny' -Type 'String' -Force",
    "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}' -Type 'String' -Name 'Value' -Value 'DENY' -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessEmail' -Type 'DWORD' -Value 2 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks' -Name 'Value' -Value 'Deny' -Type 'String' -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessTasks' -Type 'DWORD' -Value 2 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat' -Name 'Value' -Value 'Deny' -Type 'String' -Force",
    "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}' -Type 'String' -Name 'Value' -Value 'DENY' -Force",
    "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}' -Type 'String' -Name 'Value' -Value 'DENY' -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessMessaging' -Type 'DWORD' -Value 2 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios' -Name 'Value' -Value 'Deny' -Type 'String' -Force",
    "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}' -Type 'String' -Name 'Value' -Value 'DENY' -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessRadios' -Type 'DWORD' -Value 2 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync' -Name 'Value' -Value 'Deny' -Type 'String' -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata' -Name 'PreventDeviceMetadataFromNetwork' -Type 'DWORD' -Value 1 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata' -Name 'PreventDeviceMetadataFromNetwork' -Type 'DWORD' -Value 1 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'ExcludeWUDriversInQualityUpdate' -Type 'DWORD' -Value 1 -Force",
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' -Name 'SearchOrderConfig' -Type 'DWORD' -Value 0 -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type 'DWORD' -Value 0 -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat' -Name 'AITEnable' -Type 'DWORD' -Value 0 -Force",
    "Set-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Services\DiagTrack' -Name 'Start' -Type 'DWORD' -Value 4 -Force",
    "Set-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Services\dmwappushsvc' -Name 'Start' -Type 'DWORD' -Value 4 -Force",
    "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice' -Name 'Start' -Type 'DWORD' -Value 4 -Force",
    "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service' -Name 'Start' -Type 'DWORD' -Value 4 -Force"
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Value 0 -Type 'DWORD' -Force"
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type 'DWORD' -Value 0 -Force"
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type 'DWORD' -Value 0 -Force"
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'LimitEnhancedDiagnosticDataWindowsAnalytics' -Type 'DWORD' -Value 0 -Force"
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type 'DWORD' -Value 0 -Force"
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform' -Name 'NoGenTicket' -Type 'DWORD' -Value 1 -Force"
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Type 'DWORD' -Value 1 -Force"
    "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Type 'DWORD' -Value 1 -Force"
    "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent' -Name 'DefaultConsent' -Type 'DWORD' -Value 0 -Force"
    "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent' -Name 'DefaultOverrideBehavior' -Type 'DWORD' -Value 1 -Force"
    "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\Windows Error Reporting' -Name 'DontSendAdditionalData' -Type 'DWORD' -Value 1 -Force"
    "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\Windows Error Reporting' -Name 'LoggingDisabled' -Type 'DWORD' -Value 1 -Force"


    # Disable Bing Search and Cortana-related Telemetry
    "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' -Name 'BingSearchEnabled' -Type 'DWORD' -Value 0 -Force",
    "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' -Name 'CortanaConsent' -Type 'DWORD' -Value 0 -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Search' -Name 'BingSearchEnabled' -Type 'DWORD' -Value 0 -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Search' -Name 'CortanaConsent' -Type 'DWORD' -Value 0 -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -Type 'DWORD' -Value 0 -Force",
    "New-Item -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\' -Name 'Search' -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Search' -Name 'BingSearchEnabled' -Type 'DWORD' -Value 0 -Force",
    "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules' -Name '{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}' -Type 'String' -Value  'BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search and Cortana application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|' -Force",

    # Disable Windows Update Auto Updates and Driver Updates
    "New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\' -Name 'AU' -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Type 'DWORD' -Value 0 -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AUOptions' -Type 'DWORD' -Value 2 -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'ScheduledInstallDay' -Type 'DWORD' -Value 0 -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'ScheduledInstallTime' -Type 'DWORD' -Value 3 -Force",
    "New-Item -Path 'HKLM:\Software\Microsoft\PolicyManager\current\device\' -Name 'Update' -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\PolicyManager\current\device\Update' -Name 'ExcludeWUDriversInQualityUpdate' -Type 'DWORD' -Value 1 -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\PolicyManager\default\Update' -Name 'ExcludeWUDriversInQualityUpdate' -Type 'DWORD' -Value 1 -Force",
    "New-Item -Path 'HKLM:\Software\Microsoft\PolicyManager\default\Update\' -Name 'ExcludeWUDriversInQualityUpdates' -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdates' -Name 'Value' -Type 'DWORD' -Value 1 -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings' -Name 'ExcludeWUDriversInQualityUpdate' -Type 'DWORD' -Value 1 -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -Name 'ExcludeWUDriversInQualityUpdate' -Type 'DWORD' -Value 1 -Force",

    # Disable Edge Features and Game DVR
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\WMDRM' -Name 'DisableOnline' -Type 'DWORD' -Value 1 -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Edge' -Name 'BlockThirdPartyCookies' -Type 'DWORD' -Value 1 -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Edge' -Name 'AutofillCreditCardEnabled' -Type 'DWORD' -Value 0 -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Edge' -Name 'SyncDisabled' -Type 'DWORD' -Value 1 -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main' -Name 'AllowPrelaunch' -Type 'DWORD' -Value 0 -Force",
    "New-Item -Path 'HKLM:\Software\Policies\Microsoft\MicrosoftEdge\' -Name 'TabPreloader' -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader' -Name 'AllowTabPreloading' -Type 'DWORD' -Value 0 -Force",
    "New-Item -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\' -Name 'MicrosoftEdge.exe' -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdge.exe' -Name 'Debugger' -Type 'String' -Value '%windir%\System32\taskkill.exe' -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Edge' -Name 'BackgroundModeEnabled' -Type 'DWORD' -Value 0 -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Microsoft' -Name 'DoNotUpdateToEdgeWithChromium' -Type 'DWORD' -Value 1 -Force",

    # Disable Game DVR and Related Features
    "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\GameDVR' -Name 'AllowgameDVR' -Type 'DWORD' -Value 0 -Force",
    "Set-ItemProperty -Path 'HKCU:\System\GameConfigStore' -Name 'GameDVR_Enabled' -Type 'DWORD' -Value 0 -Force",
    "New-Item -Path 'HKLM:\System\' -Name 'GameConfigStore' -Force",
    "Set-ItemProperty -Path 'HKLM:\System\GameConfigStore' -Name 'GameDVR_Enabled' -Type 'DWORD' -Value 0 -Force",
    "New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\' -Name 'GameDVR' -Force",
    "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' -Name 'AppCaptureEnabled' -Type 'DWORD' -Value 0 -Force",
    "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' -Name 'HistoricalCaptureEnabled' -Type 'DWORD' -Value 0 -Force",
    "New-Item -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\' -Name 'GameDVR' -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\GameDVR' -Name 'AppCaptureEnabled' -Type 'DWORD' -Value 0 -Force",
    "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\GameDVR' -Name 'HistoricalCaptureEnabled' -Type 'DWORD' -Value 0 -Force"
)

# Set variables for disabling unnecessary scheduled tasks
$scheduledTasks = @(
    "Get-ScheduledTask "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Disable-ScheduledTask -Verbose"
    "Get-ScheduledTask "\Microsoft\Windows\Application Experience\ProgramDataUpdater" | Disable-ScheduledTask -Verbose"
    "Get-ScheduledTask "\Microsoft\Windows\Application Experience\StartupAppTask" | Disable-ScheduledTask -Verbose"
    "Get-ScheduledTask "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" | Disable-ScheduledTask -Verbose"
    "Get-ScheduledTask "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Disable-ScheduledTask -Verbose"
)
    
# Set variables for Services to disable
$Services = @(
    "Xbox*Service",
    "wercplsupport",
    "WerSvc",
    "WMPNetworkSvc",
    "WSearch",
    "DoSvc",
    "DiagTrack",
    "dmwappushservice"
)

#########################################################
# Tasks
#########################################################

# Remove unneeded files
Write-Host "Remove unneeded files..." -ForegroundColor Yellow
foreach ($directory in $directories) {
    if (Test-Path -Path $directory) {
        $files = Get-ChildItem -Path $directory -Recurse -Include $fileExtensions -ErrorAction SilentlyContinue
        if ($files) {
            foreach ($file in $files) {
                Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Removed file: $($file.FullName)"
            }
        }
    }
}

# Uninstall unneeded applications
Write-Host "Debloating..." -ForegroundColor Yellow
foreach ($application in $applications) {
    if (Get-AppxPackage -Name $application -ErrorAction SilentlyContinue) {
        Get-AppxPackage -Name $application -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Uninstalled application: $application"
    }
}

# Perform additional cleanup operations
foreach ($operation in $additionalCleanup) {
    Write-Host "Performing additional cleanup operation: $operation" -ForegroundColor Yellow
    Invoke-Expression -Command $operation
    Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Performed additional cleanup operation: $operation."
}

# Disabling unnecessary scheduled tasks
foreach ($operation in $scheduledTasks) {
    Write-Host "Disabling unnecessary scheduled tasks: $operation" -ForegroundColor Yellow
    Invoke-Expression -Command $operation
    Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Disabling unnecessary scheduled tasks: $operation."
}

# Disable Services
Write-Host "Stopping and disabling unnecessary services..." -ForegroundColor Yellow
foreach ($service in $Services) {
    $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
    if ($serviceObj) {
        try {
            # Stop the service
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Write-Host "$service has been stopped." -ForegroundColor Green

            # Disable the service
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "$service has been disabled." -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to stop/disable $service: $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Service $service not found." -ForegroundColor Red
    }
}

# Clean recycle bin
Write-Host "Cleaning up recycle bin files older than 30 days..." -ForegroundColor Yellow
Get-ChildItem -Path "$env:SystemDrive\$Recycle.Bin" -Recurse | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force

################################################################
Write-Host "Performing Hardening Tasks..." -ForegroundColor Blue
################################################################

############## Disable Windows Store Reinstallations ############## 

# Disable automatic reinstall of removed apps
Write-Host "Disabling automatic reinstall of removed apps..." -ForegroundColor Yellow

# Disable the 'Allow automatic updates' for Microsoft Store apps
$storePolicyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\PolicyManager\AllowAutoUpdate"
if (Test-Path $storePolicyPath) {
    Set-ItemProperty -Path $storePolicyPath -Name "AllowAutoUpdate" -Value 0 -Force
    Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Disabled auto updates for Microsoft Store apps."
}

# Prevent reinstallation of uninstalled apps
$registryPathsToRemove = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Link",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Uninstall"
)
foreach ($path in $registryPathsToRemove) {
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force
        Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Removed registry key to prevent reinstallation: $path."
    }
}

############## Registry Changes to Ensure Apps Do Not Reappear ############## 

# Additional registry tweaks to make sure uninstalled apps don't reappear
Write-Host "Preventing apps from reappearing..." -ForegroundColor Yellow

# Remove OneDrive and other system apps from reappearing
$oneDriveRegistryPath = "HKCU:\Software\Microsoft\OneDrive"
if (Test-Path $oneDriveRegistryPath) {
    Remove-Item -Path $oneDriveRegistryPath -Recurse -Force
    Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Removed OneDrive registry entries to prevent reinstallation."
}

# Remove other default apps' registry keys
$defaultAppPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
)
foreach ($path in $defaultAppPaths) {
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force
        Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Removed default app registry keys to prevent reinstallation."
    }
}

# Prevent Windows from automatically reinstalling apps like OneDrive, etc.
$disableReinstallAppsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if (-not (Test-Path $disableReinstallAppsPath)) {
    New-Item -Path $disableReinstallAppsPath -Force
}
Set-ItemProperty -Path $disableReinstallAppsPath -Name "NoReinstall" -Value 1 -Force
Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Prevented automatic reinstallation of apps."

# Disable weak ciphers
Write-Host "Disabling weak ciphers..." -ForegroundColor Blue

$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56"
if (Test-Path $registryPath) {
    Set-ItemProperty -Path $registryPath -Name "Enabled" -Value 0 -Force
    Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Disabled weak cipher DES."
}

$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128"
if (Test-Path $registryPath) {
    Set-ItemProperty -Path $registryPath -Name "Enabled" -Value 0 -Force
    Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Disabled weak cipher RC2."
}

$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128"
if (Test-Path $registryPath) {
    Set-ItemProperty -Path $registryPath -Name "Enabled" -Value 0 -Force
    Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Disabled weak cipher RC2."
}

# Disable SSLv3 and TLS 1.0
Write-Host "Disabling SSLv3 and TLS 1.0..." -ForegroundColor Blue

$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
if (Test-Path $registryPath) {
    Set-ItemProperty -Path $registryPath -Name "Enabled" -Value 0 -Force
    Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Disabled SSL 3."
}

$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
if (Test-Path $registryPath) {
    Set-ItemProperty -Path $registryPath -Name "Enabled" -Value 0 -Force
    Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Disabled TLS 1.0."
}

# Set stronger password policies
Write-Host "Setting stronger password policies..." -ForegroundColor Blue
$policy = Get-WmiObject -Class Win32_AccountPolicy -Namespace "root\rsop\computer"
$policy.SetPasswordComplexity(1)
$policy.MinimumPasswordLength = 12
$policy.MaxPasswordAge = (New-TimeSpan -Days 90).Ticks
$policy.MaxBadPasswordsAllowed = 5
$policy.PasswordHistorySize = 10
$policy.Put()

#########################################################
# Done
#########################################################

Write-Host "Hardening and debloating complete." -ForegroundColor Green
Write-Host "Logs are stored in $logFilePath..." -ForegroundColor Green
