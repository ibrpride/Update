# Check if the script is running as an admin
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    # Relaunch as an administrator
    Start-Process powershell.exe -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $MyInvocation.MyCommand.Definition) -Verb RunAs
    exit
}

# Function to set the console properties
function Set-ConsoleProperties {
    $Host.UI.RawUI.WindowTitle = "Summary Update v0.1 | @IBR HUB"
    $Host.UI.RawUI.BackgroundColor = "Black"
    $Host.PrivateData.ProgressBackgroundColor = "Black"
    $Host.PrivateData.ProgressForegroundColor = "White"
    Clear-Host
}

Set-ConsoleProperties



# Set Console Opacity Transparent
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class ConsoleOpacity {
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetLayeredWindowAttributes(IntPtr hwnd, uint crKey, byte bAlpha, uint dwFlags);

    private const uint LWA_ALPHA = 0x00000002;

    public static void SetOpacity(byte opacity) {
        IntPtr hwnd = GetConsoleWindow();
        if (hwnd == IntPtr.Zero) {
            throw new InvalidOperationException("Failed to get console window handle.");
        }
        bool result = SetLayeredWindowAttributes(hwnd, 0, opacity, LWA_ALPHA);
        if (!result) {
            throw new InvalidOperationException("Failed to set window opacity.");
        }
    }
}
"@

try {
    # Set opacity (0-255, where 255 is fully opaque and 0 is fully transparent)
    [ConsoleOpacity]::SetOpacity(230)
    Write-Host "Console opacity set successfully." -ForegroundColor Green
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}

Clear-Host


function Show-Agreement {
    Clear-Host
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host "                                                Update Agreement" -ForegroundColor Green
    Write-Host ""
    Write-Host "                        _________________________________________________________________"
    Write-Host ""
    Write-Host "                    You agree that the update can improve performance or make performance worse." -ForegroundColor Yellow
    Write-Host "                  _______________________________________________________________________________"
	Write-Host ""
	Write-Host ""
	Write-Host ""
    
    while ($true) {
        $input = Read-Host "                                            Type 'AGREE' to continue"
        if ($input -eq "AGREE") {
            break
        } else {
            Write-Host "                                        Incorrect input. Please type 'AGREE' to continue..." -ForegroundColor Red
        }
    }
}

Show-Agreement


# Function to display modern progress bar
function Show-Progress {
    param (
        [int]$percentComplete,
        [string]$statusMessage,
        [switch]$isError
    )

    $progressBar = ""
    $completed = [math]::Floor($percentComplete / 2)
    $remaining = 50 - $completed

    for ($i = 0; $i -lt $completed; $i++) {
        $progressBar += [char]0x2588
    }
    for ($i = 0; $i -lt $remaining; $i++) {
        $progressBar += [char]0x2591
    }

    cls
    if ($isError) {
        Write-Host "Summary Update v0.1 Encountered an Error..." -ForegroundColor Red
    } else {
        Write-Host "Summary Update v0.1 in Progress..." -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "Updating: [$progressBar] $percentComplete%" -ForegroundColor Green
    Write-Host ""
    Write-Host $statusMessage -ForegroundColor Yellow
}

# Custom update messages
$updateMessages = @(
    "Downloading updates...",
    "Installing critical updates...",
    "Configuring new settings...",
    "Optimizing system performance...",
    "Finalizing update installation...",
    "Cleaning up temporary files...",
    "Applying final touches...",
    "Restarting necessary services...",
    "Verifying update integrity...",
    "Backing up current settings...",
    "Checking disk space...",
    "Updating drivers...",
    "Removing outdated files...",
    "Disabling OneDrive...",
    "Disabling Cortana...",
    "Disabling startup apps...",
    "Disabling transparency...",
    "Disabling recent and mostly used items...",
    "Disabling search highlights...",
    "Optimizing mouse settings...",
    "Disabling Firefox Telemetry...",
    "Disabling Chrome Telemetry...",
    "Disabling Edge Telemetry...",
    "Optimizing browser background activity...",
    "Disabling hardware acceleration for browsers...",
    "Disabling browser updates...",
    "Disabling WU auto-reboot...",
    "Disabling Delivery Optimization...",
    "Disabling feature updates...",
    "Restricting Windows Insider...",
    "Disabling MSRT telemetry...",
    "Disabling WU nagging..."
)

# Simulated errors
$errors = @(
    "Error: Failed to download update files. Retrying...",
    "Error: Installation package corrupted. Restarting...",
    "Error: Insufficient disk space. Freeing up space...",
    "Error: Network connection lost. Reconnecting..."
)

# Main script
Write-Host "Initiating Summary Update v0.1..." -ForegroundColor Green
Start-Sleep -Seconds 3
cls

$random = New-Object System.Random

for ($progress = 0; $progress -le 100; $progress++) {
    $statusMessage = ""
    $isError = $false
    if ($random.Next(1, 100) -le 5) {
        $statusMessage = $errors[$random.Next(0, $errors.Length)]
        $isError = $true
        Start-Sleep -Seconds 2
    } elseif ($progress -le 4) {
        $statusMessage = $updateMessages[0]
        Start-Sleep -Milliseconds 50
    } elseif ($progress -le 8) {
        $statusMessage = $updateMessages[1]
        Start-Sleep -Milliseconds 10
    } elseif ($progress -le 12) {
        $statusMessage = $updateMessages[2]
        Start-Sleep -Milliseconds 15
    } elseif ($progress -le 16) {
        $statusMessage = $updateMessages[3]
        Start-Sleep -Milliseconds 10
	# Remove Mouse and Sound Schemes
	Reg.exe add 'HKCU\AppEvents\Schemes' /ve /t REG_SZ /d '.None' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\.Default\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\.Default\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\MailBeep\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\MailBeep\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\SystemHand\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\SystemHand\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current' /f
        Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current' /f
        Reg.exe add 'HKCU\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current' /f
        Reg.exe add 'HKCU\Control Panel\Cursors' /v 'ContactVisualization' /t REG_DWORD /d '0' /f
        Reg.exe add 'HKCU\Control Panel\Cursors' /v 'GestureVisualization' /t REG_DWORD /d '0' /f
        Reg.exe add 'HKCU\Control Panel\Cursors' /v 'Scheme Source' /t REG_DWORD /d '0' /f
        Reg.exe add 'HKCU\Control Panel\Cursors' /ve /t REG_SZ /d ' ' /f
        Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'AppStarting' -Force
        Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'Arrow' -Force
        Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'Crosshair' -Force -ErrorAction SilentlyContinue
        Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'Hand' -Force
        Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'IBeam' -Force -ErrorAction SilentlyContinue
        Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'No' -Force
        Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'NWPen' -Force
        Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'SizeAll' -Force
        Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'SizeNESW' -Force
        Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'SizeNS' -Force
        Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'SizeNWSE' -Force
        Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'SizeWE' -Force
        Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'UpArrow' -Force
        Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'Wait' -Force
    } elseif ($progress -le 20) {
        $statusMessage = $updateMessages[4]
        Start-Sleep -Milliseconds 20
		# Disable Windows Tracking & Telemetry services
		Stop-Service -Name "DiagTrack" -Force -ErrorAction SilentlyContinue
		Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v "Start" /t REG_DWORD /d "4" /f  
		Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f  
		Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f  
		Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f  
		Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f  
		Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f  
		Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\DcpSvc" /v "Start" /t REG_DWORD /d "4" /f  
		Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f  
		Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f  
		Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f  
		Remove-Item "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\DiagTrack*" -ErrorAction SilentlyContinue
		Remove-Item "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\ShutdownLogger\DiagTrack*" -ErrorAction SilentlyContinue
    } elseif ($progress -le 24) {
        $statusMessage = $updateMessages[5]
        Start-Sleep -Milliseconds 10
		Reg.exe Add "HKCU\Control Panel\Accessibility" /v "Sound on Activation" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\Control Panel\Accessibility" /v "Warning Sounds" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\SOFTWARE\Microsoft\ScreenMagnifier" /v "FollowCaret" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\SOFTWARE\Microsoft\ScreenMagnifier" /v "FollowNarrator" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\SOFTWARE\Microsoft\ScreenMagnifier" /v "FollowMouse" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\SOFTWARE\Microsoft\ScreenMagnifier" /v "FollowFocus" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "DuckAudio" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "WinEnterLaunchEnabled" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "ScriptingEnabled" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "OnlineServicesEnabled" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "EchoToggleKeys" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\Software\Microsoft\Ease of Access" /v "selfvoice" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\Software\Microsoft\Ease of Access" /v "selfscan" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\Software\Microsoft\Narrator" /v "NarratorCursorHighlight" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\Software\Microsoft\Narrator" /v "CoupleNarratorCursorKeyboard" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\Software\Microsoft\Narrator" /v "IntonationPause" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\Software\Microsoft\Narrator" /v "ReadHints" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\Software\Microsoft\Narrator" /v "ErrorNotificationType" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\Software\Microsoft\Narrator" /v "EchoChars" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\Software\Microsoft\Narrator" /v "EchoWords" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\SOFTWARE\Microsoft\Narrator\NarratorHome" /v "MinimizeType" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\SOFTWARE\Microsoft\Narrator\NarratorHome" /v "AutoStart" /t REG_DWORD /d 0 /f 
		Reg.exe Add "HKCU\Control Panel\Accessibility\HighContrast" /v "Flags" /t REG_SZ /d "4194" /f 
		Reg.exe Add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "2" /f 
		Reg.exe Add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "2" /f 
		Reg.exe Add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "2" /f 
		Reg.exe Add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "34" /f 
		Reg.exe Add "HKCU\Control Panel\Accessibility\SoundSentry" /v "Flags" /t REG_SZ /d "2" /f 
		Reg.exe Add "HKCU\Control Panel\Accessibility\SlateLaunch" /v "ATapp" /f 
		Reg.exe Add "HKCU\Control Panel\Accessibility\SlateLaunch" /v "LaunchAT" /t REG_DWORD /d "0" /f 
    } elseif ($progress -le 28) {
        $statusMessage = $updateMessages[6]
        Start-Sleep -Milliseconds 50
		# Disabling Startup Apps
		Reg.exe Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Discord" /t REG_BINARY /d "0300000066AF9C7C5A46D901" /f 
		Reg.exe Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Synapse3" /t REG_BINARY /d "030000007DC437B0EA9FD901" /f 
		Reg.exe Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Spotify" /t REG_BINARY /d "0300000070E93D7B5A46D901" /f 
		Reg.exe Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "EpicGamesLauncher" /t REG_BINARY /d "03000000F51C70A77A48D901" /f 
		Reg.exe Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "RiotClient" /t REG_BINARY /d "03000000A0EA598A88B2D901" /f 
		Reg.exe Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Steam" /t REG_BINARY /d "03000000E7766B83316FD901" /f 
    } elseif ($progress -le 32) {
        $statusMessage = $updateMessages[7]
        Start-Sleep -Milliseconds 30
		# Disable Fax & Print
		# The Fax & Print feature in Windows enables functionality for sending/receiving faxes and managing printers. Disabling Fax & Print can be beneficial for those who do not require faxing capabilities or want to optimize system resources by reducing background services related to fax and printing.
		Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\Fax" /v "Start" /t REG_DWORD /d "4" /f 
		Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f 
    } elseif ($progress -le 36) {
        $statusMessage = $updateMessages[8]
        Start-Sleep -Milliseconds 30
		# Set JPEG Wallpaper quality to 100%
		Reg.exe Add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f > $null
    } elseif ($progress -le 40) {
        $statusMessage = $updateMessages[9]
        Start-Sleep -Milliseconds 200
		# Set registry values to bypass requirements
		reg add "HKLM\SYSTEM\Setup\LabConfig" /v BypassSecureBootCheck /t REG_DWORD /d 1 /f
		reg add "HKLM\SYSTEM\Setup\LabConfig" /v BypassTPMCheck /t REG_DWORD /d 1 /f
		reg add "HKLM\SYSTEM\Setup\LabConfig" /v BypassCPUCheck /t REG_DWORD /d 1 /f
		reg add "HKLM\SYSTEM\Setup\LabConfig" /v BypassRAMCheck /t REG_DWORD /d 1 /f
		reg add "HKLM\SYSTEM\Setup\LabConfig" /v BypassStorageCheck /t REG_DWORD /d 1 /f
		reg add "HKLM\SYSTEM\Setup\MoSetup" /v AllowUpgradesWithUnsupportedTPMOrCPU /t REG_DWORD /d 1 /f
		reg add "HKCU\Control Panel\UnsupportedHardwareNotificationCache" /v SV1 /t REG_DWORD /d 0 /f
		reg add "HKCU\Control Panel\UnsupportedHardwareNotificationCache" /v SV2 /t REG_DWORD /d 0 /f
		reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v BypassNRO /t REG_DWORD /d 1 /f
    } elseif ($progress -le 44) {
        $statusMessage = $updateMessages[10]
        Start-Sleep -Milliseconds 20
    } elseif ($progress -le 48) {
        $statusMessage = $updateMessages[11]
        Start-Sleep -Milliseconds 20
    } elseif ($progress -le 52) {
        $statusMessage = $updateMessages[12]
        Start-Sleep -Milliseconds 20
    } elseif ($progress -le 56) {
        $statusMessage = $updateMessages[13]
        Start-Sleep -Milliseconds 20
        # Disabling OneDrive
        Reg.exe Add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v "Attributes" /t REG_DWORD /d "0" 
        Reg.exe Add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v "Attributes" /t REG_DWORD /d "0" 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d "0" /f 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d "0" /f 
    } elseif ($progress -le 60) {
        $statusMessage = $updateMessages[14]
        Start-Sleep -Milliseconds 200
        # Disabling Cortana
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "0" /f 
    } elseif ($progress -le 64) {
        $statusMessage = $updateMessages[15]
        Start-Sleep -Milliseconds 200
        # Disabling Startup Apps
        Reg.exe Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Discord" /t REG_BINARY /d "0300000066AF9C7C5A46D901" /f 
        Reg.exe Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Synapse3" /t REG_BINARY /d "030000007DC437B0EA9FD901" /f 
        Reg.exe Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Spotify" /t REG_BINARY /d "0300000070E93D7B5A46D901" /f 
        Reg.exe Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "EpicGamesLauncher" /t REG_BINARY /d "03000000F51C70A77A48D901" /f 
        Reg.exe Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "RiotClient" /t REG_BINARY /d "03000000A0EA598A88B2D901" /f 
        Reg.exe Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Steam" /t REG_BINARY /d "03000000E7766B83316FD901" /f 
    } elseif ($progress -le 68) {
        $statusMessage = $updateMessages[16]
        Start-Sleep -Milliseconds 200
        # Disabling Transparency
        Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d 0 /f 
    } elseif ($progress -le 72) {
        $statusMessage = $updateMessages[17]
        Start-Sleep -Milliseconds 200
        # Disabling Recent and Mostly Used Items
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d 1 /f 
        Reg.exe Delete "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecentlyAddedApps" /f 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d 1 /f 
        Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d 0 /f 
        Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 0 /f 
        Reg.exe Delete "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "ShowOrHideMostUsedApps" /f 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "ShowOrHideMostUsedApps" /t REG_DWORD /d 2 /f 
        Reg.exe Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoStartMenuMFUprogramsList" /f 
        Reg.exe Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f 
        Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSh" /t REG_DWORD /d 0 /f 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "ShowOrHideMostUsedApps" /t REG_DWORD /d 0 /f 
    } elseif ($progress -le 76) {
        $statusMessage = $updateMessages[18]
        Start-Sleep -Milliseconds 200
        # Disabling Search Highlights
        Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDynamicSearchBoxEnabled" /t REG_DWORD /d 0 /f 
        Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds\DSB" /v "ShowDynamicContent" /t REG_DWORD /d 0 /f
	Reg.exe add 'HKCR\Microsoft.PowerShellScript.1\Shell\Open\Command' /ve /t REG_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noLogo -executionpolicy bypass -file `"`"%1`"`"" /f
    } elseif ($progress -le 80) {
        $statusMessage = $updateMessages[19]
        Start-Sleep -Milliseconds 200
        # Mouse Optimizations
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class DPI {
    [DllImport("User32.dll")]
    public static extern int GetDpiForWindow(IntPtr hwnd);
    
    public static int GetDPI() {
        var hwnd = GetForegroundWindow();
        return GetDpiForWindow(hwnd);
    }

    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
}
"@

        $DPI = [DPI]::GetDPI()

        $ScalePercentage = switch ($DPI) {
		 
            96 {"100%"}
            120 {"125%"}
            144 {"150%"}
            192 {"200%"}
            default {"Unknown"}
        }

        Reg.exe Add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /F 
        Reg.exe Add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /F 
        Reg.exe Add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /F 
        Reg.exe Add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /F 
        Reg.exe Add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000A800000000000000E00000000000" /F 

        if ($ScalePercentage -eq "100%") {
            reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000C0CC0C0000000000809919000000000040662600000000000033330000000000" /F 
        }

        if ($ScalePercentage -eq "125%") {
            reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "00000000000000000000100000000000000020000000000000003000000000000000400000000000" /F 
        }

        if ($ScalePercentage -eq "150%") {
            reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000303313000000000060662600000000009099390000000000C0CC4C0000000000" /F 
        }

        if ($ScalePercentage -eq "175%") {
            reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "00000000000000006066160000000000C0CC2C000000000020334300000000008099590000000000" /F 
        }

        if ($ScalePercentage -eq "200%") {
            reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "000000000000000090991900000000002033330000000000B0CC4C00000000004066660000000000" /F 
        }

        Reg.exe Add "HKCU\Control Panel\Desktop" /v "LogPixels" /t REG_DWORD /d 96 /F 
        Reg.exe Add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "UseDpiScaling" /t REG_DWORD /d 0 /F 
        Reg.exe Add "HKCU\Control Panel\Desktop" /v "EnablePerProcessSystemDPI" /t REG_DWORD /d 0 /F 
    } elseif ($progress -le 84) {
        $statusMessage = $updateMessages[20]
        Start-Sleep -Milliseconds 200
        # Disabling Firefox Telemetry
        Reg.exe Add "HKLM\SOFTWARE\Policies\Mozilla\Firefox" /v "DisableTelemetry" /t REG_DWORD /d "1" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Mozilla\Firefox" /v "DisableDefaultBrowserAgent" /t REG_DWORD /d "1" /f  
        Reg.exe Add "HKCU\SOFTWARE\Policies\Mozilla\Firefox" /v "DisableTelemetry" /t REG_DWORD /d "1" /f 
    } elseif ($progress -le 88) {
        $statusMessage = $updateMessages[21]
        Start-Sleep -Milliseconds 200
        # Disabling Chrome Telemetry
        Reg.exe Add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DeviceMetricsReportingEnabled" /t REG_DWORD /d "0" /f  
    } elseif ($progress -le 92) {
        $statusMessage = $updateMessages[22]
        Start-Sleep -Milliseconds 200
        # Disabling Edge Telemetry
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "HubsSidebarEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "WebWidgetAllowed" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "PersonalizationReportingEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "SpotlightExperiencesAndRecommendationsEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "LocalProvidersEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "AddressBarMicrosoftSearchInBingProviderEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "ConfigureDoNotTrack" /t REG_DWORD /d "1" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "SearchSuggestEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary" /v "EnableExtendedBooksTelemetry" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "Use FormSuggest" /t REG_SZ /d "no" /f  
        Reg.exe Add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "ShowSearchSuggestionsGlobal" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "DoNotTrack" /t REG_DWORD /d "1" /f  
        Reg.exe Add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "OptimizeWindowsSearchResultsForScreenReaders" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" /v "FPEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" /v "ShowSearchSuggestionsGlobal" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" /v "EnableEncryptedMediaExtensions" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI\ShowSearchHistory" /d "0" /f 
	
	Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v 'AllowTelemetry' /t REG_DWORD /d '0' /f
        Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' /v 'AllowTelemetry' /t REG_DWORD /d '0' /f
        Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' /v 'MaxTelemetryAllowed' /t REG_DWORD /d '0' /f
        Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack' /v 'Start' /t REG_DWORD /d '4' /f
        Reg.exe add 'HKLM\System\ControlSet001\Services\dmwappushservice' /v 'Start' /t REG_DWORD /d '4' /f
        Reg.exe add 'HKLM\System\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener' /v 'Start' /t REG_DWORD /d '0' /f
        Reg.exe add 'HKLM\Software\Policies\Microsoft\Biometrics' /v 'Enabled' /t REG_DWORD /d '0' /f
  
 
        Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser' -ErrorAction SilentlyContinue
        Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\ProgramDataUpdater' -ErrorAction SilentlyContinue
        Disable-ScheduledTask -TaskName 'Microsoft\Windows\Autochk\Proxy' -ErrorAction SilentlyContinue
        Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\Consolidator' -ErrorAction SilentlyContinue
        Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\UsbCeip' -ErrorAction SilentlyContinue
        Disable-ScheduledTask -TaskName 'Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector' -ErrorAction SilentlyContinue

        Write-Host 'Defering Optional Updates for 30 days(MAX)'
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetAllowOptionalContent' /t REG_DWORD /d '0' /f >$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdates' /t REG_DWORD /d '1' /f >$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdatesPeriodInDays' /t REG_DWORD /d '365' /f >$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdates' /t REG_DWORD /d '1' /f >$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdatesPeriodInDays' /t REG_DWORD /d '30' /f >$null
        gpupdate /force
    }
    } elseif ($progress -le 94) {
        $statusMessage = $updateMessages[23]
        Start-Sleep -Milliseconds 250
        # Optimizing browser background activity
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "StartupBoostEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "BatterySaverModeAvailability" /t REG_DWORD /d "1" /f  

        Reg.exe Add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "StartupBoostEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "HighEfficiencyModeEnabled" /t REG_DWORD /d "1" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BatterySaverModeAvailability" /t REG_DWORD /d "1" /f  

        Reg.exe Add "HKLM\Software\Policies\BraveSoftware\Brave" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\Software\Policies\BraveSoftware\Brave" /v "HighEfficiencyModeEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\Software\Policies\BraveSoftware\Brave" /v "BatterySaverModeAvailability" /t REG_DWORD /d "0" /f  

        Reg.exe Add "HKLM\Software\Policies\BraveSoftware\Brave\Recommended" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\Software\Policies\BraveSoftware\Brave\Recommended" /v "BatterySaverModeAvailability" /t REG_DWORD /d "1" /f 
    } elseif ($progress -le 96) {
        $statusMessage = $updateMessages[24]
        Start-Sleep -Milliseconds 200
        # Disabling hardware acceleration for browsers
        Reg.exe Add "HKLM\SOFTWARE\Policies\Mozilla\Firefox" /v "HardwareAcceleration" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "HardwareAccelerationModeEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "HardwareAccelerationModeEnabled" /t REG_DWORD /d "0" /f  
        Reg.exe Add "HKLM\Software\Policies\BraveSoftware\Brave" /v "HardwareAccelerationModeEnabled" /t REG_DWORD /d "0" /f  
    } elseif ($progress -le 98) {
        $statusMessage = $updateMessages[25]
        Start-Sleep -Milliseconds 200
        # Disabling browser updates
        # Edge
        Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" /v "Start" /t REG_DWORD /d 4 /f  
        Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" /v "Start" /t REG_DWORD /d 4 /f  
        Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d 4 /f  
        Reg.exe Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineCore" /f  
        Reg.exe Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineUA" /f  
        # Chrome
        Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService" /v "Start" /t REG_DWORD /d 4 /f  
        Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\gupdate" /v "Start" /t REG_DWORD /d 4 /f  
        Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\gupdatem" /v "Start" /t REG_DWORD /d 4 /f  
        # Firefox
        Reg.exe Add "HKLM\SOFTWARE\Policies\Mozilla\Firefox" /v "DisableAppUpdate" /t REG_DWORD /d "1" /f  
    } elseif ($progress -le 99) {
        $statusMessage = $updateMessages[26]
        Start-Sleep -Milliseconds 200
        # Disabling WU auto-reboot
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "AUPowerManagement" /t REG_DWORD /d 0 /f 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d 1 /f 
    } elseif ($progress -le 100) {
        $statusMessage = $updateMessages[27]
        Start-Sleep -Milliseconds 200
        # Disabling Delivery Optimization
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d 0 /f 
    } elseif ($progress -le 102) {
        $statusMessage = $updateMessages[28]
        Start-Sleep -Milliseconds 200
        # Disabling feature updates
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "TargetReleaseVersion" /t REG_DWORD /d 1 /f 
        $version = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ProductVersion" /t REG_SZ /d "$version" /f 
    } elseif ($progress -le 104) {
        $statusMessage = $updateMessages[29]
        Start-Sleep -Milliseconds 200
        # Restricting Windows Insider
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ManagePreviewBuilds" /t REG_DWORD /d 1 /f 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ManagePreviewBuildsPolicyValue" /t REG_DWORD /d 0 /f 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d 0 /f 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d 0 /f 
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableExperimentation" /t REG_DWORD /d 0 /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "HideInsiderPage" /t REG_DWORD /d 1 /f 
    } elseif ($progress -le 106) {
        $statusMessage = $updateMessages[30]
        Start-Sleep -Milliseconds 200
        # Disabling MSRT telemetry
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\# ovalTools\MpGears" /v "HeartbeatTrackingIndex" /t REG_DWORD /d 0 /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\# ovalTools\MpGears" /v "SpyNetReportingLocation" /t REG_MULTI_SZ /d "" /f 
    } elseif ($progress -le 108) {
        $statusMessage = $updateMessages[31]
        Start-Sleep -Milliseconds 200
        # Disabling WU nagging
        Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAUAsDefaultShutdownOption" /t REG_DWORD /d 1 /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "HideMCTLink" /t REG_DWORD /d 1 /f 
    } elseif ($progress -le 110) {
        $statusMessage = $updateMessages[32]
        Start-Sleep -Milliseconds 200
        # Disable Network Bandwidth Limiters
        Reg.exe Add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f 
    } elseif ($progress -le 112) {
        $statusMessage = $updateMessages[33]
        Start-Sleep -Milliseconds 200
        # Gaming Optimizations
        # Gaming Optimizations include various system tweaks and settings designed to improve gaming performance on Windows. These optimizations can include adjusting visual effects, disabling background processes, optimizing graphics settings, and prioritizing system resources for the best gaming experience possible. Enabling gaming optimizations can lead to smoother gameplay, reduced input lag, and overall better performance for gaming enthusiasts.
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "8" /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "Medium" /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f 
        Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "0" /f 
		# Enable IBRPRIDE Gaming mode
		Reg.exe Add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "SwapEffectUpgradeEnable=1;VRROptimizeEnable=0;" /f  
    }
    Show-Progress -percentComplete $progress -statusMessage $statusMessage -isError:$isError
}

cls
Write-Host "Summary Update v0.1 Completed Successfully!" -ForegroundColor Green
        Start-Sleep -Milliseconds 200
		cls
Write-Host ""
Write-Host "                                                Summary of Changes:" -ForegroundColor Cyan
Write-Host ""
Write-Host "                        ___________________________________________________________________"
Write-Host ""
Write-Host "Performance" -ForegroundColor Yellow
Write-Host "- General improvements to the operating system"
Write-Host "- Adjustments to the Nvidia Control Panel"
Write-Host "- Fix Power Plan section and add new power plans"
Write-Host "- Configure additional Windows settings"
Write-Host "- Disable P-States"
Write-Host "- Completely disable OneDrive"
Write-Host "- Completely disable Cortana"
Write-Host "- Enhancements to Explorer"
Write-Host "- Disable Unpark cores"
Write-Host "- Disable power-saving options on the mouse and keyboard"
Write-Host "- Enable Msi mode"
Write-Host ""
Write-Host "Privacy" -ForegroundColor Yellow
Write-Host "- Disable Firefox Telemetry"
Write-Host "- Disable Chrome Telemetry"
Write-Host "- Disable Edge Telemetry"
Write-Host "- Disable Taskbar/Start Menu Tracking Telemetry"
Write-Host "- Disable Microsoft data collection"
Write-Host "- Disable Windows tracking tools from collecting data"
Write-Host "- Disable ads in the settings menu | Windows 11 only"
Write-Host "- Disable error reporting in:"
Write-Host "  - Windows"
Write-Host "  - Graphics card drivers"
Write-Host "  - Game launchers"
Write-Host ""
Write-Host "Internet" -ForegroundColor Yellow
Write-Host "- General improvements to Internet settings in Windows"
Write-Host "- Disable power-saving options for the Internet"
Write-Host ""
Write-Host "Additionally, new performance features will replace the temporary file cleaning tools in Windows."
Write-Host ""
Write-Host "Troubleshooting" -ForegroundColor Yellow
Write-Host "- Skip Requirements"
Write-Host "- Enable Clipboard History"
Write-Host "- FIX STEAM ICONS"
Write-Host "- Fix Drag & Drop"
Write-Host "- Fix Summary Update v0.1"
Write-Host "- Windows Defender Firewall"
Write-Host "- Add Thumbnail & Icon Cache Rebuilder"
Write-Host "- Fix Windows password field"
Write-Host ""
Write-Host "Finished, please reboot your device for changes to apply." -ForegroundColor Green
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
