# Check if the script is running as an admin
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    # Relaunch as an administrator
    Start-Process powershell.exe -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $MyInvocation.MyCommand.Definition) -Verb RunAs
    exit
}

# Function to set the console properties
function Set-ConsoleProperties {
    $Host.UI.RawUI.WindowTitle = "UltimateCleanup | IBRPRIDE"
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

function UltimateCleanup {
    [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null
    $msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Do You Want to Clear All Event Viewer Logs?', 'zoicware', 'YesNo', 'Question')

    switch ($msgBoxInput) {
        'Yes' {
            # Clear event viewer logs
            Write-Host 'Clearing Event Viewer Logs...'
            wevtutil el | ForEach-Object { wevtutil cl "$_" >$null 2>&1 }
        }
        'No' { }
    }

    # Cleanup temp files
    $temp1 = 'C:\Windows\Temp'
    $temp2 = $env:TEMP
    Write-Host "Cleaning Temp Files in $temp1, $temp2"
    $tempFiles = Get-ChildItem -Path $temp1, $temp2 -Recurse -Force
    foreach ($file in $tempFiles) {
        try {
            Remove-Item -Path $file.FullName -Recurse -Force -ErrorAction Stop
        } catch {
            Write-Host "Failed to delete $($file.FullName)"
        }
    }

    Write-Host 'Running Disk Cleanup...'
    $key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
    $options = @(
        'Active Setup Temp Folders'
        'Thumbnail Cache'
        'Delivery Optimization Files'
        'D3D Shader Cache'
        'Downloaded Program Files'
        'Internet Cache Files'
        'Setup Log Files'
        'Temporary Files'
        'Windows Error Reporting Files'
        'Offline Pages Files'
        'Recycle Bin'
        'Temporary Setup Files'
        'Update Cleanup'
        'Upgrade Discarded Files'
        'Windows Defender'
        'Windows ESD installation files'
        'Windows Reset Log Files'
        'Windows Upgrade Log Files'
        'Previous Installations'
        'Old ChkDsk Files'
        'Feedback Hub Archive log files'
        'Diagnostic Data Viewer database files'
        'Device Driver Packages'
    )
    foreach ($option in $options) {
        try {
            reg.exe add "$key\$option" /v StateFlags0069 /t REG_DWORD /d 00000002 /f >$null 2>&1
        } catch {
            Write-Host "Failed to set flag for $option"
        }
    }

    # Run Disk Cleanup
    Start-Process cleanmgr.exe -ArgumentList '/sagerun:69 /autoclean'
}

UltimateCleanup
