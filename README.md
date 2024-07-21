# Update Script | IBRPRIDE

This PowerShell script simulates a Windows update process with detailed system tweaks and optimizations
It includes various system performance improvements, privacy settings adjustments, and browser optimizations.

## Features

### Performance
- General improvements to the operating system
- Adjustments to the Nvidia Control Panel
- Fix Power Plan section and add new power plans
- Configure additional Windows settings
- Disable P-States
- Completely disable OneDrive
- Completely disable Cortana
- Enhancements to Explorer
- Disable Unpark cores
- Disable power-saving options on the mouse and keyboard
- Enable Msi mode

### Privacy
- Disable Firefox Telemetry
- Disable Chrome Telemetry
- Disable Edge Telemetry
- Disable Taskbar/Start Menu Tracking Telemetry
- Disable Microsoft data collection
- Disable Windows tracking tools from collecting data
- Disable ads in the settings menu | Windows 11 only
- Disable error reporting in:
  - Windows
  - Graphics card drivers
  - Game launchers

### Internet
- General improvements to Internet settings in Windows
- Disable power-saving options for the Internet

### Troubleshooting
- Skip Requirements
- Enable Clipboard History
- FIX STEAM ICONS
- Fix Drag & Drop
- Fix Windows Update
- Windows Defender Firewall
- Add Thumbnail & Icon Cache Rebuilder
- Fix Windows password field

### Additional Optimizations
- Disabling OneDrive
- Disabling Cortana
- Disabling startup apps
- Disabling transparency
- Disabling recent and mostly used items
- Disabling search highlights
- Optimizing mouse settings
- Disabling hardware acceleration for browsers
- Disabling browser updates

### Windows Update Restrictions
- Disable WU Auto-Reboot
- Disable Delivery Optimization
- Disable Feature Updates
- Restrict Windows Insider
- Disable MSRT telemetry
- Disable WU Nagging

## Usage

1. Ensure the script is run with administrative privileges. If not, it will relaunch itself as an administrator.
2. The script displays a simulated update progress bar with various system tweaks.
3. After completion, a summary of changes will be displayed.

## Installation

1. Clone the repository or download the script file.
2. Run the script using PowerShell:
```
iwr -useb https://ibrpride.com/wintools | iex
```
