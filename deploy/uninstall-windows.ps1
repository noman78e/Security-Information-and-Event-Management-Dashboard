# Removes HomeSIEM from Windows. Run from an ADMINISTRATOR PowerShell window.
# Your data in C:\ProgramData\HomeSIEM is kept unless you add -Purge.
param([switch]$Purge)
$ErrorActionPreference = "Continue"
Stop-ScheduledTask -TaskName "HomeSIEM" -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "HomeSIEM" -Confirm:$false -ErrorAction SilentlyContinue
Get-Process homesiem -ErrorAction SilentlyContinue | Stop-Process -Force
Get-NetFirewallRule -DisplayName "HomeSIEM*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Remove-Item "C:\Program Files\HomeSIEM" -Recurse -Force -ErrorAction SilentlyContinue
if ($Purge) { Remove-Item "C:\ProgramData\HomeSIEM" -Recurse -Force -ErrorAction SilentlyContinue; Write-Host "HomeSIEM and all its data were removed." }
else { Write-Host "HomeSIEM was removed. Your data is still in C:\ProgramData\HomeSIEM (use -Purge to delete it)." }
