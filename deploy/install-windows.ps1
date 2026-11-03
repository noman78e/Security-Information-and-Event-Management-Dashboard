# Installs HomeSIEM on Windows so that it starts when the computer starts.
# Run it from an ADMINISTRATOR PowerShell window, in the folder with homesiem-windows.exe:
#   .\install-windows.ps1
param(
  [string]$Exe = ".\homesiem-windows.exe",
  [int]$Port = 8080
)
$ErrorActionPreference = "Stop"

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Please run this script from an administrator PowerShell window." }
if (-not (Test-Path $Exe)) { throw "Cannot find $Exe. Pass the path with -Exe." }

$dir  = "C:\Program Files\HomeSIEM"
$data = "C:\ProgramData\HomeSIEM"
New-Item -ItemType Directory -Force -Path $dir, $data | Out-Null
Copy-Item $Exe "$dir\homesiem.exe" -Force

# The data folder holds the database, the HTTPS key and the setup code: only administrators may read it.
icacls $data /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

$exeArgs = "-addr 0.0.0.0:$Port -db `"$data\homesiem.db`" -rules `"$data\rules.yaml`""
$action    = New-ScheduledTaskAction -Execute "$dir\homesiem.exe" -Argument $exeArgs -WorkingDirectory $data
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) `
             -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "HomeSIEM" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

# Allow other computers on your PRIVATE network to reach the dashboard and send logs.
Get-NetFirewallRule -DisplayName "HomeSIEM*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "HomeSIEM dashboard" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile Private | Out-Null
New-NetFirewallRule -DisplayName "HomeSIEM logs (UDP)" -Direction Inbound -Protocol UDP -LocalPort 514 -Action Allow -Profile Private | Out-Null
New-NetFirewallRule -DisplayName "HomeSIEM logs (TCP)" -Direction Inbound -Protocol TCP -LocalPort 514 -Action Allow -Profile Private | Out-Null

Start-ScheduledTask -TaskName "HomeSIEM"
Start-Sleep -Seconds 3

Write-Host ""
Write-Host "HomeSIEM is installed and running."
Write-Host ""
Write-Host "  1. Your first-start setup code:   Get-Content '$data\setup-code.txt'"
Write-Host "  2. Open  https://localhost:$Port  (the browser warns about the self-signed certificate once)."
Write-Host "  3. Enter the setup code and choose your password."
Write-Host ""
Write-Host "Note: live packet capture and device blocking need Linux. On Windows HomeSIEM scans devices,"
Write-Host "scans ports, collects logs and raises alerts. To remove it:  .\uninstall-windows.ps1"
