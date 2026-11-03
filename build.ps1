# Builds HomeSIEM for every computer type and puts everything in the "dist" folder.
# Run from the project folder:   .\build.ps1
# Options:                       .\build.ps1 -Version 1.0.1 -SkipTests
param(
  [string]$Version = "1.0.0",
  [switch]$SkipTests
)
$ErrorActionPreference = "Stop"

if (-not $SkipTests) {
  Write-Host "Running the tests..."
  go test ./...
  if ($LASTEXITCODE -ne 0) { throw "The tests failed. Fix them, or run .\build.ps1 -SkipTests to build anyway." }
}

Remove-Item dist -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path dist | Out-Null
$env:CGO_ENABLED = "0"
$targets = @(
  @{os="windows"; arch="amd64"; out="homesiem-windows.exe"},
  @{os="linux";   arch="amd64"; out="homesiem-linux"},
  @{os="linux";   arch="386";   out="homesiem-linux-386"},
  @{os="linux";   arch="arm64"; out="homesiem-pi-arm64"},
  @{os="linux";   arch="arm";   out="homesiem-pi-armv7"; arm="7"},
  @{os="linux";   arch="arm";   out="homesiem-pi-armv6"; arm="6"},
  @{os="darwin";  arch="arm64"; out="homesiem-mac-arm64"},
  @{os="darwin";  arch="amd64"; out="homesiem-mac-intel"}
)
foreach ($t in $targets) {
  $env:GOOS = $t.os; $env:GOARCH = $t.arch
  if ($t.arm) { $env:GOARM = $t.arm } else { Remove-Item Env:GOARM -ErrorAction SilentlyContinue }
  go build -trimpath -ldflags "-s -w -X main.version=$Version" -o "dist\$($t.out)" .
  if ($LASTEXITCODE -ne 0) { throw "Build failed for $($t.out)" }
  Write-Host "built dist\$($t.out)"
}
Remove-Item Env:GOOS, Env:GOARCH, Env:GOARM, Env:CGO_ENABLED -ErrorAction SilentlyContinue

Copy-Item README.md dist\ -ErrorAction SilentlyContinue
Copy-Item deploy dist\deploy -Recurse
Get-ChildItem dist -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } |
  ForEach-Object { "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name } |
  Set-Content dist\SHA256SUMS.txt
Write-Host ""
Write-Host "Done. Files are in the dist folder, with README.md, the deploy scripts and SHA256SUMS.txt."
