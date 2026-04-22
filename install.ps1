param(
  [Parameter(Position=0, ValueFromRemainingArguments=$true)]
  [string[]]$Product = @("uwgsocks-ui"),
  [string]$Version = "latest",
  [string]$Prefix = "",
  [string]$ApiBase = "https://api.github.com",
  [switch]$SkipUwgsocks
)

$ErrorActionPreference = "Stop"

function Get-Arch {
  switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()) {
    "x64" { "amd64" }
    "arm64" { "arm64" }
    default { throw "unsupported architecture" }
  }
}

function Get-Repo($product) {
  switch ($product) {
    "uwgsocks-ui" { "reindertpelsma/simple-wireguard-server" }
    "uwgsocks" { "reindertpelsma/userspace-wireguard-socks" }
    default { throw "unsupported product: $product" }
  }
}

function Get-BinaryName($product) {
  switch ($product) {
    "uwgsocks-ui" { "uwgsocks-ui.exe" }
    "uwgsocks" { "uwgsocks.exe" }
  }
}

function Get-AssetName($product, $arch) {
  switch ($product) {
    "uwgsocks-ui" { "uwgsocks-ui-windows-$arch.exe" }
    "uwgsocks" { "uwgsocks-windows-$arch.exe" }
  }
}

function Get-DownloadUrl($repo, $asset) {
  if ($Version -eq "latest") {
    return "https://github.com/$repo/releases/latest/download/$asset"
  }
  return "https://github.com/$repo/releases/download/$Version/$asset"
}

function Ensure-UserPath($dir) {
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  $entries = @()
  if ($userPath) { $entries = $userPath -split ';' | Where-Object { $_ } }
  if ($entries -contains $dir) { return }
  $newPath = if ($entries.Count -gt 0) { ($entries + $dir) -join ';' } else { $dir }
  [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
  Write-Host "added $dir to user PATH"
}

if (-not $Prefix) {
  $Prefix = Join-Path $env:LOCALAPPDATA "Programs\\uwgsocks-ui"
}

$arch = Get-Arch
New-Item -ItemType Directory -Force -Path $Prefix | Out-Null

$needUwgsocks = -not $SkipUwgsocks
foreach ($p in $Product) {
  if ($p -eq "uwgsocks") { $needUwgsocks = $false }
}
if ($needUwgsocks -and -not (Get-Command uwgsocks -ErrorAction SilentlyContinue) -and -not (Test-Path (Join-Path $Prefix "uwgsocks.exe"))) {
  $Product += "uwgsocks"
}

foreach ($p in $Product) {
  $repo = Get-Repo $p
  $asset = Get-AssetName $p $arch
  $dst = Join-Path $Prefix (Get-BinaryName $p)
  Invoke-WebRequest -Headers @{ "User-Agent" = "uwgsocks-ui-installer" } -Uri (Get-DownloadUrl $repo $asset) -OutFile $dst
  Write-Host "installed $asset to $dst"
}

Ensure-UserPath $Prefix
