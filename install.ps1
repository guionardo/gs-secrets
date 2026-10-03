<#
.SYNOPSIS
    Downloads and installs gs-secrets on Windows into a PATH-visible folder.

.DESCRIPTION
    Fetches the gs-secrets release archive (zip) for the current architecture
    from GitHub Releases, verifies its SHA-256 checksum against the release
    checksums.txt, extracts gs-secrets.exe into the install directory and
    adds that directory to the user PATH.

    Installation is per-user; no administrator rights are required.

.PARAMETER Version
    Release version to install, e.g. "1.2.3". Defaults to the latest
    stable release (prereleases are ignored).

.PARAMETER InstallDir
    Directory where gs-secrets.exe is installed. Defaults to
    %LOCALAPPDATA%\gs-secrets\bin.

.EXAMPLE
    # Latest release, default directory
    irm https://raw.githubusercontent.com/guionardo/gs-secrets/main/install.ps1 | iex

.EXAMPLE
    # Pin a specific version and a custom directory
    .\install.ps1 -Version 1.2.3 -InstallDir "$HOME\tools\gs-secrets"
#>
[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$InstallDir = ""
)

$ErrorActionPreference = "Stop"
$Repo = "guionardo/gs-secrets"

function Get-LatestVersion {
    $release = Invoke-RestMethod `
        -Uri "https://api.github.com/repos/$Repo/releases/latest" `
        -Headers @{ "User-Agent" = "gs-secrets-installer" }
    return $release.tag_name.TrimStart("v")
}

function Get-TargetArch {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default { throw "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE (amd64 and arm64 are supported)" }
    }
}

$Version = $Version.TrimStart("v")
if (-not $Version) {
    $Version = Get-LatestVersion
}
if (-not $InstallDir) {
    $InstallDir = Join-Path $env:LOCALAPPDATA "gs-secrets\bin"
}

$Arch = Get-TargetArch
$Tag = "v$Version"
$ZipName = "gs-secrets_${Version}_windows_${Arch}.zip"
$DownloadBase = "https://github.com/$Repo/releases/download/$Tag"

Write-Host "Installing gs-secrets $Version ($Arch) into $InstallDir"

$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "gs-secrets-installer") -Force
$zipPath = Join-Path $tmp $ZipName

try {
    Invoke-WebRequest -UseBasicParsing -Uri "$DownloadBase/$ZipName" -OutFile $zipPath
} catch {
    throw "Failed to download $DownloadBase/$ZipName : $($_.Exception.Message)"
}

Write-Host "Verifying checksum..."
$checksums = Invoke-WebRequest -UseBasicParsing -Uri "$DownloadBase/checksums.txt"
$expected = ($checksums.Content -split "`r?`n" |
    Where-Object { $_ -match "\s$([regex]::Escape($ZipName))\s*$" } |
    ForEach-Object { ($_ -split "\s+")[0] })
if (-not $expected) {
    throw "checksums.txt does not contain an entry for $ZipName"
}
$actual = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash.ToLower()
if ($actual -ne $expected) {
    throw "Checksum mismatch for $ZipName. Expected $expected, got $actual. Aborting."
}

Write-Host "Extracting..."
Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
$exe = Get-ChildItem -Path $tmp -Recurse -Filter "gs-secrets.exe" | Select-Object -First 1
if (-not $exe) {
    throw "gs-secrets.exe not found inside the archive"
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item $exe.FullName -Destination (Join-Path $InstallDir "gs-secrets.exe") -Force

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$normalizedDir = $InstallDir.TrimEnd("\")
$alreadyInPath = ($userPath -split ";") | Where-Object { $_.TrimEnd("\") -ieq $normalizedDir }
if (-not $alreadyInPath) {
    $newPath = if ($userPath) { "$userPath;$InstallDir" } else { $InstallDir }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "Added $InstallDir to your user PATH. Open a new terminal before using gs-secrets."
} else {
    Write-Host "$InstallDir is already in your user PATH."
}

Write-Host ""
Write-Host "gs-secrets $Version installed successfully."
Write-Host "Usage:"
Write-Host "  gs-secrets --set api_key=value --ttl 24h"
Write-Host "  gs-secrets --get api_key"
Write-Host "Documentation: https://github.com/$Repo#readme"