# Vault Password Manager — Windows installer
# Usage: powershell -c "irm https://raw.githubusercontent.com/HarshaDokula/password-vault/main/install.ps1 | iex"

param(
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\vault"
)

$ErrorActionPreference = "Stop"
$Repo = "HarshaDokula/password-vault"

# ── Detect architecture ──────────────────────────────────────────
$Arch = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86_64" }

# ── Resolve version ──────────────────────────────────────────────
if ($Version -eq "latest") {
    Write-Host "🔍 Fetching latest release..."
    $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    $Version = $Release.tag_name
}

$Artifact = "vault-windows-$Arch.zip"
$Url = "https://github.com/$Repo/releases/download/$Version/$Artifact"

Write-Host "📦 Installing vault $Version for windows/$Arch..."

# ── Download and install ─────────────────────────────────────────
$TempDir = Join-Path $env:TEMP "vault-install-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $TempDir | Out-Null

try {
    Write-Host "⬇️  Downloading $Artifact..."
    $ZipPath = Join-Path $TempDir $Artifact
    Invoke-WebRequest -Uri $Url -OutFile $ZipPath

    Write-Host "📂 Extracting..."
    Expand-Archive -Path $ZipPath -DestinationPath $TempDir -Force

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

    Write-Host "🚀 Installing to $InstallDir..."
    Copy-Item "$TempDir\vault.exe" "$InstallDir\vault.exe" -Force

    # ── Add to PATH (current session + user PATH) ────────────────
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($UserPath -notlike "*$InstallDir*") {
        Write-Host "➕ Adding to user PATH..."
        [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
        $env:Path = "$env:Path;$InstallDir"
    }

    Write-Host "✅ vault $Version installed to $InstallDir\vault.exe"
    Write-Host ""
    Write-Host "Run 'vault' to get started — restart your terminal or run 'refreshenv' if the command isn't found."
} finally {
    Remove-Item -Recurse -Force $TempDir -ErrorAction SilentlyContinue
}
