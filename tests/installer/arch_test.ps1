#!/usr/bin/env pwsh
# Tests install.ps1 host-architecture target selection (.6.5):
# ConvertTo-WindowsTarget maps ARM64 -> aarch64, everything else -> x64.

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}

Write-Host "Test 1: ARM64 host strings -> aarch64-pc-windows-msvc"
foreach ($a in @('Arm64', 'ARM64', 'aarch64', 'ARM64 ')) {
    Check ((ConvertTo-WindowsTarget -Arch $a) -eq 'aarch64-pc-windows-msvc') "'$a' -> aarch64"
}

Write-Host "Test 2: x64 / x86 / unknown -> x86_64-pc-windows-msvc"
foreach ($a in @('X64', 'AMD64', 'x86_64', 'X86', 'unknown', '', $null)) {
    Check ((ConvertTo-WindowsTarget -Arch $a) -eq 'x86_64-pc-windows-msvc') "'$a' -> x86_64"
}

Write-Host "Test 3: Get-WindowsTarget returns a valid Windows triple on this host"
$t = Get-WindowsTarget
Check ($t -in @('aarch64-pc-windows-msvc', 'x86_64-pc-windows-msvc')) "Get-WindowsTarget -> $t"

Write-Host "Test 4: emulated x64 PowerShell still selects the native ARM64 host"
$savedW6432 = $env:PROCESSOR_ARCHITEW6432
$savedProcessArch = $env:PROCESSOR_ARCHITECTURE
try {
    $env:PROCESSOR_ARCHITEW6432 = 'ARM64'
    $env:PROCESSOR_ARCHITECTURE = 'AMD64'
    Check ((Get-WindowsTarget) -eq 'aarch64-pc-windows-msvc') "ARM64 host wins over emulated AMD64 process"
} finally {
    $env:PROCESSOR_ARCHITEW6432 = $savedW6432
    $env:PROCESSOR_ARCHITECTURE = $savedProcessArch
}

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All arch-selection tests passed." -ForegroundColor Green
