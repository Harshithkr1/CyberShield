<#
.SYNOPSIS
    Builds (if needed) and runs Cyber Shield on LAN Wi-Fi / mobile hotspot for live demos.
#>
param(
    [switch]$Rebuild
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

# Ensure Java 17+ is on PATH (fall back to IDE bundled JRE if needed)
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    $bundled = 'C:\Users\harsh\.antigravity-ide\extensions\redhat.java-1.58.0-win32-x64\jre\25.0.4.1-win32-x86_64'
    if (Test-Path "$bundled\bin\java.exe") {
        $env:JAVA_HOME = $bundled
        $env:PATH = "$bundled\bin;$env:PATH"
    } else {
        Write-Error 'Java 17+ not found on PATH and JAVA_HOME is not set.'
        exit 1
    }
}

$jarPath = Join-Path $PSScriptRoot 'target\cybershield-0.0.1-SNAPSHOT.jar'
$needsBuild = $Rebuild -or (-not (Test-Path $jarPath))

if (-not $needsBuild) {
    $jarTime = (Get-Item $jarPath).LastWriteTime
    $latestSrc = Get-ChildItem (Join-Path $PSScriptRoot 'src') -Recurse -File |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latestSrc -and $latestSrc.LastWriteTime -gt $jarTime) {
        $needsBuild = $true
    }
}

if ($needsBuild) {
    Write-Host 'Building Cyber Shield JAR (.\mvnw.cmd clean package -DskipTests)...' -ForegroundColor Cyan
    & .\mvnw.cmd clean package -DskipTests
    if ($LASTEXITCODE -ne 0) {
        Write-Error 'Maven build failed.'
        exit $LASTEXITCODE
    }
}

# Detect laptop LAN IPv4 (prefer Wi-Fi / physical NICs with default gateway, exclude loopback/virtual)
$lanIp = $null
try {
    $routes = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric
    foreach ($route in $routes) {
        $ipObj = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.IPAddress -notlike '127.*' -and
                $_.IPAddress -notlike '169.254.*' -and
                $_.InterfaceAlias -notmatch 'vEthernet|WSL|Hyper-V|Docker|Loopback'
            } | Select-Object -First 1
        if ($ipObj) {
            $lanIp = $ipObj.IPAddress
            break
        }
    }
} catch {}

if (-not $lanIp) {
    $fallback = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -notlike '127.*' -and
            $_.IPAddress -notlike '169.254.*' -and
            $_.InterfaceAlias -notmatch 'vEthernet|WSL|Hyper-V|Docker|Loopback'
        } | Select-Object -First 1
    $lanIp = if ($fallback) { $fallback.IPAddress } else { '127.0.0.1' }
}

$port = if ($env:PORT) { $env:PORT } else { '8080' }
$env:PUBLIC_BASE_URL = "http://${lanIp}:${port}"

Write-Host ''
Write-Host '============================================================' -ForegroundColor Green
Write-Host '  Cyber Shield / UPI Scam Simulator - Live Demo Server' -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor Green
Write-Host "  Phones on same Wi-Fi / hotspot : http://${lanIp}:${port}" -ForegroundColor Yellow
Write-Host "  Presenter view (laptop)        : http://localhost:${port}/?present=1" -ForegroundColor Cyan
Write-Host "  PUBLIC_BASE_URL                : $($env:PUBLIC_BASE_URL)" -ForegroundColor Gray
Write-Host '  Note: Ensure Windows Firewall allows TCP port 8080 on Private networks.' -ForegroundColor DarkGray
Write-Host '============================================================' -ForegroundColor Green
Write-Host ''

& java "-Dserver.port=${port}" -jar $jarPath
