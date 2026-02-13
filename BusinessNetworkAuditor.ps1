#Requires -Version 5.1
<#
.SYNOPSIS
    PulseOne Business Network Auditor - Main Launcher
    
.DESCRIPTION
    Centralized launcher for all PulseOne network and security assessment tools.
    Provides a unified menu interface for workstation, server, M365, and dark web assessments.

.NOTES
    Version: 1.0.0
    Author: PulseOne Technical Team
    Requires: PowerShell 5.1 or higher
#>

[CmdletBinding()]
param()

# Global Configuration
$Script:Version = "1.0.0"
$Script:ProjectRoot = $PSScriptRoot
$Script:ConfigPath = Join-Path $Script:ProjectRoot "config"
$Script:OutputPath = Join-Path $Script:ProjectRoot "output"
$Script:ImportPath = Join-Path $Script:ProjectRoot "import"

# Ensure output directory exists
if (-not (Test-Path $Script:OutputPath)) {
    New-Item -ItemType Directory -Path $Script:OutputPath -Force | Out-Null
}

# Display Header
function Show-Header {
    Clear-Host
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "    PulseOne Business Network Auditor" -ForegroundColor Cyan
    Write-Host "    Version $Script:Version" -ForegroundColor Gray
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
}

# Display Main Menu
function Show-MainMenu {
    Write-Host "Assessment Options:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [1] Windows Workstation Audit" -ForegroundColor White
    Write-Host "  [2] Windows Server Audit" -ForegroundColor White
    Write-Host "  [3] macOS Workstation Audit" -ForegroundColor White
    Write-Host "  [4] Dark Web Domain Check" -ForegroundColor White
    Write-Host "  [5] M365 Security Assessment" -ForegroundColor White
    Write-Host ""
    Write-Host "Reporting Options:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [6] Aggregate Multiple Reports" -ForegroundColor White
    Write-Host ""
    Write-Host "  [0] Exit" -ForegroundColor Gray
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
}

# Execute Workstation Audit
function Start-WorkstationAudit {
    Write-Host "`nStarting Windows Workstation Audit..." -ForegroundColor Cyan
    $ScriptPath = Join-Path $Script:ProjectRoot "src\WindowsWorkstationAuditor.ps1"
    if (Test-Path $ScriptPath) {
        & $ScriptPath
    } else {
        Write-Host "Error: WindowsWorkstationAuditor.ps1 not found at $ScriptPath" -ForegroundColor Red
    }
    Write-Host "`nPress any key to return to menu..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Execute Server Audit
function Start-ServerAudit {
    Write-Host "`nStarting Windows Server Audit..." -ForegroundColor Cyan
    $ScriptPath = Join-Path $Script:ProjectRoot "src\WindowsServerAuditor.ps1"
    if (Test-Path $ScriptPath) {
        & $ScriptPath
    } else {
        Write-Host "Error: WindowsServerAuditor.ps1 not found at $ScriptPath" -ForegroundColor Red
    }
    Write-Host "`nPress any key to return to menu..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Execute macOS Audit
function Start-MacOSAudit {
    Write-Host "`nStarting macOS Workstation Audit..." -ForegroundColor Cyan
    Write-Host "Note: macOS audit requires bash execution." -ForegroundColor Yellow
    $ScriptPath = Join-Path $Script:ProjectRoot "src\macOSWorkstationAuditor.sh"
    if (Test-Path $ScriptPath) {
        Write-Host "Run the following command in Terminal on macOS:" -ForegroundColor Yellow
        Write-Host "  sudo bash '$ScriptPath'" -ForegroundColor White
    } else {
        Write-Host "Error: macOSWorkstationAuditor.sh not found at $ScriptPath" -ForegroundColor Red
    }
    Write-Host "`nPress any key to return to menu..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Execute Dark Web Check
function Start-DarkWebCheck {
    Write-Host "`nStarting Dark Web Domain Check..." -ForegroundColor Cyan
    $ScriptPath = Join-Path $Script:ProjectRoot "src\DarkWebChecker.ps1"
    if (Test-Path $ScriptPath) {
        & $ScriptPath
    } else {
        Write-Host "Error: DarkWebChecker.ps1 not found at $ScriptPath" -ForegroundColor Red
    }
    Write-Host "`nPress any key to return to menu..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Execute M365 Assessment
function Start-M365Assessment {
    Write-Host "`nStarting M365 Security Assessment..." -ForegroundColor Cyan
    $ScriptPath = Join-Path $Script:ProjectRoot "Invoke-M365Assessment.ps1"
    if (Test-Path $ScriptPath) {
        & $ScriptPath
        # Exit after assessment completes so results remain visible
        exit
    } else {
        Write-Host "Error: Invoke-M365Assessment.ps1 not found at $ScriptPath" -ForegroundColor Red
        Write-Host "`nPress any key to continue..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# Execute Report Aggregation
function Start-ReportAggregation {
    Write-Host "`nStarting Report Aggregation..." -ForegroundColor Cyan
    $ScriptPath = Join-Path $Script:ProjectRoot "src\NetworkAuditAggregator.ps1"
    if (Test-Path $ScriptPath) {
        & $ScriptPath -ImportPath $Script:ImportPath -OutputPath $Script:OutputPath
    } else {
        Write-Host "Error: NetworkAuditAggregator.ps1 not found at $ScriptPath" -ForegroundColor Red
    }
    Write-Host "`nPress any key to return to menu..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Main Execution Loop
$running = $true
while ($running) {
    Show-Header
    Show-MainMenu
    
    $selection = Read-Host "Select an option"
    
    switch ($selection) {
        "1" { Start-WorkstationAudit }
        "2" { Start-ServerAudit }
        "3" { Start-MacOSAudit }
        "4" { Start-DarkWebCheck }
        "5" { Start-M365Assessment }
        "6" { Start-ReportAggregation }
        "0" { 
            Write-Host "`nExiting PulseOne Business Network Auditor..." -ForegroundColor Green
            $running = $false 
        }
        default {
            Write-Host "`nInvalid selection. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
}
