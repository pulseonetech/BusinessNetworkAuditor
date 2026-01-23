# NetworkAuditAggregator - Main Orchestrator
# Version 1.0.0

<#
.SYNOPSIS
    Aggregates audit results from multiple systems into consolidated client reports

.DESCRIPTION
    The NetworkAuditAggregator processes JSON audit files from WindowsWorkstationAuditor
    and WindowsServerAuditor to generate executive-level reports suitable for client
    deliverables. Combines findings across multiple systems with risk prioritization
    and professional formatting.

.PARAMETER ImportPath
    Directory containing JSON audit files to process

.PARAMETER OutputPath
    Directory for generated consolidated reports

.PARAMETER ClientName
    Client name for report customization

.EXAMPLE
    .\NetworkAuditAggregator.ps1 -ImportPath ".\import" -ClientName "Example Client"
#>

param(
    [string]$ImportPath,
    [string]$OutputPath,
    [string]$ClientName = "Client Name"
)

# Set default paths relative to project root (one level up from script location)
$ProjectRoot = Split-Path -Parent $PSScriptRoot
if (-not $ImportPath) { $ImportPath = Join-Path $ProjectRoot "import" }
if (-not $OutputPath) { $OutputPath = Join-Path $ProjectRoot "output" }

# Global variables
$Script:StartTime = Get-Date
$Script:ImportedSystems = @()
$Script:AllFindings = @()
$Script:AggregationSummary = @{}

# Import core functions
$CorePath = Join-Path $PSScriptRoot "core"
$CoreFiles = @(
    "Import-ReportConfig.ps1",
    "Import-AuditData.ps1",
    "Generate-ExecutiveSummary.ps1",
    "Generate-ScoringMatrix.ps1",
    "Generate-RiskAnalysis.ps1",
    "Export-ClientReport.ps1"
)

Write-Host "NetworkAuditAggregator v1.0.0" -ForegroundColor Green
Write-Host "Processing audit files for: $ClientName" -ForegroundColor Yellow

# Load core modules
foreach ($CoreFile in $CoreFiles) {
    $FilePath = Join-Path $CorePath $CoreFile
    if (Test-Path $FilePath) {
        Write-Verbose "Loading: $CoreFile"
        . $FilePath
    } else {
        Write-Warning "Core module not found: $CoreFile"
    }
}

# Main execution
try {
    Write-Host "`nStep 1: Importing audit data..." -ForegroundColor Cyan
    $ImportResult = Import-AuditData -ImportPath $ImportPath

    if ($ImportResult.SystemCount -eq 0) {
        Write-Warning "No audit files found in $ImportPath"
        Write-Host "Expected file format: COMPUTERNAME_YYYYMMDD_HHMMSS_raw_data.json"
        exit 1
    }

    Write-Host "  > Imported $($ImportResult.SystemCount) systems"
    Write-Host "  > Total findings: $($ImportResult.FindingCount)"

    Write-Host "`nStep 2: Generating executive summary..." -ForegroundColor Cyan
    $ExecutiveSummary = Generate-ExecutiveSummary -ImportedData $ImportResult -ClientName $ClientName

    Write-Host "`nStep 3: Creating scoring matrix..." -ForegroundColor Cyan
    $ScoringMatrix = Generate-ScoringMatrix -ImportedData $ImportResult

    Write-Host "`nStep 4: Analyzing risk factors..." -ForegroundColor Cyan
    $RiskAnalysis = Generate-RiskAnalysis -ImportedData $ImportResult

    Write-Host "`nStep 5: Generating client report..." -ForegroundColor Cyan
    $ReportPath = Export-ClientReport -ExecutiveSummary $ExecutiveSummary -ScoringMatrix $ScoringMatrix -RiskAnalysis $RiskAnalysis -OutputPath $OutputPath -ClientName $ClientName
    
    $Duration = (Get-Date) - $Script:StartTime
    Write-Host "`nReport generation completed in $([math]::Round($Duration.TotalSeconds, 1))s" -ForegroundColor Green
    Write-Host "  > Output: $ReportPath"
    
    # Open the report
    if (Test-Path $ReportPath) {
        Write-Host "  > Opening report..." -ForegroundColor Gray
        if ($IsWindows -or ($PSVersionTable.PSVersion.Major -lt 6)) {
            Start-Process $ReportPath
        } else {
            Start-Process "open" -ArgumentList $ReportPath
        }
    }
}
catch {
    Write-Error "Aggregation failed: $($_.Exception.Message)"
    Write-Verbose $_.ScriptStackTrace
    exit 1
}