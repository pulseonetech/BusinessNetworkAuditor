# Dark Web Checker - Domain Breach Analysis Tool
# Version 1.0.0
# Standalone tool for checking email domains against known data breaches

param(
    [Parameter(Mandatory=$false)]
    [string]$Domains,

    [Parameter(Mandatory=$false)]
    [string]$Emails,

    [Parameter(Mandatory=$false)]
    [string]$EmailList,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\output",

    [Parameter(Mandatory=$false)]
    [string]$ConfigPath,

    [Parameter(Mandatory=$false)]
    [switch]$DetailedLogging,

    [Parameter(Mandatory=$false)]
    [switch]$Help,

    [Parameter(Mandatory=$false)]
    [switch]$DemoMode
)

# Display help information
if ($Help) {
    Write-Host @"

Dark Web Checker - Domain and Email Breach Analysis Tool
=========================================================

DESCRIPTION:
    Checks email domains or specific email addresses for compromised accounts and data breaches.
    Identifies breached accounts, sources, and provides risk assessment.

SCANNING METHODS:
    Domain-Based: Requires domain ownership verification (dashboard setup)
    Email-Based:  No verification required, works with any email addresses (API key needed)

USAGE:
    .\DarkWebChecker.ps1 -Domains "company.com,subsidiary.org"
    .\DarkWebChecker.ps1 -Emails "user1@company.com,user2@company.com"
    .\DarkWebChecker.ps1 -EmailList "emails.txt"
    .\DarkWebChecker.ps1                                     (prompts for input)

PARAMETERS:
    -Domains        Comma-separated list of email domains to check
    -Emails         Comma-separated list of email addresses to check
    -EmailList      Path to text file with email addresses (one per line, no header)
    -OutputPath     Directory for output files (default: .\output)
    -ConfigPath     Path to breach database API configuration file
    -DetailedLogging Enable detailed logging
    -DemoMode       Run in demo mode with simulated results (no API key required)
    -Help           Show this help message

SETUP OPTIONS:
    Option A - Full API Access (Recommended for Email Scanning):
    1. Copy config\hibp-api-config.example.json to config\hibp-api-config.json
    2. Add your paid API key to the configuration file
    3. Ensure internet connectivity for API calls

    Option B - Basic Access (Free - Domain Scanning Only):
    1. No configuration required
    2. Uses subscription-free breach data only (limited results)
    3. Ensure internet connectivity for API calls

EXAMPLES:
    Domain scanning:
    .\DarkWebChecker.ps1 -Domains "acme.com"

    Email scanning:
    .\DarkWebChecker.ps1 -Emails "admin@acme.com,support@acme.com"
    .\DarkWebChecker.ps1 -EmailList "C:\emails.txt"
    .\DarkWebChecker.ps1 -Emails "test@example.com" -DemoMode

"@ -ForegroundColor Cyan
    exit 0
}

# Resolve ConfigPath relative to script location if not provided
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $PSScriptRoot "..\config\hibp-api-config.json"
}

# Global variables
$Script:StartTime = Get-Date
$Script:OutputDirectory = $OutputPath

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

# Simple logging function for standalone script
function Write-LogMessage {
    param(
        [string]$Level,
        [string]$Message,
        [string]$Category = "DARKWEB"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] [$Category] $Message"

    switch ($Level) {
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
        "INFO"    { Write-Host $LogEntry -ForegroundColor Cyan }
        "WARN"    { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
        default   { Write-Host $LogEntry }
    }

    if ($DetailedLogging) {
        # Also log to file if detailed logging enabled
        $LogFile = Join-Path $OutputDirectory "darkweb-check-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
        $LogEntry | Out-File -FilePath $LogFile -Append -Encoding UTF8
    }
}

# Load required modules
$ModulePath = Join-Path $PSScriptRoot "modules\Get-DarkWebAnalysis.ps1"
if (Test-Path $ModulePath) {
    . $ModulePath
    Write-LogMessage "SUCCESS" "Loaded Dark Web Analysis module" "INIT"
} else {
    Write-LogMessage "ERROR" "Dark Web Analysis module not found at: $ModulePath" "INIT"
    Write-Host "Please ensure you're running this script from the src directory or that the modules directory exists." -ForegroundColor Red
    exit 1
}

# Load markdown export module
$MarkdownModulePath = Join-Path $PSScriptRoot "core\Export-MarkdownReport.ps1"
if (Test-Path $MarkdownModulePath) {
    . $MarkdownModulePath
    Write-LogMessage "SUCCESS" "Loaded Markdown Export module" "INIT"
} else {
    Write-LogMessage "WARN" "Markdown Export module not found - JSON export only" "INIT"
}

# Main execution
Write-Host @"

========================================
Dark Web Checker - Domain Analysis
========================================
Start Time: $($Script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))

"@ -ForegroundColor Green

try {
    # Validate that at least one scanning method is specified
    $HasDomains = -not [string]::IsNullOrWhiteSpace($Domains)
    $HasEmails = -not [string]::IsNullOrWhiteSpace($Emails)
    $HasEmailList = -not [string]::IsNullOrWhiteSpace($EmailList)

    # If nothing specified, prompt user
    if (-not $HasDomains -and -not $HasEmails -and -not $HasEmailList) {
        Write-Host "No scanning target specified. Please choose a scanning method:" -ForegroundColor Yellow
        Write-Host "  1. Domain-based scanning (requires domain ownership verification)" -ForegroundColor Cyan
        Write-Host "  2. Email-based scanning (requires API key, no verification)" -ForegroundColor Cyan
        $Choice = Read-Host "Enter choice (1 or 2)"

        if ($Choice -eq "1") {
            Write-Host "`nEnter domains separated by commas (e.g., company.com, subsidiary.org):" -ForegroundColor Cyan
            $Domains = Read-Host "Domains"
            if ([string]::IsNullOrWhiteSpace($Domains)) {
                Write-Host "No domains provided. Exiting." -ForegroundColor Red
                exit 1
            }
            $HasDomains = $true
        } elseif ($Choice -eq "2") {
            Write-Host "`nEnter email addresses separated by commas, or path to email list file:" -ForegroundColor Cyan
            $Input = Read-Host "Emails or file path"
            if ([string]::IsNullOrWhiteSpace($Input)) {
                Write-Host "No input provided. Exiting." -ForegroundColor Red
                exit 1
            }
            # Check if input is a file path
            if (Test-Path $Input) {
                $EmailList = $Input
                $HasEmailList = $true
            } else {
                $Emails = $Input
                $HasEmails = $true
            }
        } else {
            Write-Host "Invalid choice. Exiting." -ForegroundColor Red
            exit 1
        }
    }

    # Execute the appropriate dark web analysis
    if ($HasDomains) {
        Write-Host "Checking domains: $Domains" -ForegroundColor Green
        if ($DemoMode) {
            Write-Host "`n[DEMO MODE] Running with simulated data - no API calls will be made" -ForegroundColor Magenta
            $Results = Get-DarkWebAnalysis -Domains $Domains -ConfigPath $ConfigPath -DemoMode
        } else {
            $Results = Get-DarkWebAnalysis -Domains $Domains -ConfigPath $ConfigPath
        }
    } elseif ($HasEmails) {
        Write-Host "Checking email addresses: $Emails" -ForegroundColor Green
        if ($DemoMode) {
            Write-Host "`n[DEMO MODE] Running with simulated data - no API calls will be made" -ForegroundColor Magenta
            $Results = Get-DarkWebAnalysis -EmailAddresses $Emails -ConfigPath $ConfigPath -DemoMode
        } else {
            $Results = Get-DarkWebAnalysis -EmailAddresses $Emails -ConfigPath $ConfigPath
        }
    } elseif ($HasEmailList) {
        Write-Host "Loading email addresses from file: $EmailList" -ForegroundColor Green
        if ($DemoMode) {
            Write-Host "`n[DEMO MODE] Running with simulated data - no API calls will be made" -ForegroundColor Magenta
            $Results = Get-DarkWebAnalysis -EmailListPath $EmailList -ConfigPath $ConfigPath -DemoMode
        } else {
            $Results = Get-DarkWebAnalysis -EmailListPath $EmailList -ConfigPath $ConfigPath
        }
    }

    if ($Results.Count -eq 0) {
        Write-LogMessage "WARN" "No results returned from analysis" "SCAN"
        exit 1
    }

    # Display results in console
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "SCAN RESULTS" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $BreachCount = 0
    $CleanCount = 0
    $ErrorCount = 0

    foreach ($Result in $Results) {
        $Color = switch ($Result.RiskLevel) {
            "HIGH"   { "Red" }
            "MEDIUM" { "Yellow" }
            "LOW"    { "DarkYellow" }
            "INFO"   { "Cyan" }
            default  { "White" }
        }

        Write-Host "`n[$($Result.RiskLevel)] $($Result.Item)" -ForegroundColor $Color
        Write-Host "  Value: $($Result.Value)" -ForegroundColor White
        Write-Host "  Details: $($Result.Details)" -ForegroundColor Gray
        Write-Host "  Recommendation: $($Result.Recommendation)" -ForegroundColor Gray

        # Count result types
        if ($Result.Item -like "*Breach*" -and $Result.Item -notlike "*Breach Details*") {
            $BreachCount++
        } elseif ($Result.Item -like "*Status" -and $Result.Value -like "*Clean*") {
            $CleanCount++
        } elseif ($Result.Value -like "*Error*" -or $Result.Value -like "*Exception*") {
            $ErrorCount++
        }
    }

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Breaches Found: $BreachCount" -ForegroundColor $(if ($BreachCount -gt 0) { "Red" } else { "Green" })
    Write-Host "Clean: $CleanCount" -ForegroundColor Green
    Write-Host "Errors: $ErrorCount" -ForegroundColor $(if ($ErrorCount -gt 0) { "Yellow" } else { "Green" })
    Write-Host "Total Results: $($Results.Count)" -ForegroundColor Cyan

    # Automatic export to JSON and Markdown (like other audit modules)
    $BaseFileName = "darkweb-check-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

    # Export JSON
    $JsonFile = Join-Path $OutputDirectory "$BaseFileName.json"

    # Determine scan method
    $ScanMethod = if ($HasDomains) {
        "domain"
    } elseif ($HasEmails -or $HasEmailList) {
        "email"
    } else {
        "unknown"
    }

    $ExportData = @{
        CheckDate = $Script:StartTime.ToString('yyyy-MM-dd HH:mm:ss')
        ScanMethod = $ScanMethod
        Summary = @{
            BreachesFound = $BreachCount
            Clean = $CleanCount
            Errors = $ErrorCount
            TotalResults = $Results.Count
        }
        Results = $Results
    }
    $ExportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $JsonFile -Encoding UTF8
    Write-LogMessage "SUCCESS" "JSON results exported to: $JsonFile" "EXPORT"

    # Export Markdown if module is available
    if (Get-Command Export-MarkdownReport -ErrorAction SilentlyContinue) {
        Export-MarkdownReport -Results $Results -OutputPath $OutputDirectory -BaseFileName $BaseFileName
        Write-LogMessage "SUCCESS" "Markdown report exported to: $OutputDirectory" "EXPORT"
    } else {
        Write-LogMessage "WARN" "Markdown export not available - JSON export completed" "EXPORT"
    }

    $EndTime = Get-Date
    $Duration = $EndTime - $Script:StartTime
    Write-Host "`nCheck completed in $($Duration.TotalSeconds.ToString('F1')) seconds" -ForegroundColor Green

    # Exit with appropriate code
    if ($BreachCount -gt 0) {
        Write-Host "WARNING: Breaches detected! Review results and take appropriate action." -ForegroundColor Red
        exit 2  # Exit code 2 indicates breaches found
    } elseif ($ErrorCount -gt 0) {
        Write-Host "WARNING: Some errors occurred during check." -ForegroundColor Yellow
        exit 3  # Exit code 3 indicates errors occurred
    } else {
        Write-Host "Scan complete - no breaches detected." -ForegroundColor Green
        exit 0  # Success
    }
}
catch {
    Write-LogMessage "ERROR" "Check failed: $($_.Exception.Message)" "DARKWEB"
    Write-Host "`nFATAL ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}