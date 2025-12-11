function Import-ReportConfig {
    <#
    .SYNOPSIS
        Loads report presentation configuration
    .DESCRIPTION
        Loads configuration controlling report grouping, formatting, and presentation.
        Provides defaults if config file is missing or invalid.
    #>
    [CmdletBinding()]
    param()

    $ConfigPath = Join-Path $PSScriptRoot "..\..\config\report-presentation.json"

    if (-not (Test-Path $ConfigPath)) {
        Write-Warning "Report config not found at $ConfigPath, using defaults"
        return Get-DefaultReportConfig
    }

    try {
        $Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        Write-Verbose "Loaded report config version $($Config.version)"
        return $Config
    }
    catch {
        Write-Warning "Failed to load report config: $_"
        Write-Warning "Using default configuration"
        return Get-DefaultReportConfig
    }
}

function Get-DefaultReportConfig {
    <#
    .SYNOPSIS
        Returns default report configuration
    .DESCRIPTION
        Provides fallback configuration if config file is missing or invalid
    #>

    return [PSCustomObject]@{
        version = "1.0"
        grouping = [PSCustomObject]@{
            combine_per_system = @(
                "Critical Role Detected",
                "Server Role",
                "Remote Access Software",
                "RMM Software"
            )
            domain_wide_findings = @(
                "Computer Account Summary",
                "User Account Summary",
                "Disabled Domain Accounts",
                "Password Age Analysis",
                "Stale User Accounts",
                "Stale Computer Accounts"
            )
            normalize_risk_levels = @(
                "Local Administrators",
                "Critical Role Detected",
                "Failed Logon",
                "Available Updates"
            )
        }
        formatting = [PSCustomObject]@{}
        security_strengths = [PSCustomObject]@{
            categories = [PSCustomObject]@{}
            exclude_default_features = @()
        }
        technical_debt = [PSCustomObject]@{
            temporary_filters = @()
        }
    }
}

function Test-ItemMatchesPattern {
    <#
    .SYNOPSIS
        Tests if an item matches a pattern
    .DESCRIPTION
        Helper function to test if finding item name matches a pattern.
        Supports wildcards.
    #>
    param(
        [string]$Item,
        [string]$Pattern
    )

    return $Item -like $Pattern
}

function Test-ItemMatchesAnyPattern {
    <#
    .SYNOPSIS
        Tests if an item matches any pattern in a list
    #>
    param(
        [string]$Item,
        [array]$Patterns
    )

    if (-not $Patterns -or $Patterns.Count -eq 0) {
        return $false
    }

    foreach ($Pattern in $Patterns) {
        if ($Item -like $Pattern) {
            return $true
        }
    }

    return $false
}

function Test-FindingShouldBeFiltered {
    <#
    .SYNOPSIS
        Determines if a finding should be filtered based on config
    .DESCRIPTION
        Checks technical debt filters to determine if finding should be excluded
    #>
    param(
        [PSCustomObject]$Finding,
        [PSCustomObject]$Config
    )

    if (-not $Config.technical_debt -or -not $Config.technical_debt.temporary_filters) {
        return $false
    }

    foreach ($Filter in $Config.technical_debt.temporary_filters) {
        # Check exact item match
        if ($Filter.item -and $Finding.Item -eq $Filter.item) {
            # Check if there's a condition
            if ($Filter.condition) {
                # Parse condition (e.g., "value matches NETLOGON|SYSVOL")
                if ($Filter.condition -match "value matches (.+)") {
                    $Pattern = $Matches[1]
                    if ($Finding.Value -match $Pattern) {
                        return $true
                    }
                }
            }
            else {
                return $true
            }
        }

        # Check pattern match
        if ($Filter.pattern -and ($Finding.Item -like $Filter.pattern)) {
            return $true
        }
    }

    return $false
}

# Note: Functions are dot-sourced, not exported as module members
