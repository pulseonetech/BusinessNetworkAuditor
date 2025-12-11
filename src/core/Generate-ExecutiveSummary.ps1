# NetworkAuditAggregator - Executive Summary Generator
# Version 1.0.0

function Generate-ExecutiveSummary {
    <#
    .SYNOPSIS
        Generates executive-level summary of IT assessment findings

    .DESCRIPTION
        Analyzes consolidated audit data to produce high-level metrics,
        key findings, and priority recommendations suitable for executive reporting.

    .PARAMETER ImportedData
        Consolidated audit data from Import-AuditData

    .PARAMETER ClientName
        Client name for report customization

    .PARAMETER ReportConfig
        Report configuration object from Import-ReportConfig
    #>

    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ImportedData,

        [Parameter(Mandatory = $true)]
        [string]$ClientName,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$ReportConfig
    )

    Write-Verbose "Generating executive summary for $($ImportedData.SystemCount) systems"
    
    # Environment Overview Analysis (separate computers from dark web checks)
    $WorkstationCount = ($ImportedData.Systems | Where-Object { $_.SystemType -like "*Workstation*" }).Count
    $ServerCount = ($ImportedData.Systems | Where-Object { $_.SystemType -like "*Server*" }).Count
    $DarkWebChecks = ($ImportedData.Systems | Where-Object { $_.SystemType -eq "Breach Monitor" }).Count
    $DomainControllers = ($ImportedData.AllFindings | Where-Object { $_.Category -eq "System" -and $_.Item -eq "Server Roles" -and $_.Value -like "*Domain Controller*" }).Count

    # Systems assessed = computers only (exclude dark web checks)
    $ComputerCount = $WorkstationCount + $ServerCount

    # Initialize summary object
    $Summary = [PSCustomObject]@{
        ClientName = $ClientName
        AssessmentDate = (Get-Date).ToString("MMMM yyyy")
        SystemsAssessed = $ComputerCount
        TotalFindings = $ImportedData.FindingCount
        RiskDistribution = $ImportedData.RiskSummary
        KeyFindings = @()
        PriorityRecommendations = @()
        EnvironmentOverview = @{}
        TechnicalHighlights = @{}
        SecurityStrengths = @()
        PositiveFindings = @{}
    }

    $Summary.EnvironmentOverview = @{
        TotalSystems = $ImportedData.SystemCount
        Workstations = $WorkstationCount
        Servers = $ServerCount
        DarkWebChecks = $DarkWebChecks
        DomainControllers = $DomainControllers
        AssessmentScope = "$ComputerCount computers ($WorkstationCount workstations, $ServerCount servers)" + $(if ($DarkWebChecks -gt 0) { " + $DarkWebChecks dark web check(s)" } else { "" })
    }
    
    # Key Findings Analysis (HIGH and MEDIUM risk items)
    $CriticalFindings = $ImportedData.AllFindings | Where-Object { $_.RiskLevel -in @("HIGH", "MEDIUM") } | 
        Group-Object Category, Item | 
        ForEach-Object {
            [PSCustomObject]@{
                Category = $_.Group[0].Category
                Issue = $_.Group[0].Item
                AffectedSystems = $_.Count
                RiskLevel = $_.Group[0].RiskLevel
                Description = $_.Group[0].Details
                Recommendation = $_.Group[0].Recommendation
            }
        } | Sort-Object { if ($_.RiskLevel -eq "HIGH") { 1 } else { 2 } }, AffectedSystems -Descending
    
    $Summary.KeyFindings = $CriticalFindings | Select-Object -First 10
    
    # Technical Highlights
    $SecurityFindings = $ImportedData.AllFindings | Where-Object { $_.Category -in @("Security", "Users", "Network") }
    $PatchFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Patching" -and $_.RiskLevel -eq "HIGH" }
    $SoftwareFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Software" }
    $DarkWebFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Dark Web Analysis" -and $_.Item -like "*Domain Breach*" }
    
    $Summary.TechnicalHighlights = @{
        SecurityIssues = $SecurityFindings.Count
        CriticalPatches = $PatchFindings.Count
        SoftwareInventory = $SoftwareFindings.Count
        DarkWebBreaches = $DarkWebFindings.Count
        SystemsWithAdminIssues = ($ImportedData.AllFindings | Where-Object {
            $_.Category -eq "Users" -and $_.Item -like "*Administrator*" -and $_.RiskLevel -in @("HIGH", "MEDIUM")
        } | Select-Object -Unique SystemName).Count
        NetworkRisks = ($ImportedData.AllFindings | Where-Object {
            $_.Category -eq "Network" -and $_.RiskLevel -eq "HIGH"
        }).Count
    }

    # Security Strengths Analysis
    $PositiveFindings = $ImportedData.AllFindings | Where-Object { $_.RiskLevel -in @("LOW", "INFO") }
    $SecurityStrengths = @()

    # Use config if available, otherwise use hard-coded patterns
    if ($ReportConfig -and $ReportConfig.security_strengths -and $ReportConfig.security_strengths.categories) {
        foreach ($CategoryName in $ReportConfig.security_strengths.categories.PSObject.Properties.Name) {
            $CategoryConfig = $ReportConfig.security_strengths.categories.$CategoryName

            # Get item patterns for this category
            $ItemPatterns = $CategoryConfig.item_patterns
            $ExcludePatterns = $CategoryConfig.exclude_patterns

            if (-not $ItemPatterns) { continue }

            # Find matching findings
            foreach ($Pattern in $ItemPatterns) {
                $MatchingFindings = $PositiveFindings | Where-Object { $_.Item -match $Pattern }

                # Apply exclusion patterns if configured
                if ($ExcludePatterns) {
                    foreach ($ExcludePattern in $ExcludePatterns) {
                        $MatchingFindings = $MatchingFindings | Where-Object { $_.Details -notmatch $ExcludePattern }
                    }
                }

                # Filter out default Windows components and Windows Defender
                $MatchingFindings = $MatchingFindings | Where-Object {
                    $_.Item -notlike "*Windows Defender*" -and
                    $_.Value -notlike "*Windows Defender*" -and
                    $_.Item -notlike "*DNS Client*" -and
                    $_.Item -notlike "*Disk Health*"
                }

                # For antivirus, consolidate multiple products into single "Third-party Antivirus" entry
                if ($CategoryName -eq "Malware Protection" -and $MatchingFindings.Count -gt 0) {
                    $AVSystems = ($MatchingFindings | Select-Object -Unique SystemName).Count
                    # Keep only one finding, update it to consolidated name
                    $MatchingFindings = @($MatchingFindings[0])
                    $MatchingFindings[0].Item = "Third-party Antivirus"
                }

                # For Network Security, consolidate firewall profiles into single "Windows Firewall" entry
                if ($CategoryName -eq "Network Security") {
                    $FirewallFindings = $MatchingFindings | Where-Object { $_.Item -like "Firewall -*" }
                    if ($FirewallFindings.Count -gt 0) {
                        # Remove all firewall profile findings
                        $MatchingFindings = $MatchingFindings | Where-Object { $_.Item -notlike "Firewall -*" }
                        # Add single consolidated firewall entry
                        $FirewallSystems = ($FirewallFindings | Select-Object -Unique SystemName).Count
                        $ConsolidatedFirewall = $FirewallFindings[0]
                        $ConsolidatedFirewall.Item = "Windows Firewall"
                        $MatchingFindings = @($ConsolidatedFirewall) + $MatchingFindings
                    }
                }

                # For Data Encryption, consolidate BitLocker variants into single entry
                if ($CategoryName -eq "Data Encryption") {
                    $BitLockerFindings = $MatchingFindings | Where-Object { $_.Item -like "*BitLocker*" }
                    if ($BitLockerFindings.Count -gt 1) {
                        # Remove all BitLocker findings
                        $MatchingFindings = $MatchingFindings | Where-Object { $_.Item -notlike "*BitLocker*" }
                        # Add single consolidated BitLocker entry
                        $ConsolidatedBitLocker = $BitLockerFindings[0]
                        $ConsolidatedBitLocker.Item = "BitLocker Encryption"
                        $MatchingFindings = @($ConsolidatedBitLocker) + $MatchingFindings
                    }
                }

                # NEW: Filter out wscsvc/Windows Security Center on servers
                $MatchingFindings = $MatchingFindings | Where-Object {
                    $IsServer = $_.SystemType -like "*Server*"
                    $IsWSCSVC = $_.Item -like "*Windows Security Center*" -or $_.Item -like "*wscsvc*"
                    -not ($IsServer -and $IsWSCSVC)
                }

                # NEW: Filter out WSUS if not actually configured
                $MatchingFindings = $MatchingFindings | Where-Object {
                    if ($_.Item -like "*WSUS*") {
                        # Only keep if Details contains actual server URL
                        $_.Details -match "WSUS Server:|Update Server URL:" -and $_.Value -notlike "*Not Configured*"
                    } else {
                        $true
                    }
                }

                # Add to security strengths
                foreach ($Finding in $MatchingFindings) {
                    $SecurityStrengths += [PSCustomObject]@{
                        Category = $CategoryName
                        Strength = $Finding.Item
                        Details = $Finding.Details
                        SystemName = $Finding.SystemName
                        OriginalFinding = $Finding
                    }
                }
            }
        }
    }
    else {
        # Fallback: Hard-coded security strength detection when no config available
        # Malware Protection - Show actual AV products and systems
        $AVFindings = $PositiveFindings | Where-Object {
            $_.Item -like "*Antivirus Product*" -and
            $_.Value -notlike "*Windows Defender*"
        }
        foreach ($Finding in $AVFindings) {
            $SecurityStrengths += [PSCustomObject]@{
                Category = "Malware Protection"
                Strength = "Antivirus: $($Finding.Value)"
                Details = "Active on $($Finding.SystemName)"
                SystemName = $Finding.SystemName
            }
        }

        # Data Encryption - Show which systems have it enabled
        $EncryptionFindings = $PositiveFindings | Where-Object {
            ($_.Item -like "*BitLocker*" -or $_.Item -like "*FileVault*") -and
            $_.Details -like "*Encrypted*"
        }
        foreach ($Finding in $EncryptionFindings) {
            $EncType = if ($Finding.Item -like "*FileVault*") { "FileVault" } else { "BitLocker" }
            $SecurityStrengths += [PSCustomObject]@{
                Category = "Data Encryption"
                Strength = "$EncType Encryption"
                Details = "$($Finding.Details) on $($Finding.SystemName)"
                SystemName = $Finding.SystemName
            }
        }

        # Enterprise Management - Show domain name
        $DomainFindings = $PositiveFindings | Where-Object {
            $_.Item -like "*Domain Membership*" -and $_.Value -notlike "*Workgroup*"
        }
        if ($DomainFindings -and $DomainFindings[0].Value) {
            $DomainName = $DomainFindings[0].Value
            $DomainSystems = ($DomainFindings | Select-Object -Unique SystemName).Count
            $SecurityStrengths += [PSCustomObject]@{
                Category = "Enterprise Management"
                Strength = "Domain: $DomainName"
                Details = "$DomainSystems systems joined to managed domain"
                SystemCount = $DomainSystems
            }
        }

        # Password Policy
        $PasswordFindings = $PositiveFindings | Where-Object {
            $_.Item -like "*Password*" -and $_.RiskLevel -in @("LOW", "INFO")
        }
        foreach ($Finding in $PasswordFindings) {
            $SecurityStrengths += [PSCustomObject]@{
                Category = "Access Control"
                Strength = $Finding.Item
                Details = $Finding.Details
                SystemName = $Finding.SystemName
            }
        }

        # Backup Solutions - Only show if we have actual backup status/timing
        $BackupFindings = $PositiveFindings | Where-Object {
            ($_.Item -like "*Time Machine*" -or $_.Item -like "*Backup*") -and
            ($_.Details -like "*Last backup*" -or $_.Details -like "*enabled*")
        }
        foreach ($Finding in $BackupFindings) {
            $SecurityStrengths += [PSCustomObject]@{
                Category = "Data Protection"
                Strength = $Finding.Item
                Details = "$($Finding.Details) on $($Finding.SystemName)"
                SystemName = $Finding.SystemName
            }
        }

        # Don't include default macOS features (SIP, Gatekeeper, XProtect) - those are baseline, not strengths

        # Account Lockout Policy (actual security best practice)
        $LockoutFindings = $PositiveFindings | Where-Object {
            $_.Item -like "*Account Lockout*" -or $_.Item -like "*Lockout Threshold*"
        }
        foreach ($Finding in $LockoutFindings) {
            $SecurityStrengths += [PSCustomObject]@{
                Category = "Access Control"
                Strength = $Finding.Item
                Details = $Finding.Details
                SystemName = $Finding.SystemName
            }
        }

        # User Account Control (UAC) - Windows security feature
        $UACFindings = $PositiveFindings | Where-Object {
            $_.Item -like "*User Account Control*" -or $_.Item -like "*UAC*"
        }
        foreach ($Finding in $UACFindings) {
            $SecurityStrengths += [PSCustomObject]@{
                Category = "Access Control"
                Strength = $Finding.Item
                Details = $Finding.Details
                SystemName = $Finding.SystemName
            }
        }

        # Guest Account Disabled (security best practice)
        $GuestFindings = $PositiveFindings | Where-Object {
            $_.Item -like "*Guest Account*" -and $_.Value -like "*Disabled*"
        }
        if ($GuestFindings) {
            $GuestSystems = ($GuestFindings | Select-Object -Unique SystemName).Count
            $SecurityStrengths += [PSCustomObject]@{
                Category = "Access Control"
                Strength = "Guest Account Disabled"
                Details = "Guest account properly disabled"
                SystemCount = $GuestSystems
            }
        }
    }

    # Group duplicates if configured (default: true)
    $GroupDuplicates = if ($ReportConfig -and $null -ne $ReportConfig.security_strengths.group_duplicates) {
        $ReportConfig.security_strengths.group_duplicates
    } else {
        $true
    }

    if ($GroupDuplicates) {
        # Group by Category and Strength, count systems
        $GroupedStrengths = $SecurityStrengths | Group-Object Category, Strength | ForEach-Object {
            $SystemCount = ($_.Group | Select-Object -Unique SystemName).Count
            $FirstFinding = $_.Group[0]

            [PSCustomObject]@{
                Category = $FirstFinding.Category
                Strength = $FirstFinding.Strength
                Details = $FirstFinding.Details
                SystemCount = $SystemCount
            }
        }
        $Summary.SecurityStrengths = $GroupedStrengths | Sort-Object Category, Strength
    } else {
        $Summary.SecurityStrengths = $SecurityStrengths | Sort-Object Category, Strength
    }

    $Summary.PositiveFindings = @{
        TotalPositiveFindings = $PositiveFindings.Count
        SecurityStrengthsFound = $SecurityStrengths.Count
        StrengthCategories = ($SecurityStrengths | Group-Object Category).Count
    }

    # Priority Recommendations (based on risk level and system impact)
    $RecommendationPriorities = @()
    
    # High-impact recommendations based on findings
    if ($Summary.RiskDistribution.HighRisk -gt 0) {
        $RecommendationPriorities += [PSCustomObject]@{
            Priority = 1
            Category = "Critical Security"
            Recommendation = "Address $($Summary.RiskDistribution.HighRisk) high-risk security findings immediately"
            Timeframe = "1-2 weeks"
            Impact = "High"
            AffectedSystems = ($ImportedData.AllFindings | Where-Object { $_.RiskLevel -eq "HIGH" } | Select-Object -Unique SystemName).Count
        }
    }
    
    if ($PatchFindings.Count -gt 0) {
        $RecommendationPriorities += [PSCustomObject]@{
            Priority = 2  
            Category = "Patch Management"
            Recommendation = "Deploy critical security updates to $($PatchFindings.Count) systems"
            Timeframe = "2-4 weeks"
            Impact = "High"
            AffectedSystems = ($PatchFindings | Select-Object -Unique SystemName).Count
        }
    }
    
    if ($Summary.TechnicalHighlights.SystemsWithAdminIssues -gt 0) {
        $RecommendationPriorities += [PSCustomObject]@{
            Priority = 3
            Category = "Access Management"  
            Recommendation = "Review administrator account configurations on $($Summary.TechnicalHighlights.SystemsWithAdminIssues) systems"
            Timeframe = "1-3 weeks"
            Impact = "Medium"
            AffectedSystems = $Summary.TechnicalHighlights.SystemsWithAdminIssues
        }
    }
    
    if ($Summary.RiskDistribution.MediumRisk -gt 10) {
        $RecommendationPriorities += [PSCustomObject]@{
            Priority = 4
            Category = "IT Hygiene"
            Recommendation = "Address $($Summary.RiskDistribution.MediumRisk) medium-risk findings for improved security posture"
            Timeframe = "1-2 months"
            Impact = "Medium"
            AffectedSystems = ($ImportedData.AllFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" } | Select-Object -Unique SystemName).Count
        }
    }
    
    $Summary.PriorityRecommendations = $RecommendationPriorities
    
    Write-Verbose "Executive summary generated: $($Summary.KeyFindings.Count) key findings, $($Summary.SecurityStrengths.Count) security strengths, $($Summary.PriorityRecommendations.Count) priority recommendations"
    
    return $Summary
}