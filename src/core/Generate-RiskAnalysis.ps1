# NetworkAuditAggregator - Risk Analysis Generator
# Version 1.0.0

function Generate-RiskAnalysis {
    <#
    .SYNOPSIS
        Generates color-coded risk analysis matching client report format

    .DESCRIPTION
        Analyzes consolidated findings to create risk-based sections with
        specific recommendations, similar to the "High Risk" and "Low Risk"
        sections in professional client reports.

    .PARAMETER ImportedData
        Consolidated audit data from Import-AuditData

    .PARAMETER ReportConfig
        Report configuration object from Import-ReportConfig
    #>

    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ImportedData,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$ReportConfig
    )

    Write-Verbose "Generating risk analysis from $($ImportedData.FindingCount) findings"

    # Load report configuration if not provided
    if (-not $ReportConfig) {
        $ReportConfig = Import-ReportConfig
        Write-Verbose "Loaded report configuration version $($ReportConfig.version)"
    }

    # Initialize risk analysis structure
    $RiskAnalysis = [PSCustomObject]@{
        HighRiskFindings = @()
        MediumRiskFindings = @()
        LowRiskFindings = @()
        DarkWebFindings = @()
        SystemsSnapshot = @()
        RiskSummary = @{
            TotalRisks = 0
            CriticalSystems = 0
            ImmediateActions = 0
        }
    }
    
    # Filter out redundant findings first
    $FilteredFindings = Remove-RedundantFindings -AllFindings $ImportedData.AllFindings -ReportConfig $ReportConfig

    # Apply consolidation rules
    $ConsolidatedFindings = Apply-ConsolidationRules -Findings $FilteredFindings -ReportConfig $ReportConfig

    # Normalize risk levels for findings that shouldn't be split across risk categories
    # Use config to determine which findings to normalize
    $FindingsToNormalize = $ReportConfig.grouping.normalize_risk_levels

    foreach ($ItemName in $FindingsToNormalize) {
        $MatchingFindings = $ConsolidatedFindings | Where-Object { $_.Item -eq $ItemName }
        if ($MatchingFindings -and $MatchingFindings.Count -gt 0) {
            # Find highest risk level present
            $RiskLevels = $MatchingFindings | Select-Object -ExpandProperty RiskLevel -Unique
            $HighestRisk = if ($RiskLevels -contains "HIGH") { "HIGH" }
                          elseif ($RiskLevels -contains "MEDIUM") { "MEDIUM" }
                          else { "LOW" }

            # Normalize all to highest risk level
            $ConsolidatedFindings | Where-Object { $_.Item -eq $ItemName } | ForEach-Object {
                $_.RiskLevel = $HighestRisk
            }

            # For Available Updates, also normalize category (Windows="Patches", macOS="Patching")
            if ($ItemName -eq "Available Updates") {
                $ConsolidatedFindings | Where-Object { $_.Item -eq $ItemName } | ForEach-Object {
                    $_.Category = "Patches"
                }
            }
        }
    }

    # ============================================================================
    # Demote items to INFO level based on config
    # ============================================================================
    if ($ReportConfig.demote_to_info) {
        foreach ($DemoteItem in $ReportConfig.demote_to_info) {
            $ConsolidatedFindings | Where-Object { $_.Item -like "*$DemoteItem*" } | ForEach-Object {
                if ($_.RiskLevel -ne "LOW") {
                    Write-Verbose "Demoting $($_.Item) from $($_.RiskLevel) to LOW (Info)"
                    $_.RiskLevel = "LOW"
                }
            }
        }
    }

    # Handle Available Updates - demote unless above threshold
    if ($ReportConfig.available_updates_threshold) {
        $Threshold = $ReportConfig.available_updates_threshold
        $ConsolidatedFindings | Where-Object { $_.Item -like "*Available Updates*" } | ForEach-Object {
            # Try to extract count from value or details
            $Count = 0
            if ($_.Value -match "(\d+)") { $Count = [int]$Matches[1] }
            if ($Count -lt $Threshold -and $_.RiskLevel -ne "LOW") {
                Write-Verbose "Demoting Available Updates ($Count < $Threshold threshold) to LOW"
                $_.RiskLevel = "LOW"
            }
        }
    }

    # Filter out RDP Disabled and Guest Account Disabled from risk items (they are strengths)
    $ConsolidatedFindings = $ConsolidatedFindings | Where-Object {
        $dominated = $false
        if ($_.Item -like "*Remote Desktop*" -and $_.Value -like "*Disabled*") {
            $dominated = $true
        }
        if ($_.Item -like "*Guest Account*" -and $_.Value -like "*Disabled*") {
            $dominated = $true
        }
        -not $dominated
    }

    # Filter risky ports that are just default Windows ports
    if ($ReportConfig.default_windows_ports) {
        $DefaultPorts = $ReportConfig.default_windows_ports
        $ConsolidatedFindings = $ConsolidatedFindings | Where-Object {
            if ($_.Item -like "*Risky*Port*" -or $_.Item -like "*Open Port*") {
                # Check if all ports mentioned are default ports
                $PortNumbers = [regex]::Matches($_.Details, "\b(\d{2,5})\b") | ForEach-Object { [int]$_.Groups[1].Value }
                $NonDefaultPorts = $PortNumbers | Where-Object { $_ -notin $DefaultPorts }
                if ($NonDefaultPorts.Count -eq 0 -and $PortNumbers.Count -gt 0) {
                    Write-Verbose "Excluding $($_.Item) - only default Windows ports detected"
                    return $false
                }
            }
            return $true
        }
    }

    # ============================================================================
    # TECHNICAL DEBT: Filter band-aids loaded from config
    # See config/report-presentation.json "technical_debt" section for details
    # ============================================================================

    # Process HIGH risk findings - filter using config
    $HighRiskItems = $ConsolidatedFindings | Where-Object {
        $_.RiskLevel -eq "HIGH" -and
        -not (Test-FindingShouldBeFiltered -Finding $_ -Config $ReportConfig)
    } |
        Group-Object Category, Item |
        ForEach-Object {
            $AllFindings = $_.Group
            $Finding = $AllFindings[0]
            $AffectedSystems = $AllFindings | Select-Object -Unique SystemName

            # Format details using config-driven processor - pass all findings for per-system detail
            $FormattedDetails = Format-FindingDetails -Findings $AllFindings -ReportConfig $ReportConfig

            # Get recommendation using config-driven processor
            $RecommendationText = Get-DefaultRecommendation -Finding $Finding -ReportConfig $ReportConfig

            [PSCustomObject]@{
                RiskFactor = $Finding.Item
                Category = $Finding.Category
                Description = $FormattedDetails
                Recommendation = $RecommendationText
                AffectedCount = $AffectedSystems.Count
                AffectedSystems = ($AffectedSystems.SystemName -join ", ")
                Severity = "Critical"
            }
        } | Sort-Object AffectedCount -Descending

    $RiskAnalysis.HighRiskFindings = $HighRiskItems
    
    # ============================================================================
    # TECHNICAL DEBT: Same config-driven filters applied to MEDIUM risk
    # ============================================================================

    # Process MEDIUM risk findings - filter using config
    $MediumRiskItems = $ConsolidatedFindings | Where-Object {
        $_.RiskLevel -eq "MEDIUM" -and
        -not (Test-FindingShouldBeFiltered -Finding $_ -Config $ReportConfig)
    } |
        Group-Object Category, Item |
        ForEach-Object {
            $AllFindings = $_.Group
            $Finding = $AllFindings[0]
            $AffectedSystems = $AllFindings | Select-Object -Unique SystemName

            # Format details using config-driven processor - pass all findings for per-system detail
            $FormattedDetails = Format-FindingDetails -Findings $AllFindings -ReportConfig $ReportConfig

            # Get recommendation using config-driven processor
            $RecommendationText = Get-DefaultRecommendation -Finding $Finding -ReportConfig $ReportConfig

            [PSCustomObject]@{
                RiskFactor = $Finding.Item
                Category = $Finding.Category
                Description = $FormattedDetails
                Recommendation = $RecommendationText
                AffectedCount = $AffectedSystems.Count
                AffectedSystems = ($AffectedSystems.SystemName -join ", ")
                Severity = "Moderate"
            }
        } | Sort-Object AffectedCount -Descending | Select-Object -First 10

    $RiskAnalysis.MediumRiskFindings = $MediumRiskItems
    
    # ============================================================================
    # TECHNICAL DEBT: Same config-driven filters applied to LOW risk
    # ============================================================================

    # Process LOW risk findings (informational) - filter using config
    $LowRiskItems = $ConsolidatedFindings | Where-Object {
        $_.RiskLevel -eq "LOW" -and
        -not (Test-FindingShouldBeFiltered -Finding $_ -Config $ReportConfig)
    } |
        Group-Object Category, Item |
        ForEach-Object {
            $AllFindings = $_.Group
            $Finding = $AllFindings[0]
            $AffectedSystems = $AllFindings | Select-Object -Unique SystemName

            # Format details using config-driven processor - pass all findings for per-system detail
            $FormattedDetails = Format-FindingDetails -Findings $AllFindings -ReportConfig $ReportConfig

            # Get recommendation using config-driven processor
            $RecommendationText = Get-DefaultRecommendation -Finding $Finding -ReportConfig $ReportConfig

            [PSCustomObject]@{
                RiskFactor = $Finding.Item
                Category = $Finding.Category
                Description = $FormattedDetails
                Recommendation = $RecommendationText
                AffectedCount = $AffectedSystems.Count
                AffectedSystems = ($AffectedSystems.SystemName -join ", ")
                Severity = "Low"
            }
        } | Sort-Object AffectedCount -Descending

    # Separate dark web findings into their own section
    $DarkWebItems = $LowRiskItems | Where-Object { $_.Category -eq "Dark Web Analysis" }
    $OtherLowRiskFindings = $LowRiskItems | Where-Object { $_.Category -ne "Dark Web Analysis" } | Select-Object -First 5

    $RiskAnalysis.DarkWebFindings = $DarkWebItems
    $RiskAnalysis.LowRiskFindings = $OtherLowRiskFindings
    
    # Generate Systems Snapshot (similar to Computer Snapshot table)
    # Exclude dark web checks - only include actual computer systems
    # Use consolidated (filtered) findings for accurate grading
    $ActualSystems = $ImportedData.Systems | Where-Object { $_.SystemType -ne "Breach Monitor" }
    foreach ($System in $ActualSystems) {
        $SystemFindings = $ConsolidatedFindings | Where-Object { $_.SystemName -eq $System.ComputerName }
        
        # Calculate grades for each category
        $Grades = @{
            Security = Get-SystemGrade -Findings ($SystemFindings | Where-Object { $_.Category -eq "Security" }) -ReportConfig $ReportConfig
            Users = Get-SystemGrade -Findings ($SystemFindings | Where-Object { $_.Category -eq "Users" }) -ReportConfig $ReportConfig
            Network = Get-SystemGrade -Findings ($SystemFindings | Where-Object { $_.Category -eq "Network" }) -ReportConfig $ReportConfig
            Patching = Get-SystemGrade -Findings ($SystemFindings | Where-Object { $_.Category -eq "Patching" }) -ReportConfig $ReportConfig
            System = Get-SystemGrade -Findings ($SystemFindings | Where-Object { $_.Category -eq "System" }) -ReportConfig $ReportConfig
        }

        # Calculate overall grade
        $OverallGrade = Get-OverallGrade -Grades $Grades -ReportConfig $ReportConfig
        
        $SystemSnapshot = [PSCustomObject]@{
            ComputerName = $System.ComputerName
            OverallGrade = $OverallGrade
            SecurityGrade = $Grades.Security
            UsersGrade = $Grades.Users  
            NetworkGrade = $Grades.Network
            PatchingGrade = $Grades.Patching
            SystemGrade = $Grades.System
            OperatingSystem = $System.OperatingSystem
            SystemType = $System.SystemType
            HighRiskCount = ($SystemFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
            MediumRiskCount = ($SystemFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
            FindingsCount = $SystemFindings.Count
        }
        
        $RiskAnalysis.SystemsSnapshot += $SystemSnapshot
    }
    
    # Calculate risk summary
    $RiskAnalysis.RiskSummary = @{
        TotalRisks = $RiskAnalysis.HighRiskFindings.Count + $RiskAnalysis.MediumRiskFindings.Count
        CriticalSystems = ($RiskAnalysis.SystemsSnapshot | Where-Object { $_.OverallGrade -in @("C", "D", "F") }).Count
        ImmediateActions = $RiskAnalysis.HighRiskFindings.Count
        SystemsNeedingAttention = ($RiskAnalysis.SystemsSnapshot | Where-Object { $_.HighRiskCount -gt 0 }).Count
    }
    
    Write-Verbose "Risk analysis completed: $($RiskAnalysis.HighRiskFindings.Count) high-risk, $($RiskAnalysis.MediumRiskFindings.Count) medium-risk findings"
    
    return $RiskAnalysis
}

function Get-SystemGrade {
    <#
    .SYNOPSIS
        Calculates letter grade (A-F) for a system category based on risk findings
    .DESCRIPTION
        Uses configurable thresholds from report-config.json to determine grades
    #>
    param(
        [array]$Findings,
        [PSCustomObject]$ReportConfig
    )

    if (-not $Findings -or $Findings.Count -eq 0) { return "A" }

    $HighRisk = ($Findings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $MediumRisk = ($Findings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count

    # Use config-driven thresholds if available, otherwise fall back to defaults
    if ($ReportConfig -and $ReportConfig.grading_rules -and $ReportConfig.grading_rules.category_thresholds) {
        $Thresholds = $ReportConfig.grading_rules.category_thresholds

        # Evaluate grades in order: F, D, C, B, A
        foreach ($GradeLetter in @("F", "D", "C", "B", "A")) {
            $Threshold = $Thresholds.$GradeLetter
            if (-not $Threshold) { continue }

            $HighMatch = $true
            $MediumMatch = $true

            # Check HIGH risk thresholds
            if ($Threshold.high_min -ne $null) {
                if ($HighRisk -lt $Threshold.high_min) { $HighMatch = $false }
            }
            if ($Threshold.high_max -ne $null) {
                if ($HighRisk -gt $Threshold.high_max) { $HighMatch = $false }
            }

            # Check MEDIUM risk thresholds
            if ($Threshold.medium_min -ne $null) {
                if ($MediumRisk -lt $Threshold.medium_min) { $MediumMatch = $false }
            }
            if ($Threshold.medium_max -ne $null) {
                if ($MediumRisk -gt $Threshold.medium_max) { $MediumMatch = $false }
            }

            # For grade C, it's HIGH=1 OR MEDIUM>=3, so use OR logic
            if ($GradeLetter -eq "C") {
                if ($HighMatch -or $MediumMatch) {
                    return $GradeLetter
                }
            }
            # For other grades, both conditions must match
            elseif ($HighMatch -and $MediumMatch) {
                return $GradeLetter
            }
        }
    }

    # Fallback to hardcoded logic if config not available
    if ($HighRisk -gt 0) {
        if ($HighRisk -ge 3) { return "F" }
        elseif ($HighRisk -eq 2) { return "D" }
        else { return "C" }
    }
    elseif ($MediumRisk -gt 0) {
        if ($MediumRisk -ge 3) { return "C" }
        else { return "B" }
    }

    return "A"
}

function Get-OverallGrade {
    <#
    .SYNOPSIS
        Calculates overall system grade from category grades
    .DESCRIPTION
        Uses configurable category weights and grade values from report-config.json
        to calculate weighted average of all category grades
    #>
    param(
        [hashtable]$Grades,
        [PSCustomObject]$ReportConfig
    )

    # Get grade values and weights from config or use defaults
    if ($ReportConfig -and $ReportConfig.grading_rules) {
        $GradeValues = @{}
        if ($ReportConfig.grading_rules.grade_values) {
            foreach ($Prop in $ReportConfig.grading_rules.grade_values.PSObject.Properties) {
                # Skip documentation properties
                if ($Prop.Name -notlike "_*") {
                    $GradeValues[$Prop.Name] = [int]$Prop.Value
                }
            }
        } else {
            # Default values
            $GradeValues = @{ "A" = 4; "B" = 3; "C" = 2; "D" = 1; "F" = 0 }
        }

        $CategoryWeights = @{}
        if ($ReportConfig.grading_rules.category_weights) {
            foreach ($Prop in $ReportConfig.grading_rules.category_weights.PSObject.Properties) {
                # Skip documentation properties
                if ($Prop.Name -notlike "_*") {
                    $CategoryWeights[$Prop.Name] = [double]$Prop.Value
                }
            }
        }
    } else {
        # Default values if config not available
        $GradeValues = @{ "A" = 4; "B" = 3; "C" = 2; "D" = 1; "F" = 0 }
        $CategoryWeights = @{}
    }

    # Build reverse lookup (value to letter)
    $GradeLetters = @{}
    foreach ($Letter in $GradeValues.Keys) {
        $Value = [int]$GradeValues[$Letter]
        $GradeLetters[$Value] = $Letter
    }

    $TotalWeightedValue = 0
    $TotalWeight = 0

    foreach ($CategoryName in $Grades.Keys) {
        $Grade = $Grades[$CategoryName]
        $GradeValue = $GradeValues[$Grade]

        # Get weight for this category (default 1.0 if not specified)
        $Weight = if ($CategoryWeights.ContainsKey($CategoryName)) {
            $CategoryWeights[$CategoryName]
        } else {
            1.0
        }

        $TotalWeightedValue += ($GradeValue * $Weight)
        $TotalWeight += $Weight
    }

    if ($TotalWeight -eq 0) { return "A" }

    # Calculate weighted average and round
    $Average = [int][math]::Round($TotalWeightedValue / $TotalWeight)

    # Ensure average is within valid range
    if ($Average -gt 4) { $Average = 4 }
    if ($Average -lt 0) { $Average = 0 }

    return $GradeLetters[$Average]
}

# Config-driven finding processing functions
# These replace the old hardcoded logic with configurable processors

function Get-FindingProcessor {
    <#
    .SYNOPSIS
        Gets processor configuration for a finding type (stub function)
    #>
    param(
        [string]$Item,
        [PSCustomObject]$Config
    )

    # Stub function - returns null if no config available
    if (-not $Config -or -not $Config.finding_processors) {
        return $null
    }

    # Look up processor in config
    foreach ($Prop in $Config.finding_processors.PSObject.Properties) {
        if ($Item -like "*$($Prop.Name)*") {
            return $Prop.Value
        }
    }

    return $null
}

function Format-FindingWithProcessor {
    <#
    .SYNOPSIS
        Formats finding using processor config (stub function)
    #>
    param(
        [PSCustomObject]$Finding,
        [PSCustomObject]$Processor
    )

    # Stub function - returns Details as-is
    return $Finding.Details
}

function Get-ProcessedRecommendation {
    <#
    .SYNOPSIS
        Gets recommendation using processor config (stub function)
    #>
    param(
        [PSCustomObject]$Finding,
        [PSCustomObject]$Processor
    )

    # Stub function - returns Recommendation as-is
    return $Finding.Recommendation
}

function Test-FindingExcluded {
    <#
    .SYNOPSIS
        Checks if finding is excluded (stub function)
    #>
    param(
        [PSCustomObject]$Finding,
        [PSCustomObject]$Config
    )

    # Stub function - never exclude
    return $false
}

function Get-FindingSignificance {
    <#
    .SYNOPSIS
        Gets finding significance level (stub function)
    #>
    param(
        [PSCustomObject]$Finding,
        [PSCustomObject]$Config
    )

    # Stub function - always return normal significance
    return "normal"
}

function Test-SystemTypeRelevant {
    <#
    .SYNOPSIS
        Checks if finding is relevant for system type (stub function)
    #>
    param(
        [PSCustomObject]$Finding,
        [string]$SystemType,
        [PSCustomObject]$Config
    )

    # Stub function - always relevant
    return $true
}

function Format-FindingDetails {
    <#
    .SYNOPSIS
        Formats finding details using config-driven processors
    #>
    param(
        [PSCustomObject[]]$Findings,
        [PSCustomObject]$ReportConfig
    )

    # If multiple findings, format with per-system details
    if ($Findings.Count -gt 1) {
        return Format-MultiSystemDetails -Findings $Findings -ReportConfig $ReportConfig
    }

    # Single finding - use Details field
    $Finding = $Findings[0]

    # If config is available, try to use processor
    if ($ReportConfig) {
        $Processor = Get-FindingProcessor -Item $Finding.Item -Config $ReportConfig
        if ($Processor) {
            return Format-FindingWithProcessor -Finding $Finding -Processor $Processor
        }
    }

    # No config or processor, use Details as-is
    return $Finding.Details
}

function Format-MultiSystemDetails {
    <#
    .SYNOPSIS
        Formats multiple findings with per-system details
    #>
    param(
        [PSCustomObject[]]$Findings,
        [PSCustomObject]$ReportConfig
    )

    $Finding = $Findings[0]
    $ItemName = $Finding.Item

    # Get processor for formatting rules
    $Processor = Get-FindingProcessor -Item $ItemName -Config $ReportConfig

    # Check if this is a domain-wide finding (same data across all systems)
    # Use config to determine domain-wide patterns
    $IsDomainWide = Test-ItemMatchesAnyPattern -Item $ItemName -Patterns $ReportConfig.grouping.domain_wide_findings

    # For domain-wide findings, just return the first finding's details (they're all the same)
    if ($IsDomainWide) {
        # For Password Age Analysis and Disabled Domain Accounts, prefer Value which has the count
        if ($ItemName -match "Password Age Analysis|Disabled Domain Accounts") {
            if ($Finding.Value) {
                # Format the count nicely
                if ($ItemName -match "Disabled Domain Accounts") {
                    return "$($Finding.Value) disabled domain accounts"
                } else {
                    return $Finding.Value
                }
            }
        }
        # For other domain-wide findings, use Details
        if ($Finding.Details) {
            return $Finding.Details
        } elseif ($Finding.Value) {
            return $Finding.Value
        }
    }

    # Special handling for Privileged Group - show all groups with member counts
    if ($ItemName -match "Privileged Group") {
        # Get all unique group Values (deduplicate across DCs since it's domain-wide)
        $AllGroups = @()
        $SeenGroups = @{}

        Write-Verbose "Processing $($Findings.Count) Privileged Group findings"
        foreach ($F in $Findings) {
            Write-Verbose "  - Value: $($F.Value)"
            if ($F.Value -and -not $SeenGroups.ContainsKey($F.Value)) {
                $AllGroups += $F.Value
                $SeenGroups[$F.Value] = $true
            }
        }

        Write-Verbose "Found $($AllGroups.Count) unique privileged groups: $($AllGroups -join ', ')"

        # Return groups as bullet list if multiple, otherwise single value
        if ($AllGroups.Count -gt 1) {
            return ($AllGroups -join "|||")
        } elseif ($AllGroups.Count -eq 1) {
            return $AllGroups[0]
        } else {
            return "High-privilege group membership count"
        }
    }

    # Build per-system details based on finding type
    $SystemDetails = @()

    # Special handling for BitLocker - add context about total systems
    if ($ItemName -match "BitLocker.*Encryption" -and -not ($ItemName -match "Summary|Volume")) {
        $TotalSystems = ($ImportedData.Systems | Where-Object { $_.SystemType -ne "Breach Monitor" }).Count
        $UnencryptedCount = $Findings.Count
        $SystemDetails += "WARNING: $UnencryptedCount of $TotalSystems systems lack full disk encryption"

        # Still list individual systems
        foreach ($F in $Findings) {
            $SystemDetails += "$($F.SystemName) (No disk encryption)"
        }

        return ($SystemDetails -join "|||")
    }

    # For certain finding types, group by system first to collect multiple values
    # Use config to determine which findings require system grouping
    $RequiresSystemGrouping = Test-ItemMatchesAnyPattern -Item $ItemName -Patterns $ReportConfig.grouping.combine_per_system

    if ($RequiresSystemGrouping) {
        # Group findings by system to collect all products per system
        $BySystem = $Findings | Group-Object SystemName
        foreach ($SystemGroup in $BySystem) {
            $SystemName = $SystemGroup.Name
            $Products = $SystemGroup.Group | ForEach-Object { $_.Value } | Where-Object { $_ }
            if ($Products) {
                $Detail = "$SystemName ($($Products -join ', '))"
                $SystemDetails += $Detail
            }
        }
        # Return early since we've already built the details
        return ($SystemDetails -join "|||")
    }

    foreach ($F in $Findings) {
        $SystemName = $F.SystemName
        $Detail = ""

        # Extract meaningful detail based on finding type
        switch -Regex ($ItemName) {
            "Local Administrators|Domain Admins|Privileged Group" {
                # Show admin names
                # For Local Administrators, names are in Details field like "Users: name1, name2, ..."
                if ($F.Details -match "Users?:\s*(.+)") {
                    $AdminList = $Matches[1] -split ',\s*' | Select-Object -First 8
                    $Detail = "$SystemName ($($AdminList -join ', '))"
                    if (($Matches[1] -split ',').Count -gt 8) {
                        $Detail += " + $(($Matches[1] -split ',').Count - 8) more"
                    }
                } elseif ($F.Value) {
                    # Fallback to Value if Details doesn't have the pattern
                    $AdminList = $F.Value -split ',\s*' | Select-Object -First 8
                    $Detail = "$SystemName ($($AdminList -join ', '))"
                    if (($F.Value -split ',').Count -gt 8) {
                        $Detail += " + $(($F.Value -split ',').Count - 8) more"
                    }
                } else {
                    $Detail = "$SystemName ($($F.Value) admins)"
                }
            }
            "Open Ports|Risky Open Ports" {
                # Show port numbers
                if ($F.Value) {
                    $Detail = "$SystemName (Ports: $($F.Value))"
                } elseif ($F.Details -match 'Ports?:\s*(.+)') {
                    $Detail = "$SystemName (Ports: $($Matches[1]))"
                } else {
                    $Detail = "$SystemName"
                }
            }
            "Critical Role|Server Roles" {
                # Show roles per server
                if ($F.Value) {
                    $Detail = "$SystemName ($($F.Value))"
                } else {
                    $Detail = "$SystemName"
                }
            }
            "File Share|Network Share" {
                # Show share name and path
                if ($F.Value) {
                    $Detail = "$SystemName ($($F.Value))"
                } else {
                    $Detail = "$SystemName"
                }
            }
            "Remote Access Software|RMM.*Software" {
                # Show software name per system
                if ($F.Value) {
                    $Detail = "$SystemName ($($F.Value))"
                } else {
                    $Detail = "$SystemName"
                }
            }
            "Antivirus Protection Summary" {
                # Show which AV products are active
                if ($F.Details -match "Active products?:\s*(.+)") {
                    $Detail = "$SystemName ($($Matches[1]))"
                } elseif ($F.Value) {
                    $Detail = "$SystemName ($($F.Value))"
                } else {
                    $Detail = "$SystemName"
                }
            }
            "Available Updates" {
                # Show update counts per system
                if ($F.Details -match "Available:\s*(.+)") {
                    # macOS format - extract update details from Details field
                    $Detail = "$SystemName ($($Matches[1]))"
                } elseif ($F.Value) {
                    # Windows format - Value already includes "updates" text
                    $Detail = "$SystemName ($($F.Value))"
                } else {
                    $Detail = "$SystemName"
                }
            }
            "Disk Space|Disk Health" {
                # Show disk details per system
                if ($F.Details) {
                    $Detail = "$SystemName ($($F.Details))"
                } else {
                    $Detail = "$SystemName"
                }
            }
            "Password.*Age|Password Policy" {
                # Show password details
                if ($F.Details) {
                    $Detail = "$SystemName ($($F.Details))"
                } else {
                    $Detail = "$SystemName"
                }
            }
            "Screen Lock Policy" {
                # Show screen lock configuration details
                if ($F.Details) {
                    $Detail = "$SystemName ($($F.Details))"
                } elseif ($F.Value) {
                    $Detail = "$SystemName ($($F.Value))"
                } else {
                    $Detail = "$SystemName"
                }
            }
            default {
                # Generic: show system with value or details
                if ($F.Value -and $F.Value.ToString().Length -lt 100) {
                    $Detail = "$SystemName ($($F.Value))"
                } elseif ($F.Details -and $F.Details.Length -lt 100) {
                    $Detail = "$SystemName ($($F.Details))"
                } else {
                    $Detail = "$SystemName"
                }
            }
        }

        $SystemDetails += $Detail
    }

    # Join with special delimiter for HTML formatting
    return ($SystemDetails -join "|||")
}

function Get-DefaultRecommendation {
    <#
    .SYNOPSIS
        Gets recommendation using config-driven processors
    #>
    param(
        [PSCustomObject]$Finding,
        [PSCustomObject]$ReportConfig
    )

    # If config available, try to use processor
    if ($ReportConfig) {
        $Processor = Get-FindingProcessor -Item $Finding.Item -Config $ReportConfig
        if ($Processor) {
            return Get-ProcessedRecommendation -Finding $Finding -Processor $Processor
        }
    }

    # No config or processor, use Finding.Recommendation as-is
    return $Finding.Recommendation
}

function Remove-RedundantFindings {
    <#
    .SYNOPSIS
        Filters findings based on significance levels and exclusion rules
    #>
    param(
        [array]$AllFindings,
        [PSCustomObject]$ReportConfig
    )

    # If no config, return all findings
    if (-not $ReportConfig) {
        return $AllFindings
    }

    $Filtered = $AllFindings | Where-Object {
        $Finding = $_

        # Check omit_from_report list first
        if ($ReportConfig.omit_from_report) {
            foreach ($OmitItem in $ReportConfig.omit_from_report) {
                if ($Finding.Item -like "*$OmitItem*") {
                    Write-Verbose "Omitting $($Finding.Item) - matches omit_from_report: $OmitItem"
                    return $false
                }
            }
        }

        # Check if explicitly excluded (old redundancy rules)
        if (Test-FindingExcluded -Finding $Finding -Config $ReportConfig) {
            return $false
        }

        # Check significance level - exclude if marked as "exclude"
        $Significance = Get-FindingSignificance -Finding $Finding -Config $ReportConfig
        if ($Significance -eq "exclude") {
            Write-Verbose "Excluding $($Finding.Item) based on significance level"
            return $false
        }

        # Check system type relevance (existing logic)
        if ($Finding.SystemType) {
            $SystemType = if ($Finding.SystemType -like "*Server*") { "server" } else { "workstation" }
            if (-not (Test-SystemTypeRelevant -Finding $Finding -SystemType $SystemType -Config $ReportConfig)) {
                return $false
            }
        }

        # NEW: Apply threshold filters
        if (-not (Test-ThresholdMet -Finding $Finding -Config $ReportConfig)) {
            return $false
        }

        # NEW: Apply validation checks
        if (-not (Test-ValidationPassed -Finding $Finding -Config $ReportConfig)) {
            return $false
        }

        # NEW: Check system-type specific exclusions
        if (-not (Test-SystemTypeAllowed -Finding $Finding -Config $ReportConfig)) {
            return $false
        }

        return $true
    }

    $RemovedCount = $AllFindings.Count - $Filtered.Count
    if ($RemovedCount -gt 0) {
        Write-Verbose "Filtered out $RemovedCount findings based on framework rules"
    }

    return $Filtered
}

function Test-ThresholdMet {
    <#
    .SYNOPSIS
        Checks if finding meets minimum threshold
    #>
    param(
        [PSCustomObject]$Finding,
        [PSCustomObject]$Config
    )

    if (-not $Config.filtering_rules -or -not $Config.filtering_rules.threshold_filters) {
        return $true
    }

    $ThresholdConfig = $Config.filtering_rules.threshold_filters.PSObject.Properties |
        Where-Object { $Finding.Item -like "*$($_.Name)*" } |
        Select-Object -First 1

    if (-not $ThresholdConfig) {
        return $true
    }

    $Threshold = $ThresholdConfig.Value

    # Check Failed Logon threshold
    if ($Finding.Item -like "*Failed Logon*" -and $Threshold.min_count) {
        if ($Finding.Details -match "(\d+)\s+failed\s+logon") {
            $Count = [int]$Matches[1]
            if ($Count -lt $Threshold.min_count) {
                Write-Verbose "Excluding $($Finding.Item) - only $Count events (threshold: $($Threshold.min_count))"
                return $false
            }
        }
    }

    # Check PowerShell Execution threshold
    if ($Finding.Item -like "*PowerShell Execution*" -and $Threshold.min_suspicious_count) {
        $SuspiciousCount = 0
        if ($Finding.Details -match "Policy Bypass \((\d+)\)") { $SuspiciousCount += [int]$Matches[1] }
        if ($Finding.Details -match "Network Downloads \((\d+)\)") { $SuspiciousCount += [int]$Matches[1] }
        if ($Finding.Details -match "Invoke Commands \((\d+)\)") { $SuspiciousCount += [int]$Matches[1] }

        if ($SuspiciousCount -lt $Threshold.min_suspicious_count) {
            Write-Verbose "Excluding $($Finding.Item) - only $SuspiciousCount suspicious activities (threshold: $($Threshold.min_suspicious_count))"
            return $false
        }
    }

    return $true
}

function Test-ValidationPassed {
    <#
    .SYNOPSIS
        Validates finding data before including in report
    .DESCRIPTION
        Applies config-driven validation rules to filter findings:
        - Pattern matching (exact and regex)
        - Empty value exclusion
        - Pattern-based exclusions (e.g., SYSVOL/NETLOGON)
        - Antivirus product detection (exclude if products present)
        - Disk space thresholds (exclude if sufficient free space)
    .PARAMETER Finding
        Finding object to validate
    .PARAMETER Config
        Report configuration containing validation rules
    .OUTPUTS
        Boolean - $true if finding passes validation, $false to exclude
    #>
    param(
        [PSCustomObject]$Finding,
        [PSCustomObject]$Config
    )

    if (-not $Config.filtering_rules -or -not $Config.filtering_rules.validation_checks) {
        return $true
    }

    # Try exact match first, then regex match
    $ValidationConfig = $Config.filtering_rules.validation_checks.PSObject.Properties |
        Where-Object { $Finding.Item -eq $_.Name } |
        Select-Object -First 1

    # If no exact match, try regex match (e.g., "Disk Space.*" matches "Disk Space (C:)")
    if (-not $ValidationConfig) {
        $ValidationConfig = $Config.filtering_rules.validation_checks.PSObject.Properties |
            Where-Object { $Finding.Item -match $_.Name } |
            Select-Object -First 1
    }

    if (-not $ValidationConfig) {
        return $true
    }

    $Validation = $ValidationConfig.Value

    # Check if required pattern is present
    if ($Validation.require_pattern) {
        $FieldValue = $Finding.Details
        if (-not ($FieldValue -match $Validation.require_pattern)) {
            Write-Verbose "Excluding $($Finding.Item) - validation pattern not found"
            return $false
        }
    }

    # Check if value is empty when it shouldn't be
    if ($Validation.exclude_if_empty -eq $true) {
        if (-not $Finding.Value -or $Finding.Value -eq "" -or $Finding.Value -eq "None") {
            Write-Verbose "Excluding $($Finding.Item) - empty value"
            return $false
        }
    }

    # Check exclude patterns (e.g., SYSVOL/NETLOGON for File Share)
    if ($Validation.exclude_patterns) {
        foreach ($ExcludePattern in $Validation.exclude_patterns) {
            if ($Finding.Details -match $ExcludePattern -or $Finding.Value -match $ExcludePattern) {
                Write-Verbose "Excluding $($Finding.Item) - matches exclude pattern: $ExcludePattern"
                return $false
            }
        }
    }

    # Check if this is Antivirus Protection Summary with products present
    if ($Validation.exclude_if_products_present -eq $true) {
        if ($Finding.Details -match "Active products?:\s*(.+)" -or $Finding.Value -match "product") {
            Write-Verbose "Excluding $($Finding.Item) - AV products detected (only flag missing AV as risk)"
            return $false
        }
    }

    # Check disk space - only show as risk if critically low
    if ($Validation.exclude_if_sufficient -eq $true) {
        # Check Value field for percentage free (Windows: "88.7% free")
        if ($Finding.Value -match "(\d+\.?\d*)%\s*free") {
            $FreePercent = [decimal]$Matches[1]
            $MinFreePercent = if ($Validation.min_free_percent) { $Validation.min_free_percent } else { 10 }
            if ($FreePercent -ge $MinFreePercent) {
                Write-Verbose "Excluding $($Finding.Item) - sufficient disk space ($FreePercent% free)"
                return $false
            }
        }
        # Check Details field for percentage used (macOS: "Used: 860Gi (99%)")
        elseif ($Finding.Details -match "Used:.*\((\d+)%\)") {
            $UsedPercent = [int]$Matches[1]
            $FreePercent = 100 - $UsedPercent
            $MinFreePercent = if ($Validation.min_free_percent) { $Validation.min_free_percent } else { 10 }
            if ($FreePercent -ge $MinFreePercent) {
                Write-Verbose "Excluding $($Finding.Item) - sufficient disk space ($FreePercent% free)"
                return $false
            }
        }
    }

    return $true
}

function Test-SystemTypeAllowed {
    <#
    .SYNOPSIS
        Checks if finding is allowed for this system type
    #>
    param(
        [PSCustomObject]$Finding,
        [PSCustomObject]$Config
    )

    if (-not $Config.filtering_rules -or -not $Config.filtering_rules.system_type_exclusions) {
        return $true
    }

    $SystemType = if ($Finding.SystemType -like "*Server*") { "server" } else { "workstation" }
    $Exclusions = $Config.filtering_rules.system_type_exclusions.$SystemType

    if (-not $Exclusions) {
        return $true
    }

    foreach ($ExclusionPattern in $Exclusions) {
        if ($Finding.Item -like "*$ExclusionPattern*") {
            Write-Verbose "Excluding $($Finding.Item) from $SystemType (system-type exclusion)"
            return $false
        }
    }

    return $true
}

function Apply-ConsolidationRules {
    <#
    .SYNOPSIS
        Consolidates related findings based on config rules
    #>
    param(
        [array]$Findings,
        [PSCustomObject]$ReportConfig
    )

    # If no config or no consolidation rules, return findings as-is
    if (-not $ReportConfig -or -not $ReportConfig.consolidation_rules -or -not $ReportConfig.consolidation_rules.rules) {
        return $Findings
    }

    $Consolidated = @()
    $ProcessedFindings = @{}

    # Get enabled consolidation rules
    $EnabledRules = $ReportConfig.consolidation_rules.rules | Where-Object { $_.enabled }

    foreach ($Finding in $Findings) {
        # Check if this finding should be consolidated
        $ApplicableRule = $null
        foreach ($Rule in $EnabledRules) {
            if ($Rule.merge_items -contains $Finding.Item) {
                $ApplicableRule = $Rule
                break
            }
        }

        if (-not $ApplicableRule) {
            # No consolidation rule, keep as-is (allow multiple findings per system+item)
            $Consolidated += $Finding
            continue
        }

        # Only track processed findings when consolidating
        $FindingKey = "$($Finding.SystemName)-$($Finding.Item)"

        # Skip if already processed
        if ($ProcessedFindings.ContainsKey($FindingKey)) {
            continue
        }

        # Consolidate findings for this rule
        if ($ApplicableRule.group_by_system) {
            # Group all related findings from the same system
            $RelatedFindings = $Findings | Where-Object {
                $_.SystemName -eq $Finding.SystemName -and
                $ApplicableRule.merge_items -contains $_.Item
            }

            if ($RelatedFindings.Count -gt 1) {
                # Create consolidated finding
                $RoleList = ($RelatedFindings | ForEach-Object { $_.Value }) -join ", "

                $ConsolidatedFinding = [PSCustomObject]@{
                    Category = $Finding.Category
                    Item = $ApplicableRule.merge_items[0]  # Use first item as the consolidated name
                    Value = $RoleList
                    Details = "Server roles: $RoleList"
                    RiskLevel = ($RelatedFindings | Sort-Object { if ($_.RiskLevel -eq "HIGH") { 0 } else { 1 } } | Select-Object -First 1).RiskLevel
                    Recommendation = "Ensure proper backup, monitoring, and security hardening for all critical roles"
                    SystemName = $Finding.SystemName
                    SystemType = $Finding.SystemType
                    AuditDate = $Finding.AuditDate
                    FindingId = "CONSOLIDATED-$($Finding.SystemName)-Roles"
                    Framework = $Finding.Framework
                }

                $Consolidated += $ConsolidatedFinding

                # Mark all related findings as processed
                foreach ($RF in $RelatedFindings) {
                    $ProcessedFindings["$($RF.SystemName)-$($RF.Item)"] = $true
                }
            } else {
                # Only one finding, keep as-is
                $Consolidated += $Finding
                $ProcessedFindings[$FindingKey] = $true
            }
        } else {
            # No special grouping, keep as-is
            $Consolidated += $Finding
            $ProcessedFindings[$FindingKey] = $true
        }
    }

    $ConsolidatedCount = $Findings.Count - $Consolidated.Count
    if ($ConsolidatedCount -gt 0) {
        Write-Verbose "Consolidated $ConsolidatedCount findings into fewer entries"
    }

    return $Consolidated
}