# NetworkAuditAggregator - Client Report Export
# Version 1.0.0

function Export-ClientReport {
    <#
    .SYNOPSIS
        Exports consolidated analysis to professional HTML report
        
    .DESCRIPTION
        Generates client-ready HTML report with executive summary, scoring matrix,
        and risk analysis sections matching professional consulting format.
        
    .PARAMETER ExecutiveSummary
        Executive summary data from Generate-ExecutiveSummary
        
    .PARAMETER ScoringMatrix
        Scoring matrix data from Generate-ScoringMatrix
        
    .PARAMETER RiskAnalysis
        Risk analysis data from Generate-RiskAnalysis
        
    .PARAMETER OutputPath
        Directory for generated report
        
    .PARAMETER ClientName
        Client name for report customization
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ExecutiveSummary,
        
        [Parameter(Mandatory = $true)] 
        [PSCustomObject]$ScoringMatrix,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$RiskAnalysis,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientName
    )
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Generate report filename
    $ReportDate = Get-Date -Format "yyyy-MM-dd"
    $SafeClientName = $ClientName -replace '[^\w\s-]', '' -replace '\s+', '-'
    $ReportFileName = "$SafeClientName-IT-Assessment-Report-$ReportDate.html"
    $ReportPath = Join-Path $OutputPath $ReportFileName
    
    Write-Verbose "Generating client report: $ReportFileName"
    
    # Generate HTML content
    $HtmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$ClientName - IT Assessment Report</title>
    <style>
        $(Get-ReportStyles)
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>$ClientName</h1>
            <h2>IT Assessment & Recommendations</h2>
            <p class="report-date">$($ExecutiveSummary.AssessmentDate)</p>
        </div>
        
        <!-- Executive Summary -->
        <div class="section">
            <h2 class="section-header">Executive Summary</h2>
            
            <div class="summary-metrics">
                <div class="metric-box">
                    <div class="metric-value">$($ExecutiveSummary.SystemsAssessed)</div>
                    <div class="metric-label">Systems Assessed</div>
                </div>
                <div class="metric-box high-risk">
                    <div class="metric-value">$($ExecutiveSummary.RiskDistribution.HighRisk)</div>
                    <div class="metric-label">High Risk</div>
                </div>
                <div class="metric-box medium-risk">
                    <div class="metric-value">$($ExecutiveSummary.RiskDistribution.MediumRisk)</div>
                    <div class="metric-label">Medium Risk</div>
                </div>
                <div class="metric-box low-risk">
                    <div class="metric-value">$($ExecutiveSummary.RiskDistribution.LowRisk)</div>
                    <div class="metric-label">Info Items</div>
                </div>
            </div>
            
            <div class="environment-overview">
                <h3>Environment Overview</h3>
                $(
                    $ScopeDetails = @()
                    if ($ExecutiveSummary.EnvironmentOverview.Workstations -gt 0) { $ScopeDetails += "$($ExecutiveSummary.EnvironmentOverview.Workstations) workstations" }
                    if ($ExecutiveSummary.EnvironmentOverview.Servers -gt 0) { $ScopeDetails += "$($ExecutiveSummary.EnvironmentOverview.Servers) servers" }
                    if ($ExecutiveSummary.EnvironmentOverview.DarkWebChecks -gt 0) { $ScopeDetails += "dark web analysis" }
                    $ScopeText = if ($ScopeDetails.Count -gt 0) { $ScopeDetails -join ', ' } else { "systems" }
                    "<p><strong>Assessment Scope:</strong> $ScopeText</p>"
                )
                <p><strong>Total Findings:</strong> $($ExecutiveSummary.TotalFindings) items identified across all systems</p>
            </div>

            <!-- Security Strengths Section -->
            $(if ($ExecutiveSummary.SecurityStrengths -and $ExecutiveSummary.SecurityStrengths.Count -gt 0) { @"
            <div class="security-strengths">
                <h3 style="color: #28a745; display: flex; align-items: center;">
                    Security Strengths
                </h3>
                <div style="background: linear-gradient(135deg, #e8f5e8 0%, #f0f9f0 100%); border-left: 4px solid #28a745; padding: 15px; border-radius: 8px; margin: 10px 0;">
                    <p style="margin-bottom: 15px; color: #155724;"><strong>Positive security findings and properly configured systems</strong></p>
                    $(
                        # Group security strengths by category for scalability
                        $StrengthGroups = $ExecutiveSummary.SecurityStrengths | Group-Object Category
                        ($StrengthGroups | ForEach-Object {
                            $CategoryName = $_.Name
                            $Items = $_.Group
                            $ItemCount = $Items.Count

                            "<div style='margin-bottom: 15px; padding: 10px; background: rgba(40, 167, 69, 0.1); border-radius: 4px;'>" +
                            "<strong style='color: #28a745;'>$CategoryName ($ItemCount types):</strong><br>" +
                            "<ul style='margin: 5px 0; padding-left: 20px; color: #155724;'>" +
                            (($Items | Select-Object -First 10 | ForEach-Object {
                                $DisplayText = $_.Strength
                                if ($_.SystemCount -gt 1) {
                                    $DisplayText += " ($($_.SystemCount) systems)"
                                }
                                "<li>$DisplayText</li>"
                            }) -join "") +
                            $(if ($ItemCount -gt 10) { "<li style='color: #6c757d;'><em>... and $($ItemCount - 10) more</em></li>" } else { "" }) +
                            "</ul>" +
                            "</div>"
                        }) -join ""
                    )
                    <p style="margin-top: 15px; margin-bottom: 0; color: #28a745; font-weight: bold;">
                        $($ExecutiveSummary.PositiveFindings.TotalPositiveFindings) total positive findings identified
                    </p>
                </div>
            </div>
"@ })
        </div>

        <!-- Risk Analysis -->
        <div class="section">
            <h2 class="section-header">Risk Analysis</h2>
            
            $(Generate-RiskSection -Title "High Risk" -Color "high-risk" -Findings $RiskAnalysis.HighRiskFindings)
            
            $(Generate-RiskSection -Title "Medium Risk" -Color "medium-risk" -Findings $RiskAnalysis.MediumRiskFindings)
            
            $(Generate-RiskSection -Title "Info Items" -Color "low-risk" -Findings $RiskAnalysis.LowRiskFindings)

            $(Generate-DarkWebSection -Findings $RiskAnalysis.DarkWebFindings)
        </div>

        <!-- Systems Snapshot -->
        <div class="section">
            <h2 class="section-header">Systems Overview</h2>
            <table class="systems-table">
                <thead>
                    <tr>
                        <th>Computer</th>
                        <th>Overall Grade</th>
                        <th>Security</th>
                        <th>Users</th>
                        <th>Network</th>
                        <th>Patching</th>
                        <th>System</th>
                        <th>High Risk Items</th>
                    </tr>
                </thead>
                <tbody>
                    $(Generate-SystemsTableRows -Systems $RiskAnalysis.SystemsSnapshot)
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p>Report generated on $(Get-Date -Format 'MMMM dd, yyyy') by BusinessNetworkAggregator v1.0.0</p>
        </div>
    </div>
</body>
</html>
"@
    
    # Write HTML file
    $HtmlContent | Set-Content -Path $ReportPath -Encoding UTF8
    
    Write-Verbose "Report exported to: $ReportPath"
    return $ReportPath
}

function Get-ReportStyles {
    return @"
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .header { text-align: center; padding: 40px 20px; background: #2c3e50; color: white; }
        .header h1 { margin: 0; font-size: 2.5em; font-weight: 300; }
        .header h2 { margin: 10px 0; font-size: 1.4em; font-weight: 300; opacity: 0.9; }
        .report-date { margin: 20px 0 0 0; font-size: 1.1em; opacity: 0.8; }
        
        .section { padding: 30px; border-bottom: 1px solid #eee; }
        .section-header { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; }
        
        .summary-metrics { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .metric-box { flex: 1; text-align: center; padding: 20px; border-radius: 8px; min-width: 120px; }
        .metric-box { background: #ecf0f1; }
        .metric-box.high-risk { background: #e74c3c; color: white; }
        .metric-box.medium-risk { background: #f39c12; color: white; }
        .metric-box.low-risk { background: #f1c40f; }
        .metric-value { font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }
        .metric-label { font-size: 0.9em; opacity: 0.8; }
        
        .environment-overview { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px; }
        .environment-overview h3 { margin-top: 0; color: #2c3e50; }
        
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border: 1px solid #ddd; }
        th { background: #34495e; color: white; font-weight: 600; }
        tr:nth-child(even) { background: #f8f9fa; }
        
        .risk-section { margin: 30px 0; }
        .risk-header { padding: 15px; border-radius: 8px 8px 0 0; color: white; font-weight: bold; font-size: 1.2em; }
        .risk-header.high-risk { background: #e74c3c; }
        .risk-header.medium-risk { background: #f39c12; }
        .risk-header.low-risk { background: #f1c40f; color: #2c3e50; }
        .risk-content { border: 1px solid #ddd; border-top: none; padding: 20px; background: white; }
        .risk-item { margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid #eee; }
        .risk-item:last-child { border-bottom: none; }
        .risk-title { font-weight: bold; color: #2c3e50; margin-bottom: 5px; }
        .risk-description { margin-bottom: 10px; color: #666; }
        .risk-recommendation { background: #e8f4f8; padding: 10px; border-radius: 4px; font-style: italic; }
        
        .systems-table th, .systems-table td { text-align: center; padding: 8px; }
        .grade-A { background: #2ecc71; color: white; font-weight: bold; }
        .grade-B { background: #3498db; color: white; font-weight: bold; }
        .grade-C { background: #f39c12; color: white; font-weight: bold; }
        .grade-D { background: #e67e22; color: white; font-weight: bold; }
        .grade-F { background: #e74c3c; color: white; font-weight: bold; }
        
        .footer { text-align: center; padding: 20px; background: #ecf0f1; color: #7f8c8d; font-size: 0.9em; }
        
        @media print {
            .container { box-shadow: none; }
            .section { page-break-inside: avoid; }
        }
"@
}

function Generate-ScoringTableRows {
    param([array]$Components)
    
    $rows = ""
    foreach ($component in $Components) {
        $adherenceClass = "adherence-$($component.ClientAdherence)"
        $rows += @"
        <tr>
            <td><strong>$($component.Component)</strong></td>
            <td>$($component.SectionCriticality)</td>
            <td class="$adherenceClass"><strong>$($component.ClientAdherence)</strong></td>
            <td>$($component.Overview)<br><small style="color: #666;">$($component.Details)</small></td>
        </tr>
"@
    }
    return $rows
}

function Generate-RiskSection {
    param([string]$Title, [string]$Color, [array]$Findings)
    
    if ($Findings.Count -eq 0) { return "" }
    
    $content = @"
    <div class="risk-section">
        <div class="risk-header $Color">$Title</div>
        <div class="risk-content">
"@
    
    foreach ($finding in $Findings) {
        # Format description - if it contains ||| delimiter, it's per-system data
        $DescriptionHtml = $finding.Description
        if ($finding.Description -and $finding.Description.Contains("|||")) {
            $SystemItems = $finding.Description -split '\|\|\|'
            $DescriptionHtml = "<ul style='margin: 5px 0; padding-left: 20px;'>`n"
            foreach ($Item in $SystemItems) {
                $DescriptionHtml += "                    <li>$Item</li>`n"
            }
            $DescriptionHtml += "                </ul>"
        }

        $content += @"
            <div class="risk-item">
                <div class="risk-title">$($finding.RiskFactor)</div>
                <div class="risk-description">$DescriptionHtml</div>
                <div class="risk-recommendation"><strong>Recommendation:</strong> $($finding.Recommendation)</div>
                <small><strong>Affected Systems ($($finding.AffectedCount)):</strong> $($finding.AffectedSystems)</small>
            </div>
"@
    }
    
    $content += @"
        </div>
    </div>
"@
    
    return $content
}

function Generate-DarkWebSection {
    <#
    .SYNOPSIS
        Generates Dark Web Analysis section with custom formatting for breach data
    #>
    param([array]$Findings)

    if ($Findings.Count -eq 0) { return "" }

    $content = @"
    <div class="risk-section">
        <div class="risk-header" style="background: #2c3e50; color: white;">Dark Web Analysis</div>
        <div class="risk-content">
            <p style="margin: 10px 0; padding: 10px; background: #ecf0f1; border-left: 4px solid #2c3e50; color: #2c3e50;">
                <strong>What this means:</strong> Historical data breaches involving your organization's domains have been identified.
                Compromised credentials from these breaches are often sold on dark web marketplaces and used in credential stuffing attacks,
                phishing campaigns, and targeted intrusions. Even old breaches remain valuable to attackers as many users reuse passwords
                across multiple services.
            </p>
"@

    foreach ($finding in $Findings) {
        # Parse breach details from Description field
        $breachDetails = $finding.Description

        # Extract domain from Value field (e.g., "adobe.com - Adobe")
        $domain = if ($finding.Description -match 'Breach Date:') {
            $breachDetails -replace ',?\s*Breach Date:.*', ''
        } else {
            "Unknown"
        }

        $content += @"
            <div class="risk-item" style="border-left: 4px solid #2c3e50;">
                <div class="risk-title">$($finding.RiskFactor)</div>
                <div class="risk-description">
                    <div style="margin-bottom: 8px;"><strong>Breach Details:</strong> $breachDetails</div>
                </div>
                <div class="risk-recommendation"><strong>Recommendation:</strong> $($finding.Recommendation)</div>
                <small style="color: #2c3e50;"><strong>Analysis Date:</strong> $($finding.AffectedSystems)</small>
            </div>
"@
    }

    $content += @"
        </div>
    </div>
"@

    return $content
}

function Generate-SystemsTableRows {
    param([array]$Systems)
    
    $rows = ""
    foreach ($system in $Systems) {
        $rows += @"
        <tr>
            <td><strong>$($system.ComputerName)</strong><br><small>$($system.OperatingSystem)</small></td>
            <td class="grade-$($system.OverallGrade)">$($system.OverallGrade)</td>
            <td class="grade-$($system.SecurityGrade)">$($system.SecurityGrade)</td>
            <td class="grade-$($system.UsersGrade)">$($system.UsersGrade)</td>
            <td class="grade-$($system.NetworkGrade)">$($system.NetworkGrade)</td>
            <td class="grade-$($system.PatchingGrade)">$($system.PatchingGrade)</td>
            <td class="grade-$($system.SystemGrade)">$($system.SystemGrade)</td>
            <td>$($system.HighRiskCount)</td>
        </tr>
"@
    }
    return $rows
}

function Generate-RecommendationsTableRows {
    param([array]$Recommendations)
    
    $rows = ""
    foreach ($rec in $Recommendations) {
        $priorityClass = if ($rec.Priority -eq 1) { "high-risk" } elseif ($rec.Priority -le 2) { "medium-risk" } else { "low-risk" }
        $rows += @"
        <tr>
            <td class="$priorityClass" style="text-align: center; font-weight: bold; color: white;">$($rec.Priority)</td>
            <td><strong>$($rec.Category)</strong></td>
            <td>$($rec.Recommendation)</td>
            <td>$($rec.Timeframe)</td>
            <td>$($rec.Impact)</td>
        </tr>
"@
    }
    return $rows
}