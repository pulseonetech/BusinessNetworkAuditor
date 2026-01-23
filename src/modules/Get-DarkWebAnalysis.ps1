# WindowsWorkstationAuditor - Dark Web Analysis Module
# Version 1.0.0 - Breach Database Integration

function Get-DarkWebAnalysis {
    <#
    .SYNOPSIS
        Analyzes email domains or addresses for exposed credentials using breach database API

    .DESCRIPTION
        Scans specified email domains or individual email addresses for compromised accounts using breach database API.
        Identifies breached accounts, breach sources, and dates to assess organizational exposure.

    .PARAMETER Domains
        Comma-separated list of email domains to check (e.g., "company.com,subsidiary.org")

    .PARAMETER EmailAddresses
        Comma-separated list of email addresses to check (e.g., "user1@company.com,user2@company.com")

    .PARAMETER EmailListPath
        Path to text file containing email addresses (one per line, no header)

    .PARAMETER ConfigPath
        Path to breach database API configuration file (default: .\config\hibp-api-config.json)

    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation

    .NOTES
        Requires: Write-LogMessage function, valid breach database API key (for email scanning)
        Dependencies: Internet connectivity, breach database API access
        Rate Limits: Respects API rate limiting with automatic retry
    #>

    param(
        [string]$Domains,
        [string]$EmailAddresses,
        [string]$EmailListPath,
        [string]$ConfigPath = ".\config\hibp-api-config.json",
        [switch]$DemoMode
    )

    Write-LogMessage "INFO" "Starting dark web analysis..." "DARKWEB"

    try {
        $Results = @()

        # Determine scanning method
        $HasDomains = -not [string]::IsNullOrWhiteSpace($Domains)
        $HasEmailAddresses = -not [string]::IsNullOrWhiteSpace($EmailAddresses)
        $HasEmailListPath = -not [string]::IsNullOrWhiteSpace($EmailListPath)

        # Validate input parameters
        if (-not $HasDomains -and -not $HasEmailAddresses -and -not $HasEmailListPath) {
            $Results += [PSCustomObject]@{
                Category = "Dark Web Analysis"
                Item = "Parameter Validation"
                Value = "ERROR"
                Details = "No scanning target specified. Use -Domains, -EmailAddresses, or -EmailListPath parameter."
                RiskLevel = "INFO"
                Recommendation = "Specify email domains or addresses to check for breaches"
            }
            return $Results
        }

        # Skip configuration check in demo mode
        if ($DemoMode) {
            Write-LogMessage "INFO" "Demo mode enabled - using simulated data" "DARKWEB"
        } else {
            # Try multiple config locations if default path doesn't exist
            if (-not (Test-Path $ConfigPath)) {
                $AlternatePaths = @(
                    (Join-Path $PSScriptRoot "..\config\hibp-api-config.json"),
                    (Join-Path $PSScriptRoot "..\..\config\hibp-api-config.json"),
                    ".\config\hibp-api-config.json",
                    "..\config\hibp-api-config.json"
                )
                foreach ($AltPath in $AlternatePaths) {
                    if (Test-Path $AltPath) {
                        $ConfigPath = $AltPath
                        break
                    }
                }
            }

            # Load configuration or create minimal config for subscription-free mode
            if (-not (Test-Path $ConfigPath)) {
                Write-LogMessage "WARN" "No configuration file found - will attempt subscription-free mode" "DARKWEB"
                # Create minimal config for subscription-free access
                $Config = @{
                    hibp = @{
                        base_url = "https://haveibeenpwned.com/api/v3"
                        recent_breach_threshold_days = 365
                        rate_limit_delay_ms = 2000
                        subscription_free_mode = $true
                    }
                }
            }
        }

        if ($DemoMode) {
            # Create dummy config for demo mode
            $Config = @{
                hibp = @{
                    recent_breach_threshold_days = 365
                    rate_limit_delay_ms = 100
                    base_url = "https://haveibeenpwned.com/api/v3"
                }
            }
        } elseif (Test-Path $ConfigPath) {
            try {
                $Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
                Write-LogMessage "SUCCESS" "Loaded breach database configuration" "DARKWEB"

                # Check API key - if not configured, use subscription-free mode
                if (-not $Config.hibp.api_key -or $Config.hibp.api_key -eq "YOUR_32_CHARACTER_HIBP_API_KEY_HERE") {
                    Write-LogMessage "WARN" "No API key configured - using subscription-free breach data (limited)" "DARKWEB"
                    $Config.hibp | Add-Member -MemberType NoteProperty -Name "subscription_free_mode" -Value $true -Force
                } else {
                    $Config.hibp | Add-Member -MemberType NoteProperty -Name "subscription_free_mode" -Value $false -Force
                }
            }
            catch {
                $Results += [PSCustomObject]@{
                    Category = "Dark Web Analysis"
                    Item = "Configuration"
                    Value = "ERROR"
                    Details = "Failed to parse configuration file: $($_.Exception.Message)"
                    RiskLevel = "INFO"
                    Recommendation = "Verify JSON syntax in configuration file"
                }
                return $Results
            }
        }

        # Determine what to scan
        if ($HasDomains) {
            # Domain-based scanning
            $DomainsToCheck = @()
            $DomainsToCheck += $Domains -split "," | ForEach-Object { $_.Trim() }

            if ($DomainsToCheck.Count -eq 0) {
                $Results += [PSCustomObject]@{
                    Category = "Dark Web Analysis"
                    Item = "Domain List"
                    Value = "ERROR"
                    Details = "No valid domains found to check"
                    RiskLevel = "INFO"
                    Recommendation = "Verify domain list contains valid email domains"
                }
                return $Results
            }

            Write-LogMessage "INFO" "Checking $($DomainsToCheck.Count) domain(s) for breaches" "DARKWEB"

            # Process each domain
            foreach ($Domain in $DomainsToCheck) {
                Write-LogMessage "INFO" "Analyzing domain: $Domain" "DARKWEB"

                try {
                    # Check domain breaches using breach database API or generate demo data
                    if ($DemoMode) {
                        $BreachData = Get-DemoBreachData -Domain $Domain
                    } elseif ($Config.hibp.subscription_free_mode) {
                        $BreachData = Invoke-SubscriptionFreeCheck -Domain $Domain -Config $Config
                    } else {
                        $BreachData = Invoke-HIBPDomainCheck -Domain $Domain -Config $Config
                    }

                    if ($BreachData.Success) {
                        # Process subscription-free breaches with full details
                        if ($BreachData.Breaches.Count -gt 0) {
                            foreach ($Breach in $BreachData.Breaches) {
                                $RiskLevel = Get-BreachRiskLevel -BreachDate $Breach.BreachDate -RecentThresholdDays $Config.hibp.recent_breach_threshold_days

                                $Results += [PSCustomObject]@{
                                    Category = "Dark Web Analysis"
                                    Item = "Domain Breach (Full Details)"
                                    Value = "$Domain - $($Breach.Name)"
                                    Details = "Breach Date: $($Breach.BreachDate), Accounts: $($Breach.PwnCount), Data: $($Breach.DataClasses -join ', ')"
                                    RiskLevel = $RiskLevel
                                    Recommendation = if ($RiskLevel -eq "HIGH") { "Recent breach detected - immediate password reset required for all domain accounts" } else { "Historical breach detected - verify users have updated passwords since breach date" }
                                }
                            }
                        }

                        # Process limited breaches (metadata only)
                        if ($BreachData.LimitedBreaches -and $BreachData.LimitedBreaches.Count -gt 0) {
                            foreach ($Breach in $BreachData.LimitedBreaches) {
                                $RiskLevel = Get-BreachRiskLevel -BreachDate $Breach.BreachDate -RecentThresholdDays $Config.hibp.recent_breach_threshold_days

                                $Results += [PSCustomObject]@{
                                    Category = "Dark Web Analysis"
                                    Item = "Domain Breach (Limited Info)"
                                    Value = "$Domain - $($Breach.Name)"
                                    Details = "Breach Date: $($Breach.BreachDate), Accounts: $($Breach.PwnCount), Data: $($Breach.DataClasses -join ', ') [Account details require paid API]"
                                    RiskLevel = $RiskLevel
                                    Recommendation = if ($RiskLevel -eq "HIGH") { "Recent breach detected - configure paid API key for detailed account analysis" } else { "Historical breach detected - configure paid API key for detailed account analysis" }
                                }
                            }
                        }

                        # If no breaches found at all
                        if ($BreachData.Breaches.Count -eq 0 -and ($BreachData.LimitedBreaches.Count -eq 0 -or -not $BreachData.LimitedBreaches)) {
                            $Results += [PSCustomObject]@{
                                Category = "Dark Web Analysis"
                                Item = "Domain Status"
                                Value = "$Domain - Clean"
                                Details = "No known breaches found for this domain"
                                RiskLevel = "INFO"
                                Recommendation = "Continue monitoring domain for future breaches"
                            }
                        }
                    } else {
                        $Results += [PSCustomObject]@{
                            Category = "Dark Web Analysis"
                            Item = "Domain Check"
                            Value = "$Domain - Error"
                            Details = $BreachData.Error
                            RiskLevel = "INFO"
                            Recommendation = "Verify domain name and API connectivity"
                        }
                    }

                    # Add a note if using subscription-free mode
                    if ($Config.hibp.subscription_free_mode -and $BreachData.Note) {
                        $Results += [PSCustomObject]@{
                            Category = "Dark Web Analysis"
                            Item = "Data Source"
                            Value = "Subscription-Free Mode"
                            Details = $BreachData.Note
                            RiskLevel = "INFO"
                            Recommendation = "For comprehensive domain-specific breach data, configure a paid API key"
                        }
                    }

                    # Rate limiting delay
                    if ($Config.hibp.rate_limit_delay_ms -gt 0) {
                        Start-Sleep -Milliseconds $Config.hibp.rate_limit_delay_ms
                    }
                }
                catch {
                    Write-LogMessage "ERROR" "Failed to check domain $Domain`: $($_.Exception.Message)" "DARKWEB"
                    $Results += [PSCustomObject]@{
                        Category = "Dark Web Analysis"
                        Item = "Domain Check"
                        Value = "$Domain - Exception"
                        Details = $_.Exception.Message
                        RiskLevel = "INFO"
                        Recommendation = "Check network connectivity and API configuration"
                    }
                }
            }

            Write-LogMessage "SUCCESS" "Completed dark web analysis for $($DomainsToCheck.Count) domain(s)" "DARKWEB"

        } elseif ($HasEmailAddresses -or $HasEmailListPath) {
            # Email-based scanning
            $EmailsToCheck = @()

            # Parse emails from comma-separated parameter
            if ($HasEmailAddresses) {
                $EmailsToCheck += $EmailAddresses -split "," | ForEach-Object { $_.Trim() }
            }

            # Load emails from file
            if ($HasEmailListPath) {
                $EmailsToCheck += Import-EmailListFromFile -FilePath $EmailListPath
            }

            if ($EmailsToCheck.Count -eq 0) {
                $Results += [PSCustomObject]@{
                    Category = "Dark Web Analysis"
                    Item = "Email List"
                    Value = "ERROR"
                    Details = "No valid email addresses found to check"
                    RiskLevel = "INFO"
                    Recommendation = "Verify email list contains valid email addresses"
                }
                return $Results
            }

            Write-LogMessage "INFO" "Checking $($EmailsToCheck.Count) email address(es) for breaches" "DARKWEB"

            # Process each email with progress tracking
            $ProcessedCount = 0
            $BreachedCount = 0
            $CleanCount = 0

            foreach ($Email in $EmailsToCheck) {
                $ProcessedCount++
                $ProgressPercent = [math]::Round(($ProcessedCount / $EmailsToCheck.Count) * 100, 1)

                Write-LogMessage "INFO" "[$ProcessedCount/$($EmailsToCheck.Count) - $ProgressPercent%] Checking: $Email" "DARKWEB"

                try {
                    # Check email breaches using breach database API or generate demo data
                    if ($DemoMode) {
                        $BreachData = Get-DemoBreachData -Domain $Email
                    } else {
                        # Email scanning requires API key
                        if ($Config.hibp.subscription_free_mode) {
                            Write-LogMessage "ERROR" "Email scanning requires a paid API key" "DARKWEB"
                            $Results += [PSCustomObject]@{
                                Category = "Dark Web Analysis"
                                Item = "Configuration Error"
                                Value = "API Key Required"
                                Details = "Email-based scanning requires a paid HIBP API key. Domain scanning does not."
                                RiskLevel = "INFO"
                                Recommendation = "Configure a paid API key in $ConfigPath or use domain-based scanning"
                            }
                            return $Results
                        }
                        $BreachData = Invoke-HIBPEmailCheck -EmailAddress $Email -Config $Config
                    }

                    if ($BreachData.Success) {
                        if ($BreachData.Breaches.Count -gt 0) {
                            $BreachedCount++

                            # Add summary finding for this email
                            $BreachNames = ($BreachData.Breaches | ForEach-Object { $_.Name }) -join ", "
                            $MostRecentBreach = ($BreachData.Breaches | Sort-Object BreachDate -Descending | Select-Object -First 1)
                            $RiskLevel = Get-BreachRiskLevel -BreachDate $MostRecentBreach.BreachDate -RecentThresholdDays $Config.hibp.recent_breach_threshold_days

                            $Results += [PSCustomObject]@{
                                Category = "Dark Web Analysis"
                                Item = "Email Breach"
                                Value = $Email
                                Details = "$($BreachData.Breaches.Count) breach(es) found: $BreachNames"
                                RiskLevel = $RiskLevel
                                Recommendation = if ($RiskLevel -eq "HIGH") { "Immediate password reset required - recent breach detected" } else { "Verify password has been changed since breach date" }
                            }

                            # Add detailed findings for each breach
                            foreach ($Breach in $BreachData.Breaches) {
                                $BreachRiskLevel = Get-BreachRiskLevel -BreachDate $Breach.BreachDate -RecentThresholdDays $Config.hibp.recent_breach_threshold_days
                                $DataTypes = if ($Breach.DataClasses) { $Breach.DataClasses -join ", " } else { "Unknown" }

                                $Results += [PSCustomObject]@{
                                    Category = "Dark Web Analysis"
                                    Item = "Breach Details - $($Breach.Name)"
                                    Value = $Email
                                    Details = "Date: $($Breach.BreachDate), Affected Accounts: $($Breach.PwnCount), Compromised Data: $DataTypes"
                                    RiskLevel = $BreachRiskLevel
                                    Recommendation = "Review breach details at haveibeenpwned.com and take appropriate action"
                                }
                            }
                        } else {
                            $CleanCount++
                            $Results += [PSCustomObject]@{
                                Category = "Dark Web Analysis"
                                Item = "Email Status"
                                Value = "$Email - Clean"
                                Details = "No known breaches found for this email address"
                                RiskLevel = "INFO"
                                Recommendation = "Continue monitoring for future breaches"
                            }
                        }
                    } else {
                        $Results += [PSCustomObject]@{
                            Category = "Dark Web Analysis"
                            Item = "Email Check"
                            Value = "$Email - Error"
                            Details = $BreachData.Error
                            RiskLevel = "INFO"
                            Recommendation = "Verify email format and API connectivity"
                        }
                    }

                    # Rate limiting delay
                    if ($Config.hibp.rate_limit_delay_ms -gt 0) {
                        Start-Sleep -Milliseconds $Config.hibp.rate_limit_delay_ms
                    }
                }
                catch {
                    Write-LogMessage "ERROR" "Failed to check email $Email`: $($_.Exception.Message)" "DARKWEB"
                    $Results += [PSCustomObject]@{
                        Category = "Dark Web Analysis"
                        Item = "Email Check"
                        Value = "$Email - Exception"
                        Details = $_.Exception.Message
                        RiskLevel = "INFO"
                        Recommendation = "Check network connectivity and API configuration"
                    }
                }
            }

            Write-LogMessage "SUCCESS" "Completed dark web analysis for $($EmailsToCheck.Count) email(s): $BreachedCount breached, $CleanCount clean" "DARKWEB"
        }

        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Dark web analysis failed: $($_.Exception.Message)" "DARKWEB"
        return @([PSCustomObject]@{
            Category = "Dark Web Analysis"
            Item = "Module Error"
            Value = "FAILED"
            Details = $_.Exception.Message
            RiskLevel = "INFO"
            Recommendation = "Check module configuration and dependencies"
        })
    }
}

function Invoke-HIBPDomainCheck {
    <#
    .SYNOPSIS
        Calls breach database API to check for domain breaches
    #>
    param(
        [string]$Domain,
        [object]$Config
    )

    try {
        $Headers = @{
            "hibp-api-key" = $Config.hibp.api_key
            "User-Agent" = "BusinessNetworkAuditor/1.0"
        }

        $Uri = "$($Config.hibp.base_url)/breacheddomain/$Domain"
        $QueryParams = @()

        if (-not $Config.settings.include_unverified_breaches) {
            $QueryParams += "includeUnverified=false"
        }

        if (-not $Config.settings.truncate_response) {
            $QueryParams += "truncateResponse=false"
        }

        if ($QueryParams.Count -gt 0) {
            $Uri += "?" + ($QueryParams -join "&")
        }

        $RetryCount = 0
        $MaxRetries = $Config.hibp.max_retries

        do {
            try {
                $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get -ErrorAction Stop

                return @{
                    Success = $true
                    Breaches = $Response
                    Error = $null
                }
            }
            catch {
                if ($_.Exception.Response.StatusCode -eq 429) {
                    # Rate limited
                    $RetryAfter = if ($_.Exception.Response.Headers["Retry-After"]) {
                        [int]$_.Exception.Response.Headers["Retry-After"] * 1000
                    } else {
                        $Config.hibp.rate_limit_delay_ms * 2
                    }

                    Write-LogMessage "WARN" "Rate limited, waiting $($RetryAfter)ms before retry" "DARKWEB"
                    Start-Sleep -Milliseconds $RetryAfter
                    $RetryCount++
                }
                elseif ($_.Exception.Response.StatusCode -eq 404) {
                    # No breaches found (this is actually success)
                    return @{
                        Success = $true
                        Breaches = @()
                        Error = $null
                    }
                }
                else {
                    throw
                }
            }
        } while ($RetryCount -lt $MaxRetries)

        # Max retries exceeded
        return @{
            Success = $false
            Breaches = @()
            Error = "Rate limit exceeded after $MaxRetries retries"
        }
    }
    catch {
        return @{
            Success = $false
            Breaches = @()
            Error = "API call failed: $($_.Exception.Message)"
        }
    }
}

function Invoke-HIBPEmailCheck {
    <#
    .SYNOPSIS
        Calls HIBP API to check for breaches associated with a specific email address
    #>
    param(
        [string]$EmailAddress,
        [object]$Config
    )

    try {
        $Headers = @{
            "hibp-api-key" = $Config.hibp.api_key
            "User-Agent" = "BusinessNetworkAuditor/1.0"
        }

        # URL encode the email address
        $EncodedEmail = [System.Web.HttpUtility]::UrlEncode($EmailAddress)
        $Uri = "$($Config.hibp.base_url)/breachedaccount/$EncodedEmail"

        # Add query parameters
        $QueryParams = @()
        $QueryParams += "truncateResponse=false"

        if ($Config.settings -and -not $Config.settings.include_unverified_breaches) {
            $QueryParams += "includeUnverified=false"
        } else {
            $QueryParams += "includeUnverified=false"
        }

        if ($QueryParams.Count -gt 0) {
            $Uri += "?" + ($QueryParams -join "&")
        }

        $RetryCount = 0
        $MaxRetries = if ($Config.hibp.max_retries) { $Config.hibp.max_retries } else { 3 }

        do {
            try {
                $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get -ErrorAction Stop

                return @{
                    Success = $true
                    Breaches = $Response
                    Error = $null
                }
            }
            catch {
                if ($_.Exception.Response.StatusCode -eq 429) {
                    # Rate limited
                    $RetryAfter = if ($_.Exception.Response.Headers["Retry-After"]) {
                        [int]$_.Exception.Response.Headers["Retry-After"] * 1000
                    } else {
                        if ($Config.hibp.rate_limit_delay_ms) {
                            $Config.hibp.rate_limit_delay_ms * 2
                        } else {
                            4000
                        }
                    }

                    Write-LogMessage "WARN" "Rate limited on $EmailAddress, waiting $($RetryAfter)ms before retry" "DARKWEB"
                    Start-Sleep -Milliseconds $RetryAfter
                    $RetryCount++
                }
                elseif ($_.Exception.Response.StatusCode -eq 404) {
                    # No breaches found (this is success)
                    return @{
                        Success = $true
                        Breaches = @()
                        Error = $null
                    }
                }
                else {
                    throw
                }
            }
        } while ($RetryCount -lt $MaxRetries)

        # Max retries exceeded
        return @{
            Success = $false
            Breaches = @()
            Error = "Rate limit exceeded after $MaxRetries retries"
        }
    }
    catch {
        return @{
            Success = $false
            Breaches = @()
            Error = "API call failed: $($_.Exception.Message)"
        }
    }
}

function Get-BreachRiskLevel {
    <#
    .SYNOPSIS
        Determines risk level based on breach date
    #>
    param(
        [string]$BreachDate,
        [int]$RecentThresholdDays = 365
    )

    try {
        $BreachDateTime = [DateTime]::Parse($BreachDate)
        $DaysSinceBreach = (Get-Date) - $BreachDateTime | Select-Object -ExpandProperty Days

        if ($DaysSinceBreach -le $RecentThresholdDays) {
            return "HIGH"
        }
        elseif ($DaysSinceBreach -le ($RecentThresholdDays * 2)) {
            return "MEDIUM"
        }
        else {
            return "LOW"
        }
    }
    catch {
        # If we can't parse the date, default to medium risk
        return "MEDIUM"
    }
}

function Import-EmailListFromFile {
    <#
    .SYNOPSIS
        Imports email addresses from a simple text file (one email per line, no header)
    #>
    param(
        [string]$FilePath
    )

    try {
        if (-not (Test-Path $FilePath)) {
            Write-LogMessage "ERROR" "Email list file not found: $FilePath" "DARKWEB"
            return @()
        }

        $EmailAddresses = @()
        $LineNumber = 0

        Get-Content $FilePath | ForEach-Object {
            $LineNumber++
            $Line = $_.Trim()

            # Skip empty lines
            if ([string]::IsNullOrWhiteSpace($Line)) {
                return
            }

            # Basic email validation
            if ($Line -match '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
                $EmailAddresses += $Line
            } else {
                Write-LogMessage "WARN" "Line $LineNumber is not a valid email address: $Line" "DARKWEB"
            }
        }

        Write-LogMessage "SUCCESS" "Loaded $($EmailAddresses.Count) email addresses from $FilePath" "DARKWEB"
        return $EmailAddresses
    }
    catch {
        Write-LogMessage "ERROR" "Failed to read email list: $($_.Exception.Message)" "DARKWEB"
        return @()
    }
}

function Get-DemoBreachData {
    <#
    .SYNOPSIS
        Generates simulated breach data for demo/testing purposes
    #>
    param(
        [string]$Domain
    )

    # Simulate some processing delay
    Start-Sleep -Milliseconds 500

    # Generate different demo scenarios based on domain name
    switch -Wildcard ($Domain.ToLower()) {
        "test.com" {
            # Clean domain - no breaches
            return @{
                Success = $true
                Breaches = @()
                Error = $null
            }
        }
        "example.com" {
            # Single recent breach
            return @{
                Success = $true
                Breaches = @(
                    @{
                        Name = "ExampleBreach"
                        BreachDate = (Get-Date).AddDays(-30).ToString("yyyy-MM-dd")
                        PwnCount = 15420
                        DataClasses = @("Email addresses", "Passwords", "Usernames")
                    }
                )
                Error = $null
            }
        }
        "demo.com" {
            # Multiple breaches with different ages
            return @{
                Success = $true
                Breaches = @(
                    @{
                        Name = "OldBreach2019"
                        BreachDate = "2019-03-15"
                        PwnCount = 250000
                        DataClasses = @("Email addresses", "Passwords")
                    },
                    @{
                        Name = "RecentBreach"
                        BreachDate = (Get-Date).AddDays(-45).ToString("yyyy-MM-dd")
                        PwnCount = 5200
                        DataClasses = @("Email addresses", "Names", "Phone numbers")
                    }
                )
                Error = $null
            }
        }
        default {
            # Random scenario for other domains
            $Random = Get-Random -Minimum 1 -Maximum 4

            if ($Random -eq 1) {
                # Clean domain
                return @{
                    Success = $true
                    Breaches = @()
                    Error = $null
                }
            } else {
                # Generate 1-2 random breaches
                $BreachCount = Get-Random -Minimum 1 -Maximum 3
                $Breaches = @()

                for ($i = 1; $i -le $BreachCount; $i++) {
                    $DaysAgo = Get-Random -Minimum 30 -Maximum 1200
                    $AccountCount = Get-Random -Minimum 1000 -Maximum 500000

                    $Breaches += @{
                        Name = "DemoBreach$i"
                        BreachDate = (Get-Date).AddDays(-$DaysAgo).ToString("yyyy-MM-dd")
                        PwnCount = $AccountCount
                        DataClasses = @("Email addresses", "Passwords", "Usernames")
                    }
                }

                return @{
                    Success = $true
                    Breaches = $Breaches
                    Error = $null
                }
            }
        }
    }
}

function Invoke-SubscriptionFreeCheck {
    <#
    .SYNOPSIS
        Calls public HIBP API endpoints that don't require authentication
    #>
    param(
        [string]$Domain,
        [object]$Config
    )

    try {
        # Get all subscription-free breaches
        $Uri = "$($Config.hibp.base_url)/breaches?includeUnverified=false"

        Write-LogMessage "INFO" "Fetching subscription-free breach data..." "DARKWEB"

        $RetryCount = 0
        $MaxRetries = 3

        do {
            try {
                $Response = Invoke-RestMethod -Uri $Uri -Method Get -ErrorAction Stop

                Write-LogMessage "INFO" "Retrieved $($Response.Count) total breaches from API" "DARKWEB"

                # Count subscription-free breaches for logging
                $SubscriptionFreeCount = ($Response | Where-Object { $_.IsSubscriptionFree }).Count
                Write-LogMessage "INFO" "Found $SubscriptionFreeCount subscription-free breaches" "DARKWEB"

                # Search all breaches for domain matches (even non-subscription-free)
                $SubscriptionFreeBreaches = @()
                $AllRelatedBreaches = @()
                $DomainKeyword = $Domain.Split('.')[0]  # Get company name part

                foreach ($Breach in $Response) {
                    # Check for domain matches in any breach
                    $IsMatch = $false

                    # Direct domain match
                    if ($Breach.Domain -eq $Domain) {
                        $IsMatch = $true
                        Write-LogMessage "INFO" "Direct domain match: $($Breach.Name)" "DARKWEB"
                    }
                    # Company name in breach name
                    elseif ($Breach.Name -like "*$DomainKeyword*") {
                        $IsMatch = $true
                        Write-LogMessage "INFO" "Name match: $($Breach.Name)" "DARKWEB"
                    }
                    # Company name in title
                    elseif ($Breach.Title -like "*$DomainKeyword*") {
                        $IsMatch = $true
                        Write-LogMessage "INFO" "Title match: $($Breach.Name)" "DARKWEB"
                    }
                    # Description contains domain
                    elseif ($Breach.Description -like "*$Domain*") {
                        $IsMatch = $true
                        Write-LogMessage "INFO" "Description match: $($Breach.Name)" "DARKWEB"
                    }

                    if ($IsMatch) {
                        $AllRelatedBreaches += $Breach
                        if ($Breach.IsSubscriptionFree) {
                            $SubscriptionFreeBreaches += $Breach
                        }
                    }
                }

                Write-LogMessage "INFO" "Found $($AllRelatedBreaches.Count) total related breaches ($($SubscriptionFreeBreaches.Count) subscription-free) for $Domain" "DARKWEB"

                # Return subscription-free breaches with full detail, and limited info for others
                $RelevantBreaches = $SubscriptionFreeBreaches
                $LimitedBreaches = $AllRelatedBreaches | Where-Object { -not $_.IsSubscriptionFree }

                return @{
                    Success = $true
                    Breaches = $RelevantBreaches
                    LimitedBreaches = $LimitedBreaches
                    Error = $null
                    Note = "Subscription-free data - limited to public breaches only"
                }
            }
            catch {
                if ($_.Exception.Response.StatusCode -eq 429) {
                    # Rate limited
                    $RetryAfter = 2000  # Default 2 second delay for public endpoint
                    Write-LogMessage "WARN" "Rate limited, waiting $($RetryAfter)ms before retry" "DARKWEB"
                    Start-Sleep -Milliseconds $RetryAfter
                    $RetryCount++
                }
                else {
                    throw
                }
            }
        } while ($RetryCount -lt $MaxRetries)

        # Max retries exceeded
        return @{
            Success = $false
            Breaches = @()
            Error = "Rate limit exceeded after $MaxRetries retries"
        }
    }
    catch {
        # If subscription-free fails, provide helpful message
        return @{
            Success = $true
            Breaches = @()
            Error = $null
            Note = "Unable to fetch subscription-free data: $($_.Exception.Message)"
        }
    }
}