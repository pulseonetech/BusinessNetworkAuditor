# WindowsWorkstationAuditor - User Account Analysis Module
# Version 1.3.0

function Get-UserAccountAnalysis {
    <#
    .SYNOPSIS
        Analyzes user accounts and administrative privileges with Azure AD support
        
    .DESCRIPTION
        Performs comprehensive analysis of local and Azure AD user accounts including:
        - Local administrator account enumeration
        - Current user privilege assessment
        - Guest account status verification
        - Azure AD joined system detection
        - Administrative privilege distribution analysis
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local admin rights recommended for complete analysis
        Supports: Traditional domain, Azure AD joined, and workgroup systems
    #>
    
    Write-LogMessage "INFO" "Analyzing user accounts..." "USERS"
    
    try {
        $LocalAdmins = @()
        
        # Determine execution context
        $CurrentUser = if ($env:USERNAME -eq "SYSTEM") { "SYSTEM" } else { $env:USERNAME }
        Write-LogMessage "INFO" "Current user: $CurrentUser" "USERS"
        
        # Check if current user is admin
        $IsCurrentUserAdmin = $false
        try {
            $CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)
            $IsCurrentUserAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            Write-LogMessage "INFO" "Current user is admin: $IsCurrentUserAdmin" "USERS"
        }
        catch {
            Write-LogMessage "WARN" "Could not check current user admin status: $($_.Exception.Message)" "USERS"
        }
        
        # Detect if we're on a Domain Controller
        $IsDomainController = $false
        try {
            $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            $IsDomainController = $OSInfo.ProductType -eq 2  # ProductType: 1=Workstation, 2=DC, 3=Server
            Write-LogMessage "INFO" "Domain Controller detected: $IsDomainController" "USERS"
        }
        catch {
            Write-LogMessage "WARN" "Could not determine system type for DC detection" "USERS"
        }
        
        # Use different methods based on whether we're on a Domain Controller
        if ($IsDomainController) {
            Write-LogMessage "INFO" "Using Active Directory methods for Domain Controller..." "USERS"
            try {
                # Try to import AD module
                Import-Module ActiveDirectory -ErrorAction SilentlyContinue
                
                # Get Domain Admins and Enterprise Admins
                $DomainAdmins = @()
                $EnterpriseAdmins = @()
                
                try {
                    $DomainAdmins = Get-ADGroupMember "Domain Admins" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
                } catch {
                    Write-LogMessage "WARN" "Could not get Domain Admins: $($_.Exception.Message)" "USERS"
                }
                
                try {
                    $EnterpriseAdmins = Get-ADGroupMember "Enterprise Admins" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
                } catch {
                    Write-LogMessage "WARN" "Could not get Enterprise Admins: $($_.Exception.Message)" "USERS"
                }
                
                # Combine and deduplicate
                $LocalAdmins = @($DomainAdmins) + @($EnterpriseAdmins) | Sort-Object -Unique | Where-Object { $_ -ne $null }
                Write-LogMessage "INFO" "Found $($DomainAdmins.Count) Domain Admins, $($EnterpriseAdmins.Count) Enterprise Admins" "USERS"
            }
            catch {
                Write-LogMessage "WARN" "AD module not available, falling back to local group detection: $($_.Exception.Message)" "USERS"
                $IsDomainController = $false  # Fall back to local methods
            }
        }
        
        # Use local methods for non-DCs or if AD methods failed
        if (-not $IsDomainController -or $LocalAdmins.Count -eq 0) {
            Write-LogMessage "INFO" "Using local group detection methods..." "USERS"
        
        # Method 1: Try Get-LocalGroupMember (best for Azure AD)
        try {
            Write-LogMessage "INFO" "Attempting Get-LocalGroupMember..." "USERS"
            $AdminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
            Write-LogMessage "INFO" "Get-LocalGroupMember returned $($AdminMembers.Count) members" "USERS"
            
            $LocalAdmins = foreach ($Member in $AdminMembers) {
                Write-LogMessage "INFO" "Processing member: Name='$($Member.Name)', ObjectClass='$($Member.ObjectClass)'" "USERS"
                
                # Extract just the username part
                if ($Member.Name -match "\\") {
                    $Username = $Member.Name.Split('\')[-1]
                } else {
                    $Username = $Member.Name
                }
                Write-LogMessage "INFO" "Extracted username: '$Username'" "USERS"
                $Username
            }
        }
        catch {
            Write-LogMessage "WARN" "Get-LocalGroupMember failed: $($_.Exception.Message)" "USERS"
        }
        
        # Method 2: Fallback to net localgroup
        if ($LocalAdmins.Count -eq 0) {
            try {
                Write-LogMessage "INFO" "Fallback: Using net localgroup Administrators" "USERS"
                $NetOutput = & net localgroup Administrators 2>&1
                Write-LogMessage "INFO" "Net command output has $($NetOutput.Count) lines" "USERS"
                
                if ($LASTEXITCODE -eq 0) {
                    $InMembersList = $false
                    $LocalAdmins = foreach ($Line in $NetOutput) {
                        # Look for the separator line
                        if ($Line -match "^-+$") {
                            $InMembersList = $true
                            continue
                        }
                        
                        # Process member lines
                        if ($InMembersList -and $Line.Trim() -ne "" -and $Line -notmatch "The command completed successfully") {
                            $CleanName = $Line.Trim()
                            # Handle AzureAD\ prefix
                            if ($CleanName -match "^AzureAD\\(.+)$") {
                                $CleanName = $matches[1]
                            }
                            Write-LogMessage "INFO" "Found admin: '$CleanName'" "USERS"
                            $CleanName
                        }
                    }
                }
            }
            catch {
                Write-LogMessage "ERROR" "Net localgroup method failed: $($_.Exception.Message)" "USERS"
            }
        }
        
            # Method 3: If still no admins but current user is admin, add them
            if ($LocalAdmins.Count -eq 0 -and $IsCurrentUserAdmin) {
                Write-LogMessage "INFO" "Adding current user as admin since detection failed" "USERS"
                $LocalAdmins = @($env:USERNAME)
            }
        }
        
        $Results = @()
        
        # Local Administrator Count (always add this result)
        $AdminCount = $LocalAdmins.Count
        Write-LogMessage "SUCCESS" "Administrator count: $AdminCount" "USERS"
        $Results += [PSCustomObject]@{
            Category = "Users"
            Item = "Local Administrators"
            Value = $AdminCount
            Details = "Users: $($LocalAdmins -join ', ')"
            RiskLevel = if ($AdminCount -gt 3) { "HIGH" } elseif ($AdminCount -gt 1) { "MEDIUM" } else { "LOW" }
            Recommendation = if ($AdminCount -gt 3) { "Limit administrative access" } else { "" }
        }
        
        # Account Security Analysis (different for DCs vs regular systems)
        if ($IsDomainController) {
            # For Domain Controllers: Check for disabled domain accounts
            try {
                if (Get-Module -Name ActiveDirectory -ListAvailable) {
                    $DisabledUsers = Get-ADUser -Filter {Enabled -eq $false} -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count
                    $Results += [PSCustomObject]@{
                        Category = "Users"
                        Item = "Disabled Domain Accounts"
                        Value = $DisabledUsers
                        Details = "Disabled user accounts in Active Directory"
                        RiskLevel = if ($DisabledUsers -gt 10) { "MEDIUM" } else { "LOW" }
                        Recommendation = if ($DisabledUsers -gt 10) { "Review and clean up disabled accounts" } else { "" }
                    }
                    Write-LogMessage "INFO" "Found $DisabledUsers disabled domain accounts" "USERS"
                } else {
                    Write-LogMessage "INFO" "Active Directory module not available for disabled account analysis" "USERS"
                }
            }
            catch {
                Write-LogMessage "WARN" "Could not check disabled domain accounts: $($_.Exception.Message)" "USERS"
            }
        } else {
            # For regular systems: Check Guest Account Status (only report if enabled)
            try {
                $LocalUsers = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue
                if ($LocalUsers) {
                    $GuestAccount = $LocalUsers | Where-Object { $_.Name -eq "Guest" }
                    if ($GuestAccount) {
                        # Guest Account disabled is baseline - only report if enabled
                        if (-not $GuestAccount.Disabled) {
                            $Results += [PSCustomObject]@{
                                Category = "Users"
                                Item = "Guest Account"
                                Value = "Enabled"
                                Details = "Guest account is enabled"
                                RiskLevel = "HIGH"
                                Recommendation = "Disable guest account"
                            }
                            Write-LogMessage "WARN" "Guest account is enabled" "USERS"
                        } else {
                            Write-LogMessage "INFO" "Guest account is disabled (baseline)" "USERS"
                        }
                    } else {
                        Write-LogMessage "INFO" "No Guest account found in local users" "USERS"
                    }
                } else {
                    Write-LogMessage "WARN" "Unable to enumerate local users" "USERS"
                }
            }
            catch {
                Write-LogMessage "WARN" "Could not check local users for Guest account: $($_.Exception.Message)" "USERS"
            }
        }
        
        Write-LogMessage "SUCCESS" "User account analysis completed - Found $AdminCount administrators" "USERS"
        Write-LogMessage "INFO" "Returning $($Results.Count) user account results" "USERS"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze user accounts: $($_.Exception.Message)" "USERS"
        return @()
    }
}