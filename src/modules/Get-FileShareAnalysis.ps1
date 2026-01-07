# WindowsServerAuditor - File Share Analysis Module
# Version 1.3.0

function Get-FileShareAnalysis {
    <#
    .SYNOPSIS
        Analyzes file shares and permissions (read-only discovery)
        
    .DESCRIPTION
        Performs file share discovery and analysis including:
        - SMB/CIFS share enumeration
        - Share permissions and access controls
        - Hidden and administrative shares
        - Share usage patterns and security risks
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Version: 1.3.0
        Dependencies: Write-LogMessage, Add-RawDataCollection
        Permissions: Local Admin recommended for complete share analysis
        Safety: READ-ONLY - No share modifications or access changes made
    #>
    
    Write-LogMessage "INFO" "Analyzing file shares..." "FILESHARE"
    
    try {
        $Results = @()
        
        # Check if File Services role is installed
        try {
            $FileServicesFeature = Get-WindowsFeature -Name "File-Services" -ErrorAction SilentlyContinue
            $FileServerFeature = Get-WindowsFeature -Name "FS-FileServer" -ErrorAction SilentlyContinue
            
            $HasFileServices = ($FileServicesFeature -and $FileServicesFeature.InstallState -eq "Installed") -or 
                             ($FileServerFeature -and $FileServerFeature.InstallState -eq "Installed")
            
            if (-not $HasFileServices) {
                Write-LogMessage "INFO" "File Services role not installed - basic share analysis only" "FILESHARE"
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to check File Services feature: $($_.Exception.Message)" "FILESHARE"
        }
        
        # Get SMB shares using Get-SmbShare (read-only)
        Write-LogMessage "INFO" "Enumerating SMB shares..." "FILESHARE"
        
        try {
            $SMBShares = Get-SmbShare -ErrorAction SilentlyContinue
            
            if ($SMBShares) {
                $ShareData = @()
                
                # Categorize shares
                $UserShares = $SMBShares | Where-Object { $_.Name -notlike "*$" -and $_.ShareType -eq "FileSystemDirectory" }
                $AdminShares = $SMBShares | Where-Object { $_.Name -like "*$" }
                $SpecialShares = $SMBShares | Where-Object { $_.ShareType -ne "FileSystemDirectory" }
                
                $Results += [PSCustomObject]@{
                    Category = "File Shares"
                    Item = "Share Summary"
                    Value = "$($SMBShares.Count) total shares"
                    Details = "User shares: $($UserShares.Count), Admin shares: $($AdminShares.Count), Special: $($SpecialShares.Count)"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                # Analyze each user share
                foreach ($Share in $UserShares) {
                    Write-LogMessage "INFO" "Analyzing share: $($Share.Name)" "FILESHARE"
                    
                    try {
                        # Get share path and description
                        $SharePath = $Share.Path
                        $ShareDescription = if ($Share.Description) { $Share.Description } else { "No description" }
                        
                        # Determine share risk level based on name and characteristics
                        $ShareRisk = switch -Regex ($Share.Name) {
                            "^(NETLOGON|SYSVOL)$" { "LOW" }  # Domain Controller administrative shares
                            "^(Users?|Home|Profiles?)$" { "LOW" }
                            "^(Public|Everyone|Guest|Temp)$" { "HIGH" }
                            "^(Data|Shared?|Common)$" { "MEDIUM" }
                            "^(Backup|Archive)$" { "MEDIUM" }
                            default { "MEDIUM" }
                        }
                        
                        # Check if share allows anonymous access (basic check)
                        $AnonymousAccess = "Unknown"
                        try {
                            $ShareAccess = Get-SmbShareAccess -Name $Share.Name -ErrorAction SilentlyContinue
                            $EveryoneAccess = $ShareAccess | Where-Object { $_.AccountName -eq "Everyone" }
                            $AnonymousAccess = if ($EveryoneAccess) { "Possible" } else { "Restricted" }
                            
                            # Increase risk if Everyone has access (except for DC shares which require it)
                            $IsDCShare = $Share.Name -match "^(NETLOGON|SYSVOL)$"
                            if ($EveryoneAccess -and -not $IsDCShare) {
                                $ShareRisk = "HIGH"
                            }
                        }
                        catch {
                            Write-LogMessage "WARN" "Unable to check access for share $($Share.Name): $($_.Exception.Message)" "FILESHARE"
                        }
                        
                        $Results += [PSCustomObject]@{
                            Category = "File Shares"
                            Item = "File Share"
                            Value = "$($Share.Name) ($SharePath)"
                            Details = "Description: $ShareDescription, Anonymous access: $AnonymousAccess"
                            RiskLevel = $ShareRisk
                            Recommendation = if ($ShareRisk -eq "HIGH") { "Review share permissions and restrict access" } else { "" }
                        }
                        
                        # Get detailed share access permissions (read-only)
                        try {
                            $ShareAccessList = Get-SmbShareAccess -Name $Share.Name -ErrorAction SilentlyContinue
                            $AccessSummary = @()
                            
                            if ($ShareAccessList) {
                                foreach ($Access in $ShareAccessList) {
                                    $AccessSummary += "$($Access.AccountName):$($Access.AccessRight)"
                                }
                                
                                # Check for risky permissions (exclude Domain Controller administrative shares)
                                $IsDomainControllerShare = $Share.Name -in @("NETLOGON", "SYSVOL")
                                
                                if (-not $IsDomainControllerShare) {
                                    $RiskyAccounts = $ShareAccessList | Where-Object { 
                                        $_.AccountName -in @("Everyone", "Guest", "Anonymous Logon", "Users") -and 
                                        $_.AccessRight -in @("Full", "Change")
                                    }
                                    
                                    if ($RiskyAccounts) {
                                        $Results += [PSCustomObject]@{
                                            Category = "File Shares"
                                            Item = "Share Permission Risk"
                                            Value = "$($Share.Name) - Excessive permissions"
                                            Details = "Risky permissions found: $($RiskyAccounts.AccountName -join ', ') with $($RiskyAccounts.AccessRight -join ', ') access"
                                            RiskLevel = "HIGH"
                                            Recommendation = "Restrict share permissions to specific users or groups"
                                        }
                                    }
                                } else {
                                    # Domain Controller shares - validate they have proper Everyone access
                                    $EveryoneAccess = $ShareAccessList | Where-Object { $_.AccountName -eq "Everyone" }
                                    if ($EveryoneAccess) {
                                        $Results += [PSCustomObject]@{
                                            Category = "File Shares"
                                            Item = "DC Share Configuration"
                                            Value = "$($Share.Name) - Everyone access configured"
                                            Details = "Domain Controller share with required Everyone access for domain functionality"
                                            RiskLevel = "LOW"
                                            Recommendation = ""
                                        }
                                    } else {
                                        $Results += [PSCustomObject]@{
                                            Category = "File Shares"
                                            Item = "DC Share Configuration"
                                            Value = "$($Share.Name) - Missing Everyone access"
                                            Details = "Domain Controller share may be missing required Everyone access for proper domain functionality"
                                            RiskLevel = "HIGH"
                                            Recommendation = "Verify NETLOGON/SYSVOL shares have appropriate Everyone read access"
                                        }
                                    }
                                }
                            }
                            
                            # Store share data for raw export
                            $ShareData += @{
                                Name = $Share.Name
                                Path = $Share.Path
                                Description = $Share.Description
                                ShareType = $Share.ShareType
                                CurrentUsers = $Share.CurrentUsers
                                CachingMode = $Share.CachingMode
                                EncryptData = $Share.EncryptData
                                FolderEnumerationMode = $Share.FolderEnumerationMode
                                Permissions = $AccessSummary
                                RiskLevel = $ShareRisk
                            }
                        }
                        catch {
                            Write-LogMessage "WARN" "Unable to get detailed permissions for share $($Share.Name): $($_.Exception.Message)" "FILESHARE"
                        }
                    }
                    catch {
                        Write-LogMessage "WARN" "Error analyzing share $($Share.Name): $($_.Exception.Message)" "FILESHARE"
                    }
                }
                
                # Check administrative shares
                foreach ($AdminShare in $AdminShares) {
                    $Results += [PSCustomObject]@{
                        Category = "File Shares"
                        Item = "Administrative Share"
                        Value = "$($AdminShare.Name) ($($AdminShare.Path))"
                        Details = "Default administrative share for remote management"
                        RiskLevel = "LOW"
                        Recommendation = ""
                    }
                }
                
                # Add share data to raw collection
                if ($ShareData.Count -gt 0) {
                    Add-RawDataCollection -CollectionName "FileShares" -Data $ShareData
                }
                
            } else {
                $Results += [PSCustomObject]@{
                    Category = "File Shares"
                    Item = "SMB Shares"
                    Value = "No shares found"
                    Details = "No SMB/CIFS shares are currently configured"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
            }
        }
        catch {
            Write-LogMessage "ERROR" "Failed to enumerate SMB shares: $($_.Exception.Message)" "FILESHARE"
            $Results += [PSCustomObject]@{
                Category = "File Shares"
                Item = "Share Enumeration Error"
                Value = "Failed"
                Details = "Unable to retrieve SMB share information: $($_.Exception.Message)"
                RiskLevel = "ERROR"
                Recommendation = "Investigate file sharing service status"
            }
        }
        
        # Check SMB server settings (read-only)
        try {
            Write-LogMessage "INFO" "Checking SMB server configuration..." "FILESHARE"
            
            $SMBServerConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
            
            if ($SMBServerConfig) {
                # Check SMB version support
                $SMBVersions = @()
                if ($SMBServerConfig.EnableSMB1Protocol) { $SMBVersions += "SMBv1" }
                if ($SMBServerConfig.EnableSMB2Protocol) { $SMBVersions += "SMBv2/3" }
                
                $SMBVersionString = $SMBVersions -join ", "
                
                # SMB1 is a security risk
                $SMBRisk = if ($SMBServerConfig.EnableSMB1Protocol) { "HIGH" } else { "LOW" }
                
                $Results += [PSCustomObject]@{
                    Category = "File Shares"
                    Item = "SMB Protocol Support"
                    Value = $SMBVersionString
                    Details = "SMB signing required: $($SMBServerConfig.RequireSecuritySignature), Encryption supported: $($SMBServerConfig.EncryptData)"
                    RiskLevel = $SMBRisk
                    Recommendation = if ($SMBServerConfig.EnableSMB1Protocol) { "Disable SMBv1 protocol - significant security vulnerability" } else { "SMB configuration is secure" }
                }
                
                # Check SMB signing
                if (-not $SMBServerConfig.RequireSecuritySignature) {
                    $Results += [PSCustomObject]@{
                        Category = "File Shares"
                        Item = "SMB Security Signing"
                        Value = "Not Required"
                        Details = "SMB signing helps prevent man-in-the-middle attacks"
                        RiskLevel = "MEDIUM"
                        Recommendation = "Consider enabling SMB security signing"
                    }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to check SMB server configuration: $($_.Exception.Message)" "FILESHARE"
        }
        
        # Check Windows file sharing service status (read-only)
        try {
            $LanmanServer = Get-Service -Name "LanmanServer" -ErrorAction SilentlyContinue
            
            if ($LanmanServer) {
                $Results += [PSCustomObject]@{
                    Category = "File Shares"
                    Item = "File Sharing Service"
                    Value = "$($LanmanServer.Status) ($($LanmanServer.StartType))"
                    Details = "Server service (LanmanServer) enables file and print sharing"
                    RiskLevel = if ($LanmanServer.Status -eq "Running") { "INFO" } else { "MEDIUM" }
                    Recommendation = ""
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to check file sharing service: $($_.Exception.Message)" "FILESHARE"
        }
        
        Write-LogMessage "SUCCESS" "File share analysis completed" "FILESHARE"
        return $Results
        
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze file shares: $($_.Exception.Message)" "FILESHARE"
        return @([PSCustomObject]@{
            Category = "File Shares"
            Item = "Analysis Error"
            Value = "Failed"
            Details = "Error during file share analysis: $($_.Exception.Message)"
            RiskLevel = "ERROR"
            Recommendation = "Investigate file share analysis failure"
        })
    }
}