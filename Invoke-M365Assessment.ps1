#Requires -Version 5.1
<#
.SYNOPSIS
    PulseOne M365 Security Assessment Tool

.DESCRIPTION
    Production-ready M365 security assessment tool.
    Generates standalone JSON and HTML reports compatible with BusinessNetworkAuditor.

.PARAMETER ConfigPath
    Path to configuration file. Defaults to .\config\m365-assessment-config.json

.PARAMETER SkipConfigPrompt
    Skip configuration prompts if config is missing

.EXAMPLE
    .\Invoke-M365Assessment.ps1

.EXAMPLE
    .\Invoke-M365Assessment.ps1 -ConfigPath "C:\custom\config.json"
#>

[CmdletBinding()]
param(
    [string]$ConfigPath = ".\config\m365-assessment-config.json",
    [switch]$SkipConfigPrompt
)

#region Configuration and Initialization

$Script:Version = "1.0.0"
$Script:StartTime = Get-Date
$Script:ProjectRoot = $PSScriptRoot
$Script:Config = $null
$Script:LogFile = $null
$Script:Results = @{
    Scuba = @{ Success = $false; Path = $null; Count = 0 }
    Maester = @{ Success = $false; Path = $null; Count = 0; SkippedCount = 0 }
    Consolidated = @{ Path = $null; Count = 0 }
}

#endregion

#region Logging Functions

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level,
        
        [Parameter(Mandatory)]
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "WARN"    { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        "INFO"    { Write-Host $logEntry -ForegroundColor Cyan }
    }
    
    if ($Script:LogFile) {
        Add-Content -Path $Script:LogFile -Value $logEntry -ErrorAction SilentlyContinue
    }
}

function Initialize-Logging {
    $logDir = Join-Path $Script:ProjectRoot "output"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Script:LogFile = Join-Path $logDir "M365_Assessment_$timestamp.log"
    
    Write-Log -Level "INFO" -Message "PulseOne M365 Assessment Tool v$Script:Version"
    Write-Log -Level "INFO" -Message "Log file: $($Script:LogFile)"
}

#endregion

#region Configuration Management

function Import-Configuration {
    param([string]$Path)
    
    Write-Log -Level "INFO" -Message "Loading configuration from: $Path"
    
    if (-not (Test-Path $Path)) {
        Write-Log -Level "WARN" -Message "Configuration file not found"
        return $null
    }
    
    try {
        $config = Get-Content $Path -Raw | ConvertFrom-Json
        Write-Log -Level "SUCCESS" -Message "Configuration loaded successfully"
        return $config
    }
    catch {
        Write-Log -Level "ERROR" -Message "Failed to parse configuration file: $($_.Exception.Message)"
        return $null
    }
}

function Test-ConfigurationComplete {
    param($Config)
    
    if (-not $Config) { return $false }
    if ([string]::IsNullOrWhiteSpace($Config.organization.tenantId)) { return $false }
    if ([string]::IsNullOrWhiteSpace($Config.organization.name)) { return $false }
    if ([string]::IsNullOrWhiteSpace($Config.authentication.mode)) { return $false }
    
    if ($Config.authentication.mode -eq "servicePrincipal") {
        if ([string]::IsNullOrWhiteSpace($Config.authentication.servicePrincipal.appId)) { return $false }
        if ([string]::IsNullOrWhiteSpace($Config.authentication.servicePrincipal.certificateThumbprint)) { return $false }
    }
    
    return $true
}

function New-ServicePrincipalCertificate {
    <#
    .SYNOPSIS
        Creates a self-signed certificate for Service Principal authentication
    #>
    param(
        [string]$CertName = "PulseOneM365Assessment",
        [int]$ValidityYears = 2
    )
    
    Write-Host "`nCreating Self-Signed Certificate..." -ForegroundColor Cyan
    Write-Host "------------------------------------" -ForegroundColor Gray
    
    try {
        # Check if running as admin
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if (-not $isAdmin) {
            Write-Host "WARNING: Not running as Administrator. Certificate will be created in CurrentUser store." -ForegroundColor Yellow
            Write-Host "This is fine for most use cases." -ForegroundColor Gray
        }
        
        # Create certificate in CurrentUser store
        $certParams = @{
            Subject = "CN=$CertName"
            CertStoreLocation = "Cert:\CurrentUser\My"
            KeyExportPolicy = "Exportable"
            KeySpec = "Signature"
            NotAfter = (Get-Date).AddYears($ValidityYears)
        }
        
        $cert = New-SelfSignedCertificate @certParams
        
        Write-Host "Certificate created successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Certificate Details:" -ForegroundColor Yellow
        Write-Host "  Subject:     $($cert.Subject)" -ForegroundColor White
        Write-Host "  Thumbprint:  $($cert.Thumbprint)" -ForegroundColor Green
        Write-Host "  Valid From:  $($cert.NotBefore)" -ForegroundColor White
        Write-Host "  Valid Until: $($cert.NotAfter)" -ForegroundColor White
        Write-Host "  Location:    Cert:\CurrentUser\My" -ForegroundColor White
        Write-Host ""
        
        # Export to temp directory for upload
        $exportPath = Join-Path $env:TEMP "$CertName.cer"
        Export-Certificate -Cert $cert -FilePath $exportPath | Out-Null
        
        Write-Host "Certificate exported to: $exportPath" -ForegroundColor Green
        Write-Host "Upload this file to your Azure AD App Registration." -ForegroundColor Yellow
        Write-Host ""
        
        return $cert.Thumbprint
    }
    catch {
        Write-Host "ERROR: Failed to create certificate: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "You can create one manually using:" -ForegroundColor Yellow
        Write-Host '  New-SelfSignedCertificate -Subject "CN=PulseOneM365Assessment" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable' -ForegroundColor Green
        return $null
    }
}

function Invoke-ConfigurationWizard {
    Write-Host "`n===============================================" -ForegroundColor Cyan
    Write-Host "    M365 Assessment Configuration Setup" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    
    $config = @{
        organization = @{
            name = "PulseOne"
            tenantId = ""
            environment = "commercial"
        }
        authentication = @{
            mode = ""
            servicePrincipal = @{
                appId = ""
                certificateThumbprint = ""
                organization = ""
            }
        }
        assessment = @{
            runScuba = $true
            runMaester = $true
            products = @("aad", "exo", "defender", "sharepoint", "teams", "powerplatform")
        }
        output = @{
            path = "./output"
            formats = @("json", "html")
            retentionDays = 90
        }
    }
    
        Write-Host "Organization Configuration" -ForegroundColor Yellow
        Write-Host "--------------------------"
        Write-Host "This is the DISPLAY NAME for reports" -ForegroundColor Gray
        $orgName = Read-Host "Enter organization display name [PulseOne]"
        if (-not [string]::IsNullOrWhiteSpace($orgName)) {
            $config.organization.name = $orgName
        }
    
    Write-Host "`nYour Tenant ID is a GUID found in Azure AD > Properties." -ForegroundColor Gray
    Write-Host "Example: 12345678-1234-1234-1234-123456789012" -ForegroundColor Gray
    do {
        $tenantId = Read-Host "Enter your Microsoft 365 Tenant ID"
        if ($tenantId -match "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$") {
            $config.organization.tenantId = $tenantId
            break
        }
        Write-Host "Invalid Tenant ID format. Please enter a valid GUID." -ForegroundColor Red
    } while ($true)
    
    Write-Host "`nEnvironment Selection" -ForegroundColor Yellow
    Write-Host "----------------------"
    Write-Host "[1] Commercial (Default - Most common)"
    Write-Host "[2] GCC (Government Community Cloud)"
    Write-Host "[3] GCC High"
    Write-Host "[4] DoD"
    $envChoice = Read-Host "Select environment [1]"
    
    switch ($envChoice) {
        "2" { $config.organization.environment = "gcc" }
        "3" { $config.organization.environment = "gcchigh" }
        "4" { $config.organization.environment = "dod" }
        default { $config.organization.environment = "commercial" }
    }
    
    Write-Host "`nAuthentication Method" -ForegroundColor Yellow
    Write-Host "---------------------"
    Write-Host "Select how you want to authenticate to Microsoft 365:" -ForegroundColor White
    Write-Host ""
    Write-Host "[1] INTERACTIVE (Recommended for first-time use)"
    Write-Host "    - You will be prompted to sign in multiple times"
    Write-Host "    - Requires manual MFA approval for each service"
    Write-Host "    - Easiest to set up, no additional configuration"
    Write-Host ""
    Write-Host "[2] SERVICE PRINCIPAL (Recommended for automation)"
    Write-Host "    - No prompts, fully automated, all products supported"
    Write-Host "    - Requires one-time App Registration + certificate setup"
    Write-Host ""
    
    $authChoice = Read-Host "Select authentication method [1-2]"
    
    if ($authChoice -eq "2") {
        $config.authentication.mode = "servicePrincipal"
        
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  Service Principal Setup Guide" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host ""
        
        # FIRST: Ask if they want auto-generate or manual
        Write-Host "Create certificate automatically?" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "[Y] YES - Automatic (Recommended)" -ForegroundColor Green
        Write-Host "    - Certificate generated by the script" -ForegroundColor Gray
        Write-Host "    - Exported and ready for Azure AD upload" -ForegroundColor Gray
        Write-Host "    - Fastest setup option" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[N] NO - Manual" -ForegroundColor White
        Write-Host "    - Detailed instructions with commands provided" -ForegroundColor Gray
        Write-Host "    - Full control over certificate configuration" -ForegroundColor Gray
        Write-Host ""
        $createCert = Read-Host "Create certificate automatically [Y/N]"
        
        $certThumbprint = $null
        
        if ($createCert -eq "Y" -or $createCert -eq "y") {
            # AUTO MODE: Create certificate and show minimal info
            $certThumbprint = New-ServicePrincipalCertificate
            
            if ($certThumbprint) {
                Write-Host "`n========================================" -ForegroundColor Green
                Write-Host "  Certificate Created Successfully!" -ForegroundColor Green
                Write-Host "========================================" -ForegroundColor Green
                Write-Host ""
                Write-Host "Next: Complete Azure AD Setup" -ForegroundColor Cyan
                Write-Host "------------------------------" -ForegroundColor Gray
                Write-Host "1. Go to https://portal.azure.com" -ForegroundColor White
                Write-Host "2. Navigate to: Azure Active Directory > App registrations" -ForegroundColor White
                Write-Host "3. Click 'New registration'" -ForegroundColor White
                Write-Host "4. Name: 'PulseOne M365 Assessment'" -ForegroundColor White
                Write-Host "5. Supported account types: Keep default (Single tenant)" -ForegroundColor Gray
                Write-Host "6. Redirect URI: Leave blank (none)" -ForegroundColor Gray
                Write-Host "7. Click 'Register'" -ForegroundColor White
                Write-Host ""
                Write-Host "8. In your app registration, click 'Certificates & secrets'" -ForegroundColor White
                Write-Host "9. Click 'Upload certificate'" -ForegroundColor White
                Write-Host "10. Upload: $env:TEMP\PulseOneM365Assessment.cer" -ForegroundColor Yellow
                Write-Host "11. Click 'Add'" -ForegroundColor White
                Write-Host ""
                Write-Host "12. Click 'API permissions' and add the following:" -ForegroundColor White
                Write-Host ""
                Write-Host "  Microsoft Graph > Application permissions:" -ForegroundColor Yellow
                Write-Host "    - DeviceManagementConfiguration.Read.All" -ForegroundColor Gray
                Write-Host "    - DeviceManagementManagedDevices.Read.All" -ForegroundColor Gray
                Write-Host "    - DeviceManagementRBAC.Read.All" -ForegroundColor Gray
                Write-Host "    - Directory.Read.All" -ForegroundColor Gray
                Write-Host "    - DirectoryRecommendations.Read.All" -ForegroundColor Gray
                Write-Host "    - IdentityRiskEvent.Read.All" -ForegroundColor Gray
                Write-Host "    - OnPremDirectorySynchronization.Read.All" -ForegroundColor Gray
                Write-Host "    - Policy.Read.All" -ForegroundColor Gray
                Write-Host "    - Policy.Read.ConditionalAccess" -ForegroundColor Gray
                Write-Host "    - PrivilegedAccess.Read.AzureAD" -ForegroundColor Gray
                Write-Host "    - PrivilegedAccess.Read.AzureADGroup" -ForegroundColor Gray
                Write-Host "    - PrivilegedEligibilitySchedule.Read.AzureADGroup" -ForegroundColor Gray
                Write-Host "    - Reports.Read.All" -ForegroundColor Gray
                Write-Host "    - ReportSettings.Read.All" -ForegroundColor Gray
                Write-Host "    - RoleEligibilitySchedule.Read.Directory" -ForegroundColor Gray
                Write-Host "    - RoleManagement.Read.All" -ForegroundColor Gray
                Write-Host "    - RoleManagement.Read.Directory" -ForegroundColor Gray
                Write-Host "    - RoleManagementPolicy.Read.AzureADGroup" -ForegroundColor Gray
                Write-Host "    - SecurityIdentitiesHealth.Read.All" -ForegroundColor Gray
                Write-Host "    - SecurityIdentitiesSensors.Read.All" -ForegroundColor Gray
                Write-Host "    - SharePointTenantSettings.Read.All" -ForegroundColor Gray
                Write-Host "    - ThreatHunting.Read.All" -ForegroundColor Gray
                Write-Host "    - User.Read.All" -ForegroundColor Gray
                Write-Host "    - UserAuthenticationMethod.Read.All" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  Optional (enables PIM eligibility and report settings tests):" -ForegroundColor Yellow
                Write-Host "    - RoleEligibilitySchedule.ReadWrite.Directory" -ForegroundColor Gray
                Write-Host "    - ReportSettings.ReadWrite.All" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  Office 365 Exchange Online > Application permissions:" -ForegroundColor Yellow
                Write-Host "    - Exchange.ManageAsApp" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  SharePoint > Application permissions:" -ForegroundColor Yellow
                Write-Host "    - Sites.FullControl.All" -ForegroundColor Gray
                Write-Host ""
                Write-Host "13. Click 'Grant admin consent'" -ForegroundColor White
                Write-Host ""
                Write-Host "ASSIGN ROLES:" -ForegroundColor Red
                Write-Host "  Assign BOTH of these roles to your app:" -ForegroundColor White
                Write-Host "    - Global Reader" -ForegroundColor Gray
                Write-Host "    - Teams Administrator" -ForegroundColor Gray
                Write-Host "  Azure AD > Roles and administrators > [Role] > Add assignments" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  NOTE: If your app has Global Admin, these are already included." -ForegroundColor DarkGray
                Write-Host ""
                Read-Host "Press Enter when you've completed the Azure AD setup"
            }
            else {
                Write-Host "`nCertificate creation failed. Please create it manually:" -ForegroundColor Red
                $createCert = "N"  # Fall through to manual instructions
            }
        }
        
        if ($createCert -ne "Y" -and $createCert -ne "y") {
            # MANUAL MODE: Show detailed instructions
            Write-Host "`n========================================" -ForegroundColor Yellow
            Write-Host "  Manual Certificate Creation Steps" -ForegroundColor Yellow
            Write-Host "========================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "STEP 1: Create a Self-Signed Certificate" -ForegroundColor Cyan
            Write-Host "-----------------------------------------" -ForegroundColor Gray
            Write-Host "Run these PowerShell commands as Administrator:" -ForegroundColor White
            Write-Host ""
            Write-Host '  $cert = New-SelfSignedCertificate -Subject "CN=PulseOneM365Assessment" ' -ForegroundColor Green
            Write-Host '      -CertStoreLocation "Cert:\\CurrentUser\\My" ' -ForegroundColor Green
            Write-Host '      -KeyExportPolicy Exportable ' -ForegroundColor Green
            Write-Host '      -KeySpec Signature ' -ForegroundColor Green
            Write-Host '      -NotAfter (Get-Date).AddYears(2)' -ForegroundColor Green
            Write-Host ""
            Write-Host "STEP 2: Export the Certificate" -ForegroundColor Cyan
            Write-Host "-------------------------------" -ForegroundColor Gray
            Write-Host '  $certPath = "C:\\Temp\\PulseOneM365Assessment.cer"' -ForegroundColor Green
            Write-Host '  Export-Certificate -Cert $cert -FilePath $certPath' -ForegroundColor Green
            Write-Host ""
            Write-Host "STEP 3: Create App Registration in Azure AD" -ForegroundColor Cyan
            Write-Host "--------------------------------------------" -ForegroundColor Gray
            Write-Host "1. Go to https://portal.azure.com" -ForegroundColor White
            Write-Host "2. Navigate to: Azure Active Directory > App registrations" -ForegroundColor White
            Write-Host "3. Click 'New registration'" -ForegroundColor White
            Write-Host "4. Name: 'PulseOne M365 Assessment'" -ForegroundColor White
            Write-Host "5. Supported account types: Keep default (Single tenant)" -ForegroundColor Gray
            Write-Host "6. Redirect URI: Leave blank (none)" -ForegroundColor Gray
            Write-Host "7. Click 'Register'" -ForegroundColor White
            Write-Host ""
            Write-Host "STEP 4: Upload Certificate" -ForegroundColor Cyan
            Write-Host "---------------------------" -ForegroundColor Gray
            Write-Host "1. Click 'Certificates & secrets'" -ForegroundColor White
            Write-Host "2. Click 'Upload certificate'" -ForegroundColor White
            Write-Host "3. Select your exported .cer file" -ForegroundColor White
            Write-Host "4. Click 'Add'" -ForegroundColor White
            Write-Host ""
            Write-Host "STEP 5: Grant API Permissions" -ForegroundColor Cyan
            Write-Host "------------------------------" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  Microsoft Graph > Application permissions:" -ForegroundColor Yellow
            Write-Host "    - DeviceManagementConfiguration.Read.All" -ForegroundColor Gray
            Write-Host "    - DeviceManagementManagedDevices.Read.All" -ForegroundColor Gray
            Write-Host "    - DeviceManagementRBAC.Read.All" -ForegroundColor Gray
            Write-Host "    - Directory.Read.All" -ForegroundColor Gray
            Write-Host "    - DirectoryRecommendations.Read.All" -ForegroundColor Gray
            Write-Host "    - IdentityRiskEvent.Read.All" -ForegroundColor Gray
            Write-Host "    - OnPremDirectorySynchronization.Read.All" -ForegroundColor Gray
            Write-Host "    - Policy.Read.All" -ForegroundColor Gray
            Write-Host "    - Policy.Read.ConditionalAccess" -ForegroundColor Gray
            Write-Host "    - PrivilegedAccess.Read.AzureAD" -ForegroundColor Gray
            Write-Host "    - PrivilegedAccess.Read.AzureADGroup" -ForegroundColor Gray
            Write-Host "    - PrivilegedEligibilitySchedule.Read.AzureADGroup" -ForegroundColor Gray
            Write-Host "    - Reports.Read.All" -ForegroundColor Gray
            Write-Host "    - ReportSettings.Read.All" -ForegroundColor Gray
            Write-Host "    - RoleEligibilitySchedule.Read.Directory" -ForegroundColor Gray
            Write-Host "    - RoleManagement.Read.All" -ForegroundColor Gray
            Write-Host "    - RoleManagement.Read.Directory" -ForegroundColor Gray
            Write-Host "    - RoleManagementPolicy.Read.AzureADGroup" -ForegroundColor Gray
            Write-Host "    - SecurityIdentitiesHealth.Read.All" -ForegroundColor Gray
            Write-Host "    - SecurityIdentitiesSensors.Read.All" -ForegroundColor Gray
            Write-Host "    - SharePointTenantSettings.Read.All" -ForegroundColor Gray
            Write-Host "    - ThreatHunting.Read.All" -ForegroundColor Gray
            Write-Host "    - User.Read.All" -ForegroundColor Gray
            Write-Host "    - UserAuthenticationMethod.Read.All" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  Optional (enables PIM eligibility and report settings tests):" -ForegroundColor Yellow
            Write-Host "    - RoleEligibilitySchedule.ReadWrite.Directory" -ForegroundColor Gray
            Write-Host "    - ReportSettings.ReadWrite.All" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  Office 365 Exchange Online > Application permissions:" -ForegroundColor Yellow
            Write-Host "    (APIs my organization uses > Office 365 Exchange Online)" -ForegroundColor Gray
            Write-Host "    - Exchange.ManageAsApp" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  SharePoint > Application permissions:" -ForegroundColor Yellow
            Write-Host "    (APIs my organization uses > SharePoint)" -ForegroundColor Gray
            Write-Host "    - Sites.FullControl.All" -ForegroundColor Gray
            Write-Host ""
            Write-Host "STEP 6: Grant Admin Consent" -ForegroundColor Cyan
            Write-Host "----------------------------" -ForegroundColor Gray
            Write-Host "Click 'Grant admin consent for [Your Organization]'" -ForegroundColor White
            Write-Host ""
            Write-Host "STEP 7: Assign Azure AD Roles" -ForegroundColor Red
            Write-Host "-------------------------------" -ForegroundColor Gray
            Write-Host "  Assign BOTH of these roles to your app:" -ForegroundColor White
            Write-Host "    - Global Reader" -ForegroundColor Gray
            Write-Host "    - Teams Administrator" -ForegroundColor Gray
            Write-Host "  Azure AD > Roles and administrators > [Role] > Add assignments" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  NOTE: If your app has Global Admin, these are already included." -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Yellow
            Write-Host ""
            Read-Host "Press Enter when you've completed all steps"
        }
        
        # Collect the information
        Write-Host "`nEnter Your App Registration Information:" -ForegroundColor Cyan
        Write-Host "-----------------------------------------" -ForegroundColor Gray
        
        $config.authentication.servicePrincipal.appId = Read-Host "Application (client) ID"
        
        if ($certThumbprint) {
            Write-Host "Certificate Thumbprint: $certThumbprint" -ForegroundColor Green
            $config.authentication.servicePrincipal.certificateThumbprint = $certThumbprint
        }
        else {
            $config.authentication.servicePrincipal.certificateThumbprint = Read-Host "Certificate Thumbprint"
        }
        
        Write-Host "`nIMPORTANT: Enter your tenant's .onmicrosoft.com domain" -ForegroundColor Yellow
        Write-Host "           (NOT the organization display name)" -ForegroundColor Red
        Write-Host "           This can be found in Azure AD > Overview > Primary domain" -ForegroundColor Gray
        Write-Host "           Example: pulseone.onmicrosoft.com" -ForegroundColor Gray
        
        do {
            $orgDomain = Read-Host "Tenant domain (e.g., pulseone.onmicrosoft.com)"
            if ($orgDomain -match "^[^\s]+\.onmicrosoft\.com$" -or $orgDomain -match "^[^\s]+\.\w+$") {
                $config.authentication.servicePrincipal.organization = $orgDomain
                break
            }
            Write-Host "Invalid domain format. Should be like 'torogroup.onmicrosoft.com'" -ForegroundColor Red
        } while ($true)
        
        # Power Platform Registration (automated with confirmation)
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "  Power Platform Registration" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Power Platform assessment requires a one-time interactive registration." -ForegroundColor White
        Write-Host "This will open a browser sign-in, then register your app for Power Platform access." -ForegroundColor Gray
        Write-Host ""
        Write-Host "NOTE: This only needs to be done ONCE per tenant/app combination." -ForegroundColor DarkGray
        Write-Host "      If you've already done this, you can skip it." -ForegroundColor DarkGray
        Write-Host ""
        $doPowerPlatform = Read-Host "Register app for Power Platform now? [Y/N]"
        
        if ($doPowerPlatform -eq "Y" -or $doPowerPlatform -eq "y") {
            try {
                Write-Host "`nInstalling Power Platform modules if needed..." -ForegroundColor Cyan
                if (-not (Get-Module -ListAvailable -Name Microsoft.PowerApps.Administration.PowerShell)) {
                    Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser -Force -AllowClobber
                    Install-Module Microsoft.PowerApps.PowerShell -Scope CurrentUser -Force -AllowClobber
                }
                Import-Module Microsoft.PowerApps.Administration.PowerShell -Force
                
                Write-Host "Connecting to Power Platform (browser sign-in will open)..." -ForegroundColor Cyan
                Write-Host ""
                Add-PowerAppsAccount -Endpoint prod -TenantID $config.organization.tenantId
                
                Write-Host ""
                Write-Host "Registering app as management app..." -ForegroundColor Cyan
                New-PowerAppManagementApp -ApplicationId $config.authentication.servicePrincipal.appId
                
                Write-Host ""
                Write-Host "Power Platform registration complete!" -ForegroundColor Green
            }
            catch {
                Write-Host ""
                Write-Host "Power Platform registration failed: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "You can retry later by running these commands manually:" -ForegroundColor Yellow
                Write-Host "  Add-PowerAppsAccount -Endpoint prod -TenantID '$($config.organization.tenantId)'" -ForegroundColor Gray
                Write-Host "  New-PowerAppManagementApp -ApplicationId '$($config.authentication.servicePrincipal.appId)'" -ForegroundColor Gray
            }
            Write-Host ""
            Read-Host "Press Enter to continue"
        }
    }
    else {
        $config.authentication.mode = "interactive"
        Write-Host "`nInteractive authentication selected." -ForegroundColor Green
        Write-Host "You will be prompted to authenticate 6-10 times during the assessment." -ForegroundColor Yellow
    }
    
    # Save configuration
    $configDir = Join-Path $Script:ProjectRoot "config"
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }
    
    $configPath = Join-Path $configDir "m365-assessment-config.json"
    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath -Encoding UTF8
    
    Write-Host "`n===============================================" -ForegroundColor Green
    Write-Host "Configuration saved successfully!" -ForegroundColor Green
    Write-Host "Config file: $configPath" -ForegroundColor Gray
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host ""
    
    Read-Host "Press Enter to continue"
    
    return $config
}

#endregion

#region Assessment Functions

function Initialize-AssessmentEnvironment {
    Write-Log -Level "INFO" -Message "Initializing assessment environment"
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
        throw "PowerShell 5.1 or higher is required. Current version: $($PSVersionTable.PSVersion)"
    }
    
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log -Level "WARN" -Message "Script not running as Administrator. Some features may be limited."
    }
    
    # Create output directory - resolve to absolute path to avoid substring issues later
    $outputPath = if ($Script:Config -and $Script:Config.output -and $Script:Config.output.path) { 
        $Script:Config.output.path 
    } else { 
        "./output" 
    }
    $outputDir = [System.IO.Path]::GetFullPath((Join-Path $Script:ProjectRoot $outputPath))
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        Write-Log -Level "INFO" -Message "Created output directory: $outputDir"
    }
    
    # Create run-specific subdirectory
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $runDir = Join-Path $outputDir "M365_Assessment_$timestamp"
    New-Item -ItemType Directory -Path $runDir -Force | Out-Null
    
    $Script:RunDirectory = $runDir
    Write-Log -Level "INFO" -Message "Assessment output directory: $runDir"
}

function Install-RequiredModules {
    Write-Log -Level "INFO" -Message "Checking required PowerShell modules"
    Write-Log -Level "INFO" -Message "Note: Modules will be installed in isolated processes to avoid version conflicts"
    
    # Only check that PowerShellGet is available - actual modules installed in child processes
    $requiredModules = @(
        @{Name = "PowerShellGet"; MinimumVersion = "2.0.0"}
    )
    
    foreach ($module in $requiredModules) {
        Write-Log -Level "INFO" -Message "Checking module: $($module.Name)"
        
        $installed = Get-Module -ListAvailable -Name $module.Name | 
            Where-Object { $_.Version -ge [version]$module.MinimumVersion } | 
            Select-Object -First 1
        
        if (-not $installed) {
            Write-Log -Level "ERROR" -Message "Required module $($module.Name) not found. Please install it first."
            throw "Missing required module: $($module.Name)"
        }
        else {
            Write-Log -Level "SUCCESS" -Message "Module $($module.Name) v$($installed.Version) is ready"
        }
    }
    
    Write-Log -Level "INFO" -Message "Module installation deferred to child processes (to avoid version conflicts)"
}

function Invoke-ScubaGearAssessment {
    param(
        [string]$TenantId,
        [string]$OrgName,
        [string]$Environment,
        [string]$OutputDir
    )
    
    Write-Log -Level "INFO" -Message "Starting baseline assessment (in separate process)"
    
    # Create temporary script for ScubaGear to run in isolated process
    $scubaScriptPath = Join-Path $OutputDir "ScubaGear_Run.ps1"
    
    $authMode = $Script:Config.authentication.mode
    $appId = $Script:Config.authentication.servicePrincipal.appId
    $certThumbprint = $Script:Config.authentication.servicePrincipal.certificateThumbprint
    $orgDomain = $Script:Config.authentication.servicePrincipal.organization
    $products = ($Script:Config.assessment.products | ForEach-Object { "'$_'" }) -join ","
    
    $scubaScriptContent = @"
`$ErrorActionPreference = 'Stop'
try {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " M365 Baseline Security Assessment" -ForegroundColor Cyan  
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Install required modules first
    Write-Host "Installing required modules..." -ForegroundColor DarkGray
    
    # Install ExchangeOnlineManagement
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Host "  Installing ExchangeOnlineManagement..." -ForegroundColor Yellow
        Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
    }
    
    # Install MicrosoftTeams
    if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
        Write-Host "  Installing MicrosoftTeams..." -ForegroundColor Yellow
        Install-Module MicrosoftTeams -Scope CurrentUser -Force -AllowClobber
    }
    
    # Install Microsoft.Graph.Authentication 2.25.0 for compatibility
    Write-Host "  Installing Microsoft.Graph.Authentication 2.25.0..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph.Authentication -RequiredVersion 2.25.0 -Scope CurrentUser -Force -AllowClobber
    Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.25.0 -Force
    
    # Install PnP.PowerShell
    if (-not (Get-Module -ListAvailable -Name PnP.PowerShell)) {
        Write-Host "  Installing PnP.PowerShell..." -ForegroundColor Yellow
        Install-Module PnP.PowerShell -Scope CurrentUser -Force -AllowClobber
    }
    
    # Install Power Platform modules
    if (-not (Get-Module -ListAvailable -Name Microsoft.PowerApps.Administration.PowerShell)) {
        Write-Host "  Installing Power Platform modules..." -ForegroundColor Yellow
        Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser -Force -AllowClobber
        Install-Module Microsoft.PowerApps.PowerShell -Scope CurrentUser -Force -AllowClobber
    }
    
    # Ensure ScubaGear is installed and up to date
    `$currentScuba = Get-Module -ListAvailable -Name ScubaGear | Sort-Object Version -Descending | Select-Object -First 1
    if (-not `$currentScuba) {
        Write-Host "Installing baseline assessment module..." -ForegroundColor Cyan
        Install-Module ScubaGear -Scope CurrentUser -Force -AllowClobber
    } else {
        # Check for updates from PSGallery
        try {
            `$latestScuba = Find-Module ScubaGear -ErrorAction Stop
            if (`$latestScuba.Version -gt `$currentScuba.Version) {
                Write-Host "Updating baseline module (`$(`$currentScuba.Version) -> `$(`$latestScuba.Version))..." -ForegroundColor Yellow
                try {
                    Update-Module ScubaGear -Force -ErrorAction Stop
                } catch {
                    Uninstall-Module ScubaGear -AllVersions -Force -ErrorAction SilentlyContinue
                    Install-Module ScubaGear -Scope CurrentUser -Force -AllowClobber
                }
            } else {
                Write-Host "  Baseline module v`$(`$currentScuba.Version) (up to date)" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "  Could not check for updates, using installed version" -ForegroundColor DarkGray
        }
    }

    Import-Module ScubaGear -Force

    # Initialize ScubaGear (installs OPA and other dependencies)
    if (Get-Command Initialize-SCuBA -ErrorAction SilentlyContinue) {
        Write-Host "Initializing assessment dependencies..." -ForegroundColor Cyan
        Initialize-SCuBA -ErrorAction Stop
    }

    `$products = @($products)

    `$splatParams = @{
        M365Environment = '$Environment'
        ProductNames = `$products
        OutPath = '$($OutputDir -replace "'","''")'
        OutFolderName = 'ScubaReports'
    }

    if ('$authMode' -eq 'servicePrincipal') {
        `$splatParams['AppID'] = '$appId'
        `$splatParams['CertificateThumbprint'] = '$certThumbprint'
        `$splatParams['Organization'] = '$orgDomain'
    } else {
        `$splatParams['LogIn'] = `$true
        if ('$OrgName') {
            `$splatParams['Organization'] = '$($OrgName -replace "'","''")'
        }
    }

    # Check for OrgName parameter support
    `$scubaParams = (Get-Command Invoke-SCuBA).Parameters
    if (`$scubaParams.ContainsKey('OrgName') -and '$OrgName') {
        `$splatParams['OrgName'] = '$($OrgName -replace "'","''")'
    }
    if (`$scubaParams.ContainsKey('SilenceBODWarnings')) {
        `$splatParams['SilenceBODWarnings'] = `$true
    }

    Invoke-SCuBA @splatParams

    # Check for output - ScubaGear may have warnings but still produce valid results
    `$scubaOutput = Get-ChildItem -Path '$($OutputDir -replace "'","''")' -Directory -Filter 'ScubaReports*' -ErrorAction SilentlyContinue
    `$jsonFile = Get-ChildItem -Path '$($OutputDir -replace "'","''")' -Directory -Filter 'ScubaReports*' -ErrorAction SilentlyContinue | Get-ChildItem -Filter 'ScubaResults*.json' -ErrorAction SilentlyContinue | Select-Object -First 1
    
    if (`$jsonFile) {
        Write-Host "Baseline assessment completed successfully with results." -ForegroundColor Green
        exit 0
    } elseif (`$scubaOutput) {
        Write-Host "Baseline assessment completed but no JSON results found." -ForegroundColor Yellow
        exit 0  # Still exit 0 since assessment ran, even if some products failed
    } else {
        Write-Host "Baseline assessment failed - no output directory found." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "FATAL ERROR: `$(`$_.Exception.Message)" -ForegroundColor Red
    Write-Host `$_.ScriptStackTrace -ForegroundColor Red
    exit 1
}
"@

    try {
        $scubaScriptContent | Set-Content -Path $scubaScriptPath -Encoding UTF8
        
        Write-Log -Level "INFO" -Message "Launching baseline assessment in separate PowerShell process..."
        
        # Create wrapper to clean modules before running (simpler approach like original script)
        $wrapperCommand = @"
# Clean up any existing modules that might conflict
Get-Module -Name Microsoft.Graph*, PnP.PowerShell, ScubaGear, Maester, MicrosoftTeams, ExchangeOnlineManagement, Microsoft.PowerApps.* -All -ErrorAction SilentlyContinue | Remove-Module -Force -ErrorAction SilentlyContinue

# Run the actual ScubaGear script
& '$($scubaScriptPath -replace "'","''")'
exit `$LASTEXITCODE
"@
        
        $wrapperPath = [System.IO.Path]::ChangeExtension($scubaScriptPath, '.wrapper.ps1')
        $wrapperCommand | Set-Content -Path $wrapperPath -Encoding UTF8
        
        # Launch child process - MUST use Windows PowerShell 5.1 for ScubaGear
        # PowerShell 7 has assembly loading conflicts with ExchangeOnlineManagement
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if (-not (Test-Path $psExe)) {
            throw "Windows PowerShell 5.1 not found. Baseline assessment requires Windows PowerShell 5.1."
        }
        
        Write-Log -Level "INFO" -Message "Using Windows PowerShell 5.1: $psExe"
        
        $argList = "-NoProfile -NoLogo -ExecutionPolicy Bypass -File `"$wrapperPath`""
        $startParams = @{
            FilePath = $psExe
            ArgumentList = $argList
            PassThru = $true
            NoNewWindow = $true
        }
        
        $process = Start-Process @startParams
        $timeoutMs = 30 * 60 * 1000  # 30 minutes
        $exited = $process.WaitForExit($timeoutMs)
        
        # Cleanup
        Remove-Item -Path $scubaScriptPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $wrapperPath -Force -ErrorAction SilentlyContinue
        
        if (-not $exited) {
            Write-Log -Level "ERROR" -Message "Baseline assessment timed out after 30 minutes"
            $process.Kill()
            $Script:Results.Scuba.Success = $false
            return
        }
        
        # Check for output files (ScubaGear may return non-zero due to warnings but still produce valid results)
        $scubaDir = Get-ChildItem -Path $OutputDir -Directory -Filter "ScubaReports*" | 
            Sort-Object CreationTime -Descending | 
            Select-Object -First 1
        
        if ($scubaDir) {
            $jsonFile = Get-ChildItem -Path $scubaDir.FullName -Filter "ScubaResults*.json" | Select-Object -First 1
            
            if ($jsonFile) {
                $Script:Results.Scuba.Path = $jsonFile.FullName
                $Script:Results.Scuba.Success = $true
                
                try {
                    $scubaData = Get-Content $jsonFile.FullName -Raw | ConvertFrom-Json
                    $Script:Results.Scuba.Count = ($scubaData.Results | Get-Member -MemberType NoteProperty).Count
                }
                catch {
                    $Script:Results.Scuba.Count = 0
                }
                
                Write-Log -Level "SUCCESS" -Message "Baseline assessment completed. Found $($Script:Results.Scuba.Count) products."
                
                if ($process.ExitCode -ne 0) {
                    Write-Log -Level "WARN" -Message "Baseline assessment had warnings (exit code $($process.ExitCode)) but results were generated"
                }
                
                return  # Exit successfully - don't go to catch block
            } else {
                throw "Baseline assessment completed but no JSON results found"
            }
        } else {
            throw "Baseline assessment completed but output directory not found"
        }
    }
    catch {
        Write-Log -Level "ERROR" -Message "Baseline assessment failed: $($_.Exception.Message)"
        Write-Log -Level "ERROR" -Message "Error details logged to: $($Script:LogFile)"
        
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  Baseline Assessment Authentication Failed" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
        Write-Host ""
        Write-Host "Common causes:" -ForegroundColor Yellow
        Write-Host "  - Incorrect Application ID or Certificate Thumbprint" -ForegroundColor White
        Write-Host "  - Certificate not found in CurrentUser\My store" -ForegroundColor White
        Write-Host "  - Admin consent not granted for API permissions" -ForegroundColor White
        Write-Host "  - MISSING: Required role or permission (see setup guide)" -ForegroundColor Red
        Write-Host ""
        Write-Host "Verify your app has:" -ForegroundColor Yellow
        Write-Host "  1. 'Global Reader' + 'Teams Administrator' roles assigned" -ForegroundColor White
        Write-Host "     (or Global Admin, which includes both)" -ForegroundColor Gray
        Write-Host "  2. 'Exchange.ManageAsApp' API permission (Office 365 Exchange Online)" -ForegroundColor White
        Write-Host "  3. All Microsoft Graph API permissions granted with admin consent" -ForegroundColor White
        Write-Host ""
        Write-Host "To retry:" -ForegroundColor Yellow
        Write-Host "  1. Update permissions in Azure AD" -ForegroundColor White
        Write-Host "  2. Delete config\m365-assessment-config.json" -ForegroundColor White
        Write-Host "  3. Run the script again" -ForegroundColor White
        Write-Host ""
        
        # Check if results were actually generated despite the error
        $scubaDir = Get-ChildItem -Path $OutputDir -Directory -Filter "ScubaReports*" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($scubaDir) {
            $jsonFile = Get-ChildItem -Path $scubaDir.FullName -Filter "ScubaResults*.json" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($jsonFile) {
                Write-Host "NOTE: Baseline assessment generated results despite errors. Check the output files." -ForegroundColor Green
                $Script:Results.Scuba.Path = $jsonFile.FullName
                $Script:Results.Scuba.Success = $true
                try {
                    $scubaData = Get-Content $jsonFile.FullName -Raw | ConvertFrom-Json
                    $Script:Results.Scuba.Count = ($scubaData.Results | Get-Member -MemberType NoteProperty).Count
                } catch {
                    $Script:Results.Scuba.Count = 0
                }
                return
            }
        }
        
        $Script:Results.Scuba.Success = $false
    }
}

function Invoke-MaesterAssessment {
    param(
        [string]$TenantId,
        [string]$OutputDir
    )
    
    Write-Log -Level "INFO" -Message "Starting configuration tests (in separate process)"
    Write-Log -Level "INFO" -Message "Note: Configuration tests will open an HTML report automatically when complete"
    
    # Create temporary script for Maester to run in isolated process
    $maesterScriptPath = Join-Path $OutputDir "Maester_Run.ps1"
    
    $authMode = $Script:Config.authentication.mode
    $appId = $Script:Config.authentication.servicePrincipal.appId
    $certThumbprint = $Script:Config.authentication.servicePrincipal.certificateThumbprint
    
    $maesterScriptContent = @"
`$ErrorActionPreference = 'Stop'
try {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " M365 Configuration Security Tests" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Install and import Maester (with auto-update)
    Write-Host "Loading test modules..." -ForegroundColor DarkGray
    `$existingMaester = Get-Module -ListAvailable -Name Maester | Sort-Object Version -Descending | Select-Object -First 1
    if (-not `$existingMaester) {
        Write-Host "Installing test framework..." -ForegroundColor Cyan
        Install-Module Maester -Scope CurrentUser -Force -SkipPublisherCheck -AllowClobber -ErrorAction Stop
    } else {
        # Check for updates from PSGallery
        try {
            `$latestMaester = Find-Module Maester -ErrorAction Stop
            if (`$latestMaester.Version -gt `$existingMaester.Version) {
                Write-Host "Updating test framework (`$(`$existingMaester.Version) -> `$(`$latestMaester.Version))..." -ForegroundColor Yellow
                Update-Module Maester -Force -ErrorAction Stop
            } else {
                Write-Host "  Test framework v`$(`$existingMaester.Version) (up to date)" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "  Could not check for updates, using installed version" -ForegroundColor DarkGray
        }
    }
    Import-Module Maester -Force -ErrorAction Stop
    
    # Setup workspace
    `$workspaceDir = '$($OutputDir -replace "'","''")\MaesterWorkspace'
    `$resultsDir = '$($OutputDir -replace "'","''")\MaesterResults'
    New-Item -Path `$workspaceDir -ItemType Directory -Force | Out-Null
    
    # Install tests
    Write-Host "Installing security test suite..." -ForegroundColor Cyan
    Install-MaesterTests -Path `$workspaceDir
    
    # Track connection status
    `$connectedServices = @()
    `$failedServices = @()
    `$isServicePrincipal = '$authMode' -eq 'servicePrincipal'
    `$orgDomain = '$($Script:Config.authentication.servicePrincipal.organization -replace "'","''")'
    
    Write-Host "`nConnecting to Microsoft 365 services..." -ForegroundColor Cyan
    if (`$isServicePrincipal) {
        Write-Host "(Using service principal authentication)" -ForegroundColor Green
    } else {
        Write-Host "(Watch for browser windows if using interactive auth)" -ForegroundColor Yellow
    }
    Write-Host ""
    
    # Connect to Microsoft Graph (required)
    Write-Host "  [1/5] Microsoft Graph..." -ForegroundColor White
    try {
        if (`$isServicePrincipal) {
            `$cert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { `$_.Thumbprint -eq '$certThumbprint' } | Select-Object -First 1
            if (-not `$cert) {
                throw "Certificate not found in CurrentUser\My store"
            }
            Connect-MgGraph -ClientId '$appId' -TenantId '$TenantId' -Certificate `$cert -NoWelcome
            `$script:cert = `$cert
        } else {
            Connect-Maester -Service Graph
        }
        `$graphContext = Get-MgContext
        if (`$graphContext) {
            Write-Host "         CONNECTED (`$(`$graphContext.Account))" -ForegroundColor Green
            `$connectedServices += "Graph"
        }
    } catch {
        Write-Host "         FAILED: `$(`$_.Exception.Message)" -ForegroundColor Red
        `$failedServices += "Graph"
    }
    Write-Host ""
    
    # Connect to Exchange Online
    Write-Host "  [2/5] Exchange Online..." -ForegroundColor White
    try {
        if (`$isServicePrincipal) {
            if (`$script:cert) {
                Connect-ExchangeOnline -Certificate `$script:cert -AppID '$appId' -Organization `$orgDomain -ShowBanner:`$false -ErrorAction Stop
                Write-Host "         CONNECTED (with certificate)" -ForegroundColor Green
                `$connectedServices += "ExchangeOnline"
            } else {
                throw "Certificate not available for Exchange Online connection"
            }
        } else {
            Connect-Maester -Service ExchangeOnline -ErrorAction Stop
            Write-Host "         CONNECTED" -ForegroundColor Green
            `$connectedServices += "ExchangeOnline"
        }
    } catch {
        Write-Host "         SKIPPED: `$(`$_.Exception.Message)" -ForegroundColor Yellow
        `$failedServices += "ExchangeOnline"
    }
    Write-Host ""
    
    # Connect to Security & Compliance
    Write-Host "  [3/5] Security & Compliance..." -ForegroundColor White
    try {
        if (`$isServicePrincipal) {
            if (`$script:cert) {
                Connect-IPPSSession -Certificate `$script:cert -AppID '$appId' -Organization `$orgDomain -ShowBanner:`$false -ErrorAction Stop
                Write-Host "         CONNECTED (with certificate)" -ForegroundColor Green
                `$connectedServices += "SecurityCompliance"
            } else {
                throw "Certificate not available"
            }
        } else {
            Connect-Maester -Service ExchangeOnline -ErrorAction Stop
            Write-Host "         CONNECTED" -ForegroundColor Green
            `$connectedServices += "SecurityCompliance"
        }
    } catch {
        Write-Host "         SKIPPED: `$(`$_.Exception.Message)" -ForegroundColor Yellow
        `$failedServices += "SecurityCompliance"
    }
    Write-Host ""
    
    # Connect to Azure
    Write-Host "  [4/5] Azure..." -ForegroundColor White
    try {
        if (`$isServicePrincipal) {
            Connect-AzAccount -ServicePrincipal -ApplicationId '$appId' -TenantId '$TenantId' -CertificateThumbprint '$certThumbprint' -ErrorAction Stop
            Write-Host "         CONNECTED (with certificate)" -ForegroundColor Green
            `$connectedServices += "Azure"
        } else {
            Connect-Maester -Service Azure -ErrorAction Stop
            Write-Host "         CONNECTED" -ForegroundColor Green
            `$connectedServices += "Azure"
        }
    } catch {
        Write-Host "         SKIPPED: `$(`$_.Exception.Message)" -ForegroundColor Yellow
        `$failedServices += "Azure"
    }
    Write-Host ""
    
    # Connect to Teams (last - known DLL conflicts with other modules)
    # MicrosoftTeams module often conflicts with Graph/Exchange DLL versions.
    # Most Teams security tests still work via Microsoft Graph without this connection.
    Write-Host "  [5/5] Teams..." -ForegroundColor White
    try {
        if (`$isServicePrincipal) {
            if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
                Install-Module MicrosoftTeams -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            }
            Import-Module MicrosoftTeams -Force -ErrorAction Stop
            Connect-MicrosoftTeams -Certificate `$script:cert -ApplicationId '$appId' -TenantId '$TenantId' -ErrorAction Stop
            Write-Host "         CONNECTED (with certificate)" -ForegroundColor Green
        } else {
            Connect-Maester -Service Teams -ErrorAction Stop
            Write-Host "         CONNECTED" -ForegroundColor Green
        }
        `$connectedServices += "Teams"
    } catch {
        if (`$_.Exception.Message -match 'assembly|manifest|Version=') {
            Write-Host "         SKIPPED (DLL version conflict - Teams tests will run via Graph)" -ForegroundColor Yellow
        } else {
            Write-Host "         SKIPPED: `$(`$_.Exception.Message)" -ForegroundColor Yellow
        }
        `$failedServices += "Teams"
    }
    Write-Host ""
    
    # Connection Summary
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " Connection Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Connected: `$(`$connectedServices -join ', ')" -ForegroundColor Green
    if (`$failedServices.Count -gt 0) {
        Write-Host "  Skipped:   `$(`$failedServices -join ', ')" -ForegroundColor Yellow
        Write-Host "`n  Skipped services:" -ForegroundColor Yellow
        if (`$failedServices -contains "ExchangeOnline") {
            Write-Host "    - Exchange Online: Needs 'Exchange.ManageAsApp' permission + Global Reader role" -ForegroundColor Gray
        }
        if (`$failedServices -contains "SecurityCompliance") {
            Write-Host "    - Security & Compliance: Needs 'Exchange.ManageAsApp' permission" -ForegroundColor Gray
        }
        if (`$failedServices -contains "Teams") {
            Write-Host "    - Teams: Known DLL conflict with other modules. Most Teams tests still run via Graph." -ForegroundColor Gray
        }
        if (`$failedServices -contains "Azure") {
            Write-Host "    - Azure: Needs 'Reader' role on Azure subscription" -ForegroundColor Gray
        }
    }
    Write-Host ""
    
    # Verify Graph connected (required)
    if (`$connectedServices -notcontains "Graph") {
        throw "Microsoft Graph connection failed. Cannot proceed."
    }
    
    # Run security tests
    Write-Host "Running security tests..." -ForegroundColor Cyan
    Write-Host "This may take 5-15 minutes..." -ForegroundColor Gray
    Write-Host ""
    # Note: The test framework will automatically open its HTML report in a browser
    Invoke-Maester -Path `$workspaceDir -OutputFolder `$resultsDir -OutputFolderFileName 'Maester'
    
    # Get test results summary
    `$jsonFile = Join-Path `$resultsDir 'Maester.json'
    if (Test-Path `$jsonFile) {
        `$results = Get-Content `$jsonFile -Raw | ConvertFrom-Json
        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host " Configuration Tests Complete" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Tests Passed:     `$results.PassedCount" -ForegroundColor Green
        Write-Host "  Tests Failed:     `$results.FailedCount" -ForegroundColor Red
        Write-Host "  Tests Skipped:    `$results.SkippedCount" -ForegroundColor Yellow
        Write-Host "  Total Tests:      `$results.TotalCount" -ForegroundColor White
        Write-Host ""
    }
    
    Write-Host "Results saved to output folder" -ForegroundColor White
    Write-Host ""
    Write-Host "Press any key to close this window..." -ForegroundColor Cyan
    `$null = `$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 0
} catch {
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host " Configuration Tests Failed" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: `$($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Press any key to close this window..." -ForegroundColor Cyan
    `$null = `$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
} finally {
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch { }
    try { Disconnect-ExchangeOnline -Confirm:`$false -ErrorAction SilentlyContinue } catch { }
}
"@

    try {
        $maesterScriptContent | Set-Content -Path $maesterScriptPath -Encoding UTF8
        
        Write-Log -Level "INFO" -Message "Launching configuration tests in separate PowerShell window..."
        
        # Maester can use either PowerShell 7 or 5.1
        # Prefer PowerShell 7 if available (better performance)
        $psExe = 'powershell.exe'
        $pwsh7 = Get-Command pwsh.exe -ErrorAction SilentlyContinue
        if ($pwsh7) {
            $psExe = $pwsh7.Source
            Write-Log -Level "INFO" -Message "Using PowerShell 7 for configuration tests: $psExe"
        } else {
            Write-Log -Level "INFO" -Message "Using Windows PowerShell 5.1 for configuration tests: $psExe"
        }
        
        $argList = "-NoProfile -NoLogo -ExecutionPolicy Bypass -File `"$maesterScriptPath`""
        $startParams = @{
            FilePath = $psExe
            ArgumentList = $argList
            PassThru = $true
            WindowStyle = 'Maximized'  # Show window for interactive auth
        }
        
        $process = Start-Process @startParams
        $timeoutMs = 45 * 60 * 1000  # 45 minutes for Maester
        $exited = $process.WaitForExit($timeoutMs)
        
        # Cleanup
        Remove-Item -Path $maesterScriptPath -Force -ErrorAction SilentlyContinue
        
        if (-not $exited) {
            Write-Log -Level "ERROR" -Message "Configuration tests timed out after 45 minutes"
            $process.Kill()
            $Script:Results.Maester.Success = $false
            return
        }
        
        if ($process.ExitCode -ne 0) {
            throw "Configuration test process failed with exit code $($process.ExitCode)"
        }
        
        # Find output files
        $resultsDir = Join-Path $OutputDir "MaesterResults"
        $jsonFile = Join-Path $resultsDir "Maester.json"
        
        if (Test-Path $jsonFile) {
            $Script:Results.Maester.Path = $jsonFile
            $Script:Results.Maester.Success = $true
            
            try {
                $maesterData = Get-Content $jsonFile -Raw | ConvertFrom-Json
                $Script:Results.Maester.Count = $maesterData.TotalCount
                $Script:Results.Maester.SkippedCount = $maesterData.SkippedCount
                
                Write-Log -Level "INFO" -Message "Config Test Results - Passed: $($maesterData.PassedCount), Failed: $($maesterData.FailedCount), Skipped: $($maesterData.SkippedCount), Total: $($maesterData.TotalCount)"
                
                if ($maesterData.SkippedCount -gt 0) {
                    Write-Log -Level "WARN" -Message "$($maesterData.SkippedCount) tests were skipped due to missing permissions, licenses, or configuration"
                }
            }
            catch {
                $Script:Results.Maester.Count = 0
                $Script:Results.Maester.SkippedCount = 0
            }
            
            Write-Log -Level "SUCCESS" -Message "Configuration tests completed with $($Script:Results.Maester.Count) total tests"
        } else {
            throw "Configuration tests completed but output file not found"
        }
    }
    catch {
        Write-Log -Level "ERROR" -Message "Configuration tests failed: $($_.Exception.Message)"
        $Script:Results.Maester.Success = $false
    }
}

#endregion

#region Report Generation

function Export-ConsolidatedReport {
    param([string]$OutputDir)
    
    Write-Log -Level "INFO" -Message "Generating consolidated report"
    
    $findings = [System.Collections.Generic.List[PSObject]]::new()
    
    # Process baseline assessment results
    if ($Script:Results.Scuba.Success -and $Script:Results.Scuba.Path) {
        try {
            $scubaData = Get-Content $Script:Results.Scuba.Path -Raw | ConvertFrom-Json
            
            $productNames = ($scubaData.Results | Get-Member -MemberType NoteProperty).Name
            foreach ($productName in $productNames) {
                $product = $scubaData.Results.$productName
                if ($product.Controls) {
                    foreach ($control in $product.Controls) {
                        if ($control.Result -in @("Fail", "Warning")) {
                            # Map ScubaGear Criticality to priority levels
                            $priority = switch -Wildcard ($control.Criticality) {
                                "Shall"               { "High" }
                                "Shall/3rd Party"     { "High" }
                                "Should"              { "Medium" }
                                "Should/3rd Party"    { "Medium" }
                                "Shall/Not-Implemented" { "Low" }
                                "Should/Not-Implemented" { "Low" }
                                default               { "Low" }
                            }
                            $findings.Add([PSCustomObject]@{
                                Source = "ScubaGear"
                                ControlId = $control.'Control ID'
                                Title = $control.Requirement
                                Status = $control.Result
                                Severity = $priority
                                Details = $control.Details
                                Remediation = "See ScubaGear detailed report for remediation steps"
                            })
                        }
                    }
                }
            }
        }
        catch {
            Write-Log -Level "ERROR" -Message "Failed to process baseline results: $($_.Exception.Message)"
        }
    }
    
    # Process configuration test results
    if ($Script:Results.Maester.Success -and $Script:Results.Maester.Path) {
        try {
            $maesterData = Get-Content $Script:Results.Maester.Path -Raw -Encoding UTF8 | ConvertFrom-Json
            
            foreach ($test in $maesterData.Tests) {
                if ($test.Result -eq "Failed") {
                    # Maester severity is already High/Medium; default unknown to Medium
                    $maesterSeverity = if ($test.Severity -in @("High", "Medium", "Low")) { $test.Severity } else { "Medium" }
                    $findings.Add([PSCustomObject]@{
                        Source = "Maester"
                        ControlId = $test.Id
                        Title = $test.Title
                        Status = $test.Result
                        Severity = $maesterSeverity
                        Details = if ($test.ResultDetail) { $test.ResultDetail.TestResult } else { "No details available" }
                        Remediation = if ($test.ResultDetail) { $test.ResultDetail.TestDescription } else { "No remediation steps available" }
                    })
                }
            }
        }
        catch {
            Write-Log -Level "ERROR" -Message "Failed to process configuration test results: $($_.Exception.Message)"
        }
    }
    
    # Export JSON findings
    $findingsFile = Join-Path $OutputDir "Consolidated_Failures.json"
    $findings | ConvertTo-Json -Depth 5 | Set-Content -Path $findingsFile -Encoding UTF8
    $Script:Results.Consolidated.Path = $findingsFile
    $Script:Results.Consolidated.Count = $findings.Count
    
    Write-Log -Level "SUCCESS" -Message "Consolidated report saved: $findingsFile ($($findings.Count) findings)"
    
    # Generate HTML report
    Export-HTMLReport -OutputDir $OutputDir -Findings $findings
}

function ConvertFrom-MarkdownToHtml {
    param([string]$Text)
    
    if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
    
    # Replace emoji - both proper unicode and mojibake from encoding issues
    # Proper unicode replacements (when read correctly as UTF-8)
    $Text = $Text -replace "\u274C", '[FAIL]'         # red X ❌
    $Text = $Text -replace "\u2705", '[PASS]'         # green check ✅
    $Text = $Text -replace "\u2714\uFE0F?", '[PASS]'  # check mark ✔️
    $Text = $Text -replace "\u2753", '[?]'             # question mark ❓
    $Text = $Text -replace "\u26A0\uFE0F?", '[WARN]'  # warning ⚠️
    $Text = $Text -replace "\u2139\uFE0F?", '[INFO]'  # info ℹ️
    $Text = $Text -replace "\u27A1\uFE0F?", '->'      # right arrow ➡️
    $Text = $Text -replace "\uD83D\uDDC4\uFE0F?", '[SKIP]'  # file cabinet 🗄️
    $Text = $Text -replace "\uFE0F", ''                # strip remaining variation selectors
    
    # Mojibake patterns (UTF-8 bytes read as Windows-1252)
    # ❌ U+274C = E2 9D 8C -> â\x9D\x8C or â<control>Œ
    $Text = $Text -replace "\u00E2\u009D\u008C", '[FAIL]'
    # ✅ U+2705 = E2 9C 85 -> â\x9C\x85
    $Text = $Text -replace "\u00E2\u009C\u0085", '[PASS]'
    # ✔ U+2714 = E2 9C 94 -> â\x9C\x94
    $Text = $Text -replace "\u00E2\u009C\u0094", '[PASS]'
    # ⚠ U+26A0 = E2 9A A0 -> â\x9A\xA0
    $Text = $Text -replace "\u00E2\u009A\u00A0", '[WARN]'
    # ➡ U+27A1 = E2 9E A1 -> â\x9E\xA1  (plus optional ï¸ = FE0F mojibake EF B8 8F)
    $Text = $Text -replace "\u00E2\u009E\u00A1(\u00EF\u00B8\u008F)?", '->'
    # ❓ U+2753 = E2 9D 93 -> â\x9D\x93
    $Text = $Text -replace "\u00E2\u009D\u0093", '[?]'
    # ❔ U+2754 = E2 9D 94
    $Text = $Text -replace "\u00E2\u009D\u0094", '[?]'
    # Variation selector mojibake ï¸ (EF B8 8F as Windows-1252)
    $Text = $Text -replace "\u00EF\u00B8\u008F", ''
    
    # Clean up any remaining ? placeholders from totally lost emoji (single ? between spaces or at line start)
    # Don't remove ? that are part of words
    $Text = $Text -replace '^\?\s+', ''
    $Text = $Text -replace '\s\?\s', ' '
    
    # Normalize line endings
    $Text = $Text -replace "`r`n", "`n"
    
    $lines = $Text -split "`n"
    $html = [System.Text.StringBuilder]::new()
    $inCodeBlock = $false
    $inTable = $false
    $inList = $false
    $listType = ""
    
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        
        # Fenced code blocks
        if ($line -match '^\s*```') {
            if ($inCodeBlock) {
                [void]$html.Append("</code></pre>")
                $inCodeBlock = $false
            } else {
                if ($inTable) { [void]$html.Append("</table>"); $inTable = $false }
                if ($inList) { [void]$html.Append("</$listType>"); $inList = $false }
                [void]$html.Append("<pre class='code-block'><code>")
                $inCodeBlock = $true
            }
            continue
        }
        
        if ($inCodeBlock) {
            [void]$html.AppendLine([System.Web.HttpUtility]::HtmlEncode($line))
            continue
        }
        
        # Skip empty lines (close open lists/tables)
        if ([string]::IsNullOrWhiteSpace($line)) {
            if ($inTable) { [void]$html.Append("</table>"); $inTable = $false }
            if ($inList) { [void]$html.Append("</$listType>"); $inList = $false }
            continue
        }
        
        # Table separator row - skip it
        if ($line -match '^\|[\s\-:|]+\|$') {
            continue
        }
        
        # Table rows
        if ($line -match '^\|(.+)\|$') {
            $cells = ($line.Trim('|') -split '\|') | ForEach-Object { $_.Trim() }
            if (-not $inTable) {
                if ($inList) { [void]$html.Append("</$listType>"); $inList = $false }
                [void]$html.Append("<table class='detail-table'><thead><tr>")
                foreach ($cell in $cells) {
                    $cell = ConvertFrom-InlineMarkdown $cell
                    [void]$html.Append("<th>$cell</th>")
                }
                [void]$html.Append("</tr></thead><tbody>")
                $inTable = $true
                
                # Check if next line is separator
                if (($i + 1) -lt $lines.Count -and $lines[$i + 1] -match '^\|[\s\-:|]+\|$') {
                    $i++  # skip separator
                }
            } else {
                [void]$html.Append("<tr>")
                foreach ($cell in $cells) {
                    $cell = ConvertFrom-InlineMarkdown $cell
                    # Color status cells
                    if ($cell -match '&#10060;|Fail') {
                        [void]$html.Append("<td class='cell-fail'>$cell</td>")
                    } elseif ($cell -match '&#9989;|&#10004;|Pass') {
                        [void]$html.Append("<td class='cell-pass'>$cell</td>")
                    } else {
                        [void]$html.Append("<td>$cell</td>")
                    }
                }
                [void]$html.Append("</tr>")
            }
            continue
        }
        
        # Close table if we're past table rows
        if ($inTable) { [void]$html.Append("</tbody></table>"); $inTable = $false }
        
        # Headers
        if ($line -match '^(#{1,4})\s+(.+)$') {
            if ($inList) { [void]$html.Append("</$listType>"); $inList = $false }
            $level = $Matches[1].Length + 2  # offset so #### becomes h6, ## becomes h4
            if ($level -gt 6) { $level = 6 }
            $headerText = ConvertFrom-InlineMarkdown $Matches[2]
            [void]$html.Append("<h$level>$headerText</h$level>")
            continue
        }
        
        # Numbered list items
        if ($line -match '^\s*\d+\.\s+(.+)$') {
            if ($inList -and $listType -ne "ol") { [void]$html.Append("</$listType>"); $inList = $false }
            if (-not $inList) { [void]$html.Append("<ol>"); $inList = $true; $listType = "ol" }
            [void]$html.Append("<li>$(ConvertFrom-InlineMarkdown $Matches[1])</li>")
            continue
        }
        
        # Bullet list items
        if ($line -match '^\s*[-*]\s+(.+)$') {
            if ($inList -and $listType -ne "ul") { [void]$html.Append("</$listType>"); $inList = $false }
            if (-not $inList) { [void]$html.Append("<ul>"); $inList = $true; $listType = "ul" }
            [void]$html.Append("<li>$(ConvertFrom-InlineMarkdown $Matches[1])</li>")
            continue
        }
        
        # Blockquotes
        if ($line -match '^>\s*(.+)$') {
            if ($inList) { [void]$html.Append("</$listType>"); $inList = $false }
            [void]$html.Append("<blockquote>$(ConvertFrom-InlineMarkdown $Matches[1])</blockquote>")
            continue
        }
        
        # Regular paragraph
        if ($inList) { [void]$html.Append("</$listType>"); $inList = $false }
        [void]$html.Append("<p>$(ConvertFrom-InlineMarkdown $line)</p>")
    }
    
    # Close any open elements
    if ($inCodeBlock) { [void]$html.Append("</code></pre>") }
    if ($inTable) { [void]$html.Append("</tbody></table>") }
    if ($inList) { [void]$html.Append("</$listType>") }
    
    return $html.ToString()
}

function ConvertFrom-InlineMarkdown {
    param([string]$Text)
    
    # HTML-encode first (but preserve our already-encoded HTML entities)
    $Text = [System.Web.HttpUtility]::HtmlEncode($Text)
    # Restore HTML entities we put in
    $Text = $Text -replace '&amp;#(\d+);', '&#$1;'
    
    # Bold: **text**
    $Text = $Text -replace '\*\*(.+?)\*\*', '<strong>$1</strong>'
    # Inline code: `text`
    $Text = $Text -replace '`([^`]+)`', '<code class="inline-code">$1</code>'
    # Links: [text](url)
    $Text = $Text -replace '\[([^\]]+)\]\(([^)]+)\)', '<a href="$2" target="_blank">$1</a>'
    
    return $Text
}

function Export-HTMLReport {
    param(
        [string]$OutputDir,
        [array]$Findings
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $orgName = $Script:Config.organization.name
    $tenantId = $Script:Config.organization.tenantId
    
    # Count by severity
    $highCount = ($Findings | Where-Object { $_.Severity -in @("High", "Critical") }).Count
    $mediumCount = ($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = ($Findings | Where-Object { $_.Severity -eq "Low" }).Count
    
    # Get baseline report paths for linking
    $scubaDir = Get-ChildItem -Path $OutputDir -Directory -Filter "ScubaReports*" | Select-Object -First 1
    $maesterDir = Join-Path $OutputDir "MaesterResults"
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>M365 Security Assessment - $orgName</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .header {
            border-bottom: 3px solid #0078d4;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #0078d4;
            margin: 0 0 10px 0;
        }
        .meta {
            color: #666;
            font-size: 14px;
        }
        .summary {
            background-color: #f0f0f0;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }
        .summary h2 {
            margin-top: 0;
            color: #333;
        }
        .stats {
            display: flex;
            gap: 20px;
            margin-top: 15px;
        }
        .stat-box {
            flex: 1;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }
        .stat-box.high {
            background-color: #fde7e9;
            border-left: 4px solid #d13438;
        }
        .stat-box.medium {
            background-color: #fff4ce;
            border-left: 4px solid #ffc107;
        }
        .stat-box.low {
            background-color: #e8f5e9;
            border-left: 4px solid #107c10;
        }
        .stat-number {
            font-size: 32px;
            font-weight: bold;
            color: #333;
        }
        .stat-label {
            font-size: 14px;
            color: #666;
            margin-top: 5px;
        }
        .finding-row {
            cursor: pointer;
            transition: background-color 0.2s;
        }
        .finding-row:hover {
            background-color: #f5f5f5;
        }
        .finding-row.expanded {
            background-color: #e8f4f8;
        }
        .finding-details {
            display: none;
            padding: 15px;
            background-color: #f9f9f9;
            border-left: 3px solid #0078d4;
            margin: 0;
        }
        .finding-details.show {
            display: table-row;
        }
        .details-content {
            padding: 15px;
        }
        .details-content h4 {
            margin-top: 0;
            color: #0078d4;
        }
        .details-content pre {
            background-color: #f4f4f4;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 12px;
        }
        .severity {
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-high {
            background-color: #d13438;
            color: white;
        }
        .severity-medium {
            background-color: #ffc107;
            color: black;
        }
        .severity-low {
            background-color: #107c10;
            color: white;
        }
        .status-fail {
            color: #d13438;
            font-weight: bold;
        }
        .status-warning {
            color: #ffc107;
            font-weight: bold;
        }
        .expand-icon {
            display: inline-block;
            width: 0;
            height: 0;
            border-top: 5px solid transparent;
            border-bottom: 5px solid transparent;
            border-left: 8px solid #666;
            margin-right: 5px;
            transition: transform 0.2s;
        }
        .expand-icon.rotated {
            transform: rotate(90deg);
        }
        th.sortable {
            cursor: pointer;
            user-select: none;
        }
        th.sortable:hover {
            background-color: #005a9e;
        }
        th.sortable::after {
            content: ' \2195';
            font-size: 10px;
        }
        th.sort-asc::after {
            content: ' \2191';
        }
        th.sort-desc::after {
            content: ' \2193';
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th {
            background-color: #0078d4;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #ddd;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
            font-size: 12px;
            text-align: center;
        }
        .report-links {
            margin-top: 20px;
            padding: 15px;
            background-color: #f0f8ff;
            border-radius: 5px;
        }
        .report-links h3 {
            margin-top: 0;
            color: #0078d4;
        }
        .report-links a {
            display: inline-block;
            margin: 5px 10px 5px 0;
            padding: 8px 15px;
            background-color: #0078d4;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-size: 14px;
        }
        .report-links a:hover {
            background-color: #005a9e;
        }
        /* Rendered markdown content styles */
        .rendered-content {
            font-size: 13px;
            line-height: 1.5;
        }
        .rendered-content p {
            margin: 6px 0;
        }
        .rendered-content h4, .rendered-content h5, .rendered-content h6 {
            color: #0078d4;
            margin: 12px 0 6px 0;
        }
        .rendered-content ol, .rendered-content ul {
            margin: 6px 0;
            padding-left: 24px;
        }
        .rendered-content li {
            margin: 4px 0;
        }
        .rendered-content blockquote {
            border-left: 3px solid #ffc107;
            background: #fff8e1;
            padding: 8px 12px;
            margin: 8px 0;
            font-style: italic;
        }
        .rendered-content a {
            color: #0078d4;
            text-decoration: underline;
        }
        .rendered-content .code-block {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 12px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 12px;
            font-family: 'Cascadia Code', 'Consolas', monospace;
            margin: 8px 0;
        }
        .rendered-content .code-block code {
            background: none;
            padding: 0;
            color: inherit;
        }
        .rendered-content .inline-code {
            background: #f0f0f0;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: 'Cascadia Code', 'Consolas', monospace;
            font-size: 12px;
        }
        .detail-table {
            width: 100%;
            border-collapse: collapse;
            margin: 8px 0;
            font-size: 13px;
        }
        .detail-table th {
            background-color: #f0f0f0;
            color: #333;
            padding: 8px 10px;
            text-align: left;
            font-weight: 600;
            border: 1px solid #ddd;
        }
        .detail-table td {
            padding: 6px 10px;
            border: 1px solid #ddd;
        }
        .detail-table tbody tr:nth-child(even) {
            background-color: #fafafa;
        }
        .detail-table .cell-fail {
            color: #d13438;
            font-weight: 600;
        }
        .detail-table .cell-pass {
            color: #107c10;
            font-weight: 600;
        }
    </style>
    <script>
        function toggleDetails(id) {
            const detailsRow = document.getElementById('details-' + id);
            const mainRow = document.getElementById('row-' + id);
            const icon = document.getElementById('icon-' + id);
            
            if (detailsRow.classList.contains('show')) {
                detailsRow.classList.remove('show');
                mainRow.classList.remove('expanded');
                icon.classList.remove('rotated');
            } else {
                detailsRow.classList.add('show');
                mainRow.classList.add('expanded');
                icon.classList.add('rotated');
            }
        }

        function sortTable(colIndex) {
            const table = document.getElementById('findings-table');
            const tbody = table.querySelector('tbody');
            const headerCells = table.querySelectorAll('th');
            
            // Get all main rows (not detail rows)
            const rows = Array.from(tbody.querySelectorAll('tr.finding-row'));
            
            // Determine sort direction
            const currentDir = headerCells[colIndex].getAttribute('data-sort') || 'asc';
            const newDir = currentDir === 'asc' ? 'desc' : 'asc';
            
            // Reset all headers
            headerCells.forEach(h => { h.removeAttribute('data-sort'); h.classList.remove('sort-asc','sort-desc'); });
            headerCells[colIndex].setAttribute('data-sort', newDir);
            headerCells[colIndex].classList.add('sort-' + newDir);
            
            // Priority order for severity sorting
            const severityOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Warning': 4, 'Unknown': 5 };
            
            rows.sort(function(a, b) {
                let aVal = a.cells[colIndex].textContent.trim();
                let bVal = b.cells[colIndex].textContent.trim();
                
                // Use severity ordering for the Priority column
                if (colIndex === 4) {
                    aVal = severityOrder[aVal] !== undefined ? severityOrder[aVal] : 99;
                    bVal = severityOrder[bVal] !== undefined ? severityOrder[bVal] : 99;
                    return newDir === 'asc' ? aVal - bVal : bVal - aVal;
                }
                
                if (newDir === 'asc') return aVal.localeCompare(bVal);
                return bVal.localeCompare(aVal);
            });
            
            // Re-insert rows in sorted order (each main row followed by its detail row)
            rows.forEach(function(row) {
                const detailRow = row.nextElementSibling;
                tbody.appendChild(row);
                if (detailRow && detailRow.classList.contains('finding-details')) {
                    tbody.appendChild(detailRow);
                }
            });
        }

        // Sort by priority (High first) on page load
        document.addEventListener('DOMContentLoaded', function() { sortTable(4); });
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>M365 Security Assessment Report</h1>
            <div class="meta">
                <strong>Organization:</strong> $orgName<br>
                <strong>Tenant ID:</strong> $tenantId<br>
                <strong>Generated:</strong> $timestamp<br>
                <strong>Assessment:</strong> Automated Security Baseline + Configuration Tests
            </div>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <p>This report contains security findings from automated assessment of your Microsoft 365 tenant configuration against industry best practices and security baselines.</p>
            
            <div class="stats">
                <div class="stat-box high">
                    <div class="stat-number">$highCount</div>
                    <div class="stat-label">High Priority</div>
                </div>
                <div class="stat-box medium">
                    <div class="stat-number">$mediumCount</div>
                    <div class="stat-label">Medium Priority</div>
                </div>
                <div class="stat-box low">
                    <div class="stat-number">$lowCount</div>
                    <div class="stat-label">Low Priority</div>
                </div>
            </div>
        </div>
        
        <div class="report-links">
            <h3>Detailed Reports</h3>
            <p>Click below to view full detailed reports:</p>
"@
    
    # Add baseline report links if available
    # Check for ScubaReports folder structure OR individual report files in root
    $scubaReportFiles = @()
    
    if ($scubaDir) {
        $scubaIndividualReports = Join-Path $scubaDir.FullName "IndividualReports"
        if (Test-Path $scubaIndividualReports) {
            $scubaReportFiles = Get-ChildItem -Path $scubaIndividualReports -Filter "*Report.html" | Sort-Object Name
            $scubaBasePath = "$($scubaDir.Name)/IndividualReports/"
        }
    }
    
    # If no ScubaReports folder, look for individual report files directly in output
    if ($scubaReportFiles.Count -eq 0) {
        $scubaReportFiles = Get-ChildItem -Path $OutputDir -Filter "*Report.html" | 
            Where-Object { $_.Name -match "^(AAD|EXO|Defender|SharePoint|Teams|PowerPlatform)Report\.html$" } | 
            Sort-Object Name
        $scubaBasePath = ""
    }
    
    if ($scubaReportFiles.Count -gt 0) {
        $html += @"
            <strong>ScubaGear Reports:</strong><br>
"@
        foreach ($report in $scubaReportFiles) {
            $relativePath = "$scubaBasePath$($report.Name)"
            $reportName = $report.BaseName -replace "Report$", "" -replace "^AAD$", "Azure AD" -replace "^EXO$", "Exchange Online" -replace "^Defender$", "Defender" -replace "^SharePoint$", "SharePoint" -replace "^Teams$", "Teams" -replace "^PowerPlatform$", "Power Platform"
            $html += @"
            <a href="$relativePath" target="_blank">$reportName</a>
"@
        }
        $html += @"
            <br><br>
"@
    }
    
    # Add configuration test report link if available
    if (Test-Path $maesterDir) {
        $maesterHtml = Join-Path $maesterDir "Maester.html"
        if (Test-Path $maesterHtml) {
            $html += @"
            <strong>Maester Report:</strong><br>
            <a href="MaesterResults/Maester.html" target="_blank">View Maester Detailed Results</a>
"@
        }
    }
    
    $html += @"
        </div>
        
        <h2>Detailed Findings</h2>
        <p style="color: #666; font-style: italic; margin-bottom: 15px;">Click on any finding to view details. Click column headers to sort.</p>
        <table id="findings-table">
            <thead>
                <tr>
                    <th style="width: 30px;"></th>
                    <th class="sortable" onclick="sortTable(1)">Control ID</th>
                    <th class="sortable" onclick="sortTable(2)">Title</th>
                    <th class="sortable" onclick="sortTable(3)">Source</th>
                    <th class="sortable" onclick="sortTable(4)">Priority</th>
                    <th class="sortable" onclick="sortTable(5)">Status</th>
                </tr>
            </thead>
            <tbody>
"@
    
    # Add findings rows with expandable details
    $rowId = 0
    foreach ($finding in $Findings) {
        $rowId++
        $severityClass = switch ($finding.Severity) {
            "High" { "severity-high" }
            "Critical" { "severity-high" }
            "Medium" { "severity-medium" }
            default { "severity-low" }
        }
        
        $statusClass = if ($finding.Status -eq "Fail") { "status-fail" } else { "status-warning" }
        
        # Create details content - convert markdown to rich HTML
        $detailsHtml = ""
        if ($finding.Details) {
            $renderedDetails = ConvertFrom-MarkdownToHtml -Text $finding.Details
            $detailsHtml += "<h4>Finding Details</h4><div class='rendered-content'>$renderedDetails</div>"
        }
        if ($finding.Remediation) {
            $renderedRemediation = ConvertFrom-MarkdownToHtml -Text $finding.Remediation
            $detailsHtml += "<h4>Remediation Guidance</h4><div class='rendered-content'>$renderedRemediation</div>"
        }
        
        $html += @"
                <tr id="row-$rowId" class="finding-row" onclick="toggleDetails($rowId)">
                    <td><span id="icon-$rowId" class="expand-icon"></span></td>
                    <td>$($finding.ControlId)</td>
                    <td>$($finding.Title)</td>
                    <td>$($finding.Source)</td>
                    <td><span class="severity $severityClass">$($finding.Severity)</span></td>
                    <td class="$statusClass">$($finding.Status)</td>
                </tr>
                <tr id="details-$rowId" class="finding-details">
                    <td colspan="6">
                        <div class="details-content">
                            $detailsHtml
                        </div>
                    </td>
                </tr>
"@
    }
    
    $html += @"
            </tbody>
        </table>
        
        <div class="footer">
            <p>Generated by PulseOne M365 Assessment Tool v$Script:Version</p>
            <p>This report contains sensitive security information. Handle in accordance with your organization's data handling policies.</p>
        </div>
    </div>
</body>
</html>
"@
    
    $htmlFile = Join-Path $OutputDir "M365_Assessment_Report.html"
    $html | Set-Content -Path $htmlFile -Encoding UTF8
    
    if (Test-Path $htmlFile) {
        Write-Log -Level "SUCCESS" -Message "HTML report saved: $htmlFile ($( (Get-Item $htmlFile).Length ) bytes)"
    } else {
        Write-Log -Level "ERROR" -Message "Failed to create HTML report at: $htmlFile"
    }
}

#endregion

#region Main Execution

function Show-CompletionSummary {
    param([string]$OutputDir)
    
    # Resolve to absolute path
    $OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
    
    $duration = (Get-Date) - $Script:StartTime
    
    Write-Host "`n===============================================" -ForegroundColor Green
    Write-Host "    M365 Assessment Complete" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Organization:    $($Script:Config.organization.name)" -ForegroundColor White
    Write-Host "Tenant ID:       $($Script:Config.organization.tenantId)" -ForegroundColor White
    Write-Host "Duration:        $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
    Write-Host ""
    Write-Host "Results Summary:" -ForegroundColor Yellow
    
    # Baseline Assessment Results
    if ($Script:Results.Scuba.Success) {
        Write-Host "  Baseline:      [OK] SUCCESS - $($Script:Results.Scuba.Count) products assessed" -ForegroundColor Green
    } else {
        Write-Host "  Baseline:      [X] FAILED - No results generated" -ForegroundColor Red
    }
    
    # Configuration Tests Results
    if ($Script:Results.Maester.Success) {
        Write-Host "  Config Tests:  [OK] SUCCESS - $($Script:Results.Maester.Count) tests completed" -ForegroundColor Green
        if ($Script:Results.Maester.SkippedCount -gt 0) {
            Write-Host "                  [!] $($Script:Results.Maester.SkippedCount) tests skipped (missing permissions or licenses)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Config Tests:  [X] FAILED - No results generated" -ForegroundColor Red
    }
    
    # Total Findings
    if ($Script:Results.Consolidated.Count -gt 0) {
        Write-Host "  Total Findings: $($Script:Results.Consolidated.Count) security issues identified" -ForegroundColor Yellow
    } else {
        Write-Host "  Total Findings: No issues found" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "Output Location: $OutputDir" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Generated Files:" -ForegroundColor Yellow
    
    Get-ChildItem -Path $OutputDir -File | ForEach-Object {
        Write-Host "  - $($_.Name)" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Note: Individual assessment tools may open their own reports automatically" -ForegroundColor DarkGray
    Write-Host "      The P1 Summary Report opens separately below" -ForegroundColor DarkGray
    
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Green
    
    # Open P1 summary HTML report if it exists
    $htmlReport = Join-Path $OutputDir "M365_Assessment_Report.html"
    $htmlReport = [System.IO.Path]::GetFullPath($htmlReport)
    
    if (Test-Path $htmlReport) {
        Write-Host "`nOpening P1 Summary Report..." -ForegroundColor Cyan
        try {
            Invoke-Item -Path $htmlReport -ErrorAction Stop
        }
        catch {
            Write-Host "Could not open report automatically. Please open manually:" -ForegroundColor Yellow
            Write-Host "  $htmlReport" -ForegroundColor White
        }
    } else {
        Write-Host "`nP1 Summary Report: $htmlReport" -ForegroundColor Yellow
    }
}

# Main Script Execution
try {
    Clear-Host
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "    PulseOne M365 Security Assessment" -ForegroundColor Cyan
    Write-Host "    Version $Script:Version" -ForegroundColor Gray
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Initialize logging
    Initialize-Logging
    
    # Load or create configuration
    $Script:Config = Import-Configuration -Path $ConfigPath
    
    if (-not (Test-ConfigurationComplete -Config $Script:Config)) {
        if ($SkipConfigPrompt) {
            throw "Configuration incomplete and -SkipConfigPrompt specified. Please run without -SkipConfigPrompt to configure."
        }
        
        Write-Log -Level "WARN" -Message "Configuration incomplete or missing"
        $Script:Config = Invoke-ConfigurationWizard
    }
    else {
        # Config exists - ask if they want to use it or reconfigure
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  Existing Configuration Found" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Display Name:     $($Script:Config.organization.name)" -ForegroundColor White
        Write-Host "Tenant ID:        $($Script:Config.organization.tenantId)" -ForegroundColor White
        Write-Host "Environment:      $($Script:Config.organization.environment)" -ForegroundColor White
        Write-Host "Authentication:   $($Script:Config.authentication.mode)" -ForegroundColor White
        if ($Script:Config.authentication.mode -eq "servicePrincipal") {
            Write-Host "Tenant Domain:    $($Script:Config.authentication.servicePrincipal.organization)" -ForegroundColor White
        }
        Write-Host ""
        Write-Host "Use this configuration or reconfigure?" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[1] Use existing configuration (Run assessment now)" -ForegroundColor Green
        Write-Host "[2] Reconfigure settings (Change tenant, credentials, etc.)" -ForegroundColor White
        Write-Host ""
        $useExisting = Read-Host "Select option [1-2]"
        
        if ($useExisting -eq "2") {
            Write-Log -Level "INFO" -Message "User chose to reconfigure"
            $Script:Config = Invoke-ConfigurationWizard
        }
        else {
            Write-Log -Level "INFO" -Message "Using existing configuration"
        }
    }
    
    # Initialize environment
    Initialize-AssessmentEnvironment
    
    # Install required modules
    Install-RequiredModules
    
    # Run assessments - each in their own try/catch so one failure doesn't stop the others
    if (-not $Script:Config -or -not $Script:Config.organization -or -not $Script:Config.organization.tenantId) {
        throw "Configuration incomplete. Please run configuration wizard first."
    }
    $tenantId = $Script:Config.organization.tenantId
    $orgName = $Script:Config.organization.name
    $environment = $Script:Config.organization.environment
    
    if ($Script:Config.assessment.runScuba) {
        try {
            Invoke-ScubaGearAssessment -TenantId $tenantId -OrgName $orgName -Environment $environment -OutputDir $Script:RunDirectory
        }
        catch {
            Write-Log -Level "ERROR" -Message "Baseline assessment failed: $($_.Exception.Message)"
            Write-Log -Level "WARN" -Message "Continuing with remaining assessments..."
        }
    }
    
    if ($Script:Config.assessment.runMaester) {
        try {
            Invoke-MaesterAssessment -TenantId $tenantId -OutputDir $Script:RunDirectory
        }
        catch {
            Write-Log -Level "ERROR" -Message "Configuration test assessment failed: $($_.Exception.Message)"
            Write-Log -Level "WARN" -Message "Continuing with report generation..."
        }
    }
    
    # Generate consolidated report (even if individual assessments failed)
    try {
        Export-ConsolidatedReport -OutputDir $Script:RunDirectory
    }
    catch {
        Write-Log -Level "ERROR" -Message "Report generation failed: $($_.Exception.Message)"
    }
    
    # Clean up temporary files from output directory
    Write-Log -Level "INFO" -Message "Cleaning up temporary files..."
    Get-ChildItem -Path $Script:RunDirectory -Recurse -Filter "*.Tests.ps1" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path $Script:RunDirectory -Recurse -Filter "*_Run.ps1" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path $Script:RunDirectory -Recurse -Filter "*_Run.wrapper.ps1" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path $Script:RunDirectory -Recurse -Filter "MaesterWorkspace" -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    
    # Show completion
    Show-CompletionSummary -OutputDir $Script:RunDirectory
    
    Write-Log -Level "SUCCESS" -Message "Assessment completed"
    
    # Pause so user can see any error messages
    Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    
    exit 0
}
catch {
    Write-Log -Level "ERROR" -Message "Assessment failed: $($_.Exception.Message)"
    Write-Log -Level "ERROR" -Message "Stack Trace: $($_.ScriptStackTrace)"
    
    # Pause so user can see the error
    Write-Host "`nAn error occurred. Press any key to exit..." -ForegroundColor Red
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    
    exit 1
}

#endregion
