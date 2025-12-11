# BusinessNetworkAuditor

Cross-platform IT assessment and dark web monitoring tool for Windows and macOS systems.

## Features

- System information, user accounts, software inventory, security settings
- Server role detection (Domain Controller, DNS, DHCP, File Services)
- Active Directory health and stale account detection
- Dark web breach monitoring for email domains
- Risk-based reporting (HIGH/MEDIUM/LOW/INFO)
- Multi-system aggregation with HTML reports

## Usage

### Local Execution
```bash
# Windows
.\src\WindowsWorkstationAuditor.ps1
.\src\WindowsServerAuditor.ps1

# macOS (admin privileges recommended)
sudo ./src/macOSWorkstationAuditor.sh
```

### Web Deployment
```bash
# Windows
iex (irm https://raw.githubusercontent.com/pulseonetech/BusinessNetworkAuditor/main/WindowsWorkstationAuditor-Web.ps1)
iex (irm https://raw.githubusercontent.com/pulseonetech/BusinessNetworkAuditor/main/WindowsServerAuditor-Web.ps1)

# macOS
curl -s https://raw.githubusercontent.com/pulseonetech/BusinessNetworkAuditor/main/macOSWorkstationAuditor-Web.sh | sudo bash
```

### Dark Web Breach Analysis
```powershell
.\src\DarkWebChecker.ps1 -Domains "client.com,subsidiary.org"
.\src\DarkWebChecker.ps1 -DemoMode
```

### Multi-System Aggregation
```powershell
# Collect JSON files from individual audits
copy output\*_raw_data.json import\

# Generate consolidated HTML report
.\src\NetworkAuditAggregator.ps1 -ClientName "Client Organization"
```

## Examples

See `examples/` directory for sample reports:
- [Windows Workstation](examples/Windows-Workstation-Example-Report.md)
- [Windows Server](examples/Windows-Server-Example-Report.md)
- [macOS Workstation](examples/macOS-Workstation-Example-Report.md)
- [Aggregated HTML Report](examples/Aggregated-Report-Example.html) ([Preview](examples/Aggregated-Report-Screenshot.png))

## Requirements

- **Windows**: 10/11 or Server 2016+, PowerShell 5.0+
- **macOS**: 12+ (Monterey), admin privileges recommended
- **Web versions**: Built with `./Build-WebVersions.ps1`
- **Dark Web Checker**: Internet connectivity, optional API key for enhanced results

## Output

- **Markdown Report**: Technical findings with risk levels and recommendations
- **JSON Export**: Complete data for aggregation and documentation
- **HTML Report**: Client-ready aggregated report (via NetworkAuditAggregator)
- **Dark Web Report**: Domain breach analysis with timeline and impact assessment

## Configuration

Customize settings in configuration files:
- `config/workstation-audit-config.json` - Windows workstation settings
- `config/server-audit-config.json` - Windows server settings
- `config/macos-audit-config.json` - macOS settings
- `config/audit-config.json` - General audit settings
- `config/hibp-api-config.json` - Dark web breach API configuration (optional)

