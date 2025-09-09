# PowerShell Forensics Collection Scripts

A collection of PowerShell scripts designed to gather forensic artifacts from Windows systems and send them to Splunk via HTTP Event Collector (HEC). These scripts were presented at Splunk .conf and are intended for security professionals, incident responders, and forensic analysts.

## Scripts Overview

### 1. DirectoryInformation.ps1
Collects comprehensive file system information including:
- User profile directories (Desktop, Downloads, Documents, Pictures, etc.)
- System directories (Temp folders, Public directories)
- File metadata (creation time, modification time, file hashes)
- File attributes and ownership information

### 2. ProcessAndNetworkConnection.ps1
Gathers running process and network connection data:
- Detailed process information (command line, executable path, owner)
- Active TCP connections and UDP endpoints
- Process-to-network connection mapping
- Limited loaded module information for suspicious processes

### 3. RegistryAndSoftware.ps1
Extracts registry artifacts and persistence mechanisms:
- Autostart locations (Run keys, services)
- Recently accessed files and URLs
- USB device history
- Installed software inventory
- MRU (Most Recently Used) lists

### 4. UserActivityCollection.ps1
Captures user activity and session information:
- Current logon sessions
- User profiles and recent logon events
- Scheduled tasks and startup programs
- Recent file access patterns
- Jump list data

### 5. WindowsEventLogs.ps1
Collects Windows Event Log data:
- Application, System, and Security logs
- Configurable time range (default: 48 hours)
- Structured event data with metadata

## Prerequisites

### Splunk Environment
- Splunk Enterprise or Splunk Cloud with HEC enabled
- HTTP Event Collector token with appropriate permissions
- Recommended index: `security_forensics` (or modify scripts for your index)

### PowerShell Requirements
- PowerShell 5.1 or later
- Administrative privileges (required for some data collection)
- Execution policy allowing script execution

### Network Requirements
- Network connectivity to Splunk HEC endpoint
- HTTPS connectivity (scripts bypass SSL certificate validation)

## Setup Instructions

### 1. Configure Splunk HEC
```bash
# In Splunk Web UI:
# Settings > Data Inputs > HTTP Event Collector
# Create new token with permissions for your target index
```

### 2. Update Script Configuration
Edit the configuration section in each script:

```powershell
# Update these values for your environment
$splunkserver = "https://YOUR-SPLUNK-SERVER:8088/services/collector"
$hectoken = "YOUR-HEC-TOKEN-HERE"
```

### 3. Optional: Customize Collection Parameters
Each script includes configurable parameters at the top:

**DirectoryInformation.ps1:**
- `$maxDepth` - Directory recursion depth (default: 5)
- `$maxFilesPerDir` - Maximum files per directory (default: 15,000)
- `$maxSystemFiles` - Maximum system files (default: 2,500)

**WindowsEventLogs.ps1:**
- `$hoursBack` - Time range for event collection (default: 48)
- `$maxEvents` - Maximum events per log (default: 50,000)

## Usage

### Single Script Execution
```powershell
# Run with administrative privileges
PowerShell.exe -ExecutionPolicy Bypass -File "DirectoryInformation.ps1"
```

### Batch Execution
```powershell
# Execute all scripts sequentially
$scripts = @(
    "WindowsEventLogs.ps1",
    "ProcessAndNetworkConnection.ps1", 
    "RegistryAndSoftware.ps1",
    "UserActivityCollection.ps1",
    "DirectoryInformation.ps1"
)

foreach ($script in $scripts) {
    Write-Host "Executing $script..." -ForegroundColor Green
    PowerShell.exe -ExecutionPolicy Bypass -File $script
    Start-Sleep -Seconds 30  # Pause between scripts
}
```

## Data Output

### Splunk Sourcetypes
- `WinEventLog` - Windows Event Log data
- `ProcessNetworkData` - Process and network information
- `RegistryForensics` - Registry artifacts
- `UserActivity` - User activity data
- `DirectoryFiles` - File system information

### Sample Splunk Searches
```spl
# Search all forensic data
index=security_forensics

# Find suspicious processes
index=security_forensics sourcetype=ProcessNetworkData EventType=Process 
| search ProcessName="powershell.exe" OR ProcessName="cmd.exe"

# Review autostart persistence
index=security_forensics sourcetype=RegistryForensics 
| search RegistryKey="AutoStart*"

# Analyze recent file access
index=security_forensics sourcetype=DirectoryFiles 
| eval LastAccessDays=round((now()-LastAccessTime)/86400,1)
| where LastAccessDays < 7
```

## Performance Considerations

### Resource Usage
- Scripts implement chunked data transmission to prevent timeouts
- Memory usage is optimized through streaming processing
- Built-in delays prevent overwhelming target systems

### Collection Limits
- File collection limits prevent excessive data volume
- Registry queries are scoped to relevant keys
- Event log collection includes time-based filtering

## Security Notes

### Data Sensitivity
These scripts collect potentially sensitive forensic data including:
- File system metadata and hashes
- Process command lines and network connections
- Registry artifacts and user activity
- System event logs

### Network Security
- Scripts bypass SSL certificate validation for lab environments
- Consider implementing proper certificate validation for production
- HEC tokens should follow principle of least privilege

## Troubleshooting

### Common Issues

**Permission Denied Errors:**
- Run PowerShell as Administrator
- Verify script execution policy allows execution

**Network Connectivity:**
- Test HEC endpoint connectivity: `Test-NetConnection -ComputerName YOUR-SPLUNK-SERVER -Port 8088`
- Verify firewall rules allow outbound HTTPS

**Data Not Appearing in Splunk:**
- Check HEC token permissions
- Verify index exists and is accessible
- Review Splunk internal logs for HEC errors

### Debug Mode
Add verbose output by uncommenting debug lines in scripts or adding:
```powershell
$VerbosePreference = "Continue"
```

## Use Cases

### Incident Response
- Rapid collection of forensic artifacts during security incidents
- Baseline system state documentation
- IOC hunting and threat analysis

### Compliance and Auditing
- Software inventory and configuration assessment
- User activity monitoring
- System access logging

### Threat Hunting
- Process analysis and network connection review
- Persistence mechanism detection
- File system timeline analysis

## Contributing

Contributions are welcome! Please consider:
- Testing scripts in lab environments before production use
- Documenting any modifications or enhancements
- Following PowerShell best practices and security guidelines

## License

These scripts are provided as-is for educational and professional use. Please review and test thoroughly before deploying in production environments.

## Disclaimer

These forensic collection scripts are intended for legitimate security analysis on systems you own or have explicit permission to analyze. Users are responsible for ensuring compliance with applicable laws and organizational policies.
