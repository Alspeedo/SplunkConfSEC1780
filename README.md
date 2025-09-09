# Forensics Collection Scripts

Thank you for attending my .conf presentation! This repository contains the scripts and slides from the talk, ready for you to use in your own environments.

## What's Included

**Presentation Materials:**
- Conference slides (uploaded to this repo)

**PowerShell Scripts:**
- **DirectoryInformation.ps1** - Comprehensive file system collection
- **ProcessAndNetworkConnection.ps1** - Running processes and network connections
- **RegistryAndSoftware.ps1** - Registry artifacts and installed software
- **UserActivityCollection.ps1** - User sessions and activity data
- **WindowsEventLogs.ps1** - Windows Event Log collection

**Python Scripts:**
- **windows_eventlog_collection.py** - Simplified event log collection
- **directory_files_collection.py** - Basic file information from common directories

## Quick Start

### 1. Configure Your Environment
Update these settings in each script:

**PowerShell:**
```powershell
$splunkserver = "https://YOUR-SPLUNK-SERVER:8088/services/collector"
$hectoken = "YOUR-HEC-TOKEN-HERE"
$splunkindex = "YOUR-INDEX-NAME"
```

**Python:**
```python
SPLUNK_SERVER = "https://YOUR-SPLUNK-SERVER:8088/services/collector"
HEC_TOKEN = "YOUR-HEC-TOKEN-HERE"
SPLUNK_INDEX = "YOUR-INDEX-NAME"
```

### 2. Python Dependencies
```bash
pip install requests pywin32
```

### 3. Run the Scripts
**PowerShell (run as Administrator):**
```powershell
PowerShell.exe -ExecutionPolicy Bypass -File "WindowsEventLogs.ps1"
```

**Python:**
```bash
python windows_eventlog_collection.py
```

## Script Configuration

All scripts have adjustable settings at the top:

**Batch/Chunk Sizes:**
- Control how much data is sent to Splunk at once
- Adjust delays between batches

**Collection Limits:**
- Maximum events/files to collect
- Time ranges for event logs
- Directory recursion depth

**Data Sources:**
- Which event logs to collect
- Which directories to scan
- Registry keys to examine

## Splunk Searches

Once data is collected, try these searches:

```spl
# All forensic data
index=YOUR-INDEX-NAME

# Recent file activity
index=YOUR-INDEX-NAME sourcetype=DirectoryFiles
| eval days_since_modified=round((now()-strptime(LastModifiedTime,"%Y-%m-%dT%H:%M:%S"))/86400,1)
| where days_since_modified < 7

# Process information
index=YOUR-INDEX-NAME sourcetype=ProcessNetworkData EventType=Process

# Logon events
index=YOUR-INDEX-NAME sourcetype=WinEventLog EventID=4624
```

## Important Notes

**Security:**
- These scripts collect forensic data - use responsibly
- Test in lab environments first
- Scripts bypass SSL verification for lab use

**Performance:**
- Start with smaller limits for initial testing
- Adjust chunk sizes based on your network/Splunk capacity
- Monitor Splunk HEC for any errors

**Permissions:**
- PowerShell scripts require Administrator privileges
- Some data sources may need additional permissions

## Troubleshooting

**Common Issues:**
- **Permission denied:** Run as Administrator
- **Network errors:** Check Splunk HEC endpoint and token
- **No data in Splunk:** Verify index exists and HEC token permissions

**Python-specific:**
- **Module not found:** Install dependencies with pip
- **Win32 errors:** Ensure pywin32 is properly installed

## Use Cases

- **Incident Response:** Rapid artifact collection during security events
- **Baseline Documentation:** Capture normal system state
- **Threat Hunting:** Look for indicators of compromise
- **Compliance:** Document system configurations and access

## Contributing

Feel free to modify these scripts for your environment. Consider sharing improvements that might benefit the community.

## License & Disclaimer

These scripts are provided for educational and legitimate security analysis purposes. Ensure you have proper authorization before running on any systems. Test thoroughly before production use.