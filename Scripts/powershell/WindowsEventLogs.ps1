# Simple Windows Event Log to Splunk HEC Script
Write-Host "Starting Windows Event Log Collection..." -ForegroundColor Green

# Configuration
# Configuration - Update these values for your environment
$splunkserver = "https://YOUR-SPLUNK-SERVER:8088/services/collector"
$hectoken = "YOUR-HEC-TOKEN-HERE"
$splunkindex = "YOUR-INDEX-NAME"
$eventLogs = @("Application", "System", "Security")
$hoursBack = 48
$maxEvents = 50000

# Bypass SSL certificate verification
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Setup headers
$headers = @{
    "Authorization" = "Splunk $hectoken"
    "Content-Type" = "application/json"
}

# Get timezone info
$tzinfo = (Get-TimeZone)

Write-Host "Collecting events from the last $hoursBack hours..." -ForegroundColor Yellow

# Collect events from specified logs
$allEvents = @()
$startTime = (Get-Date).AddHours(-$hoursBack)

foreach ($logName in $eventLogs) {
    Write-Host "Collecting from $logName log..." -ForegroundColor Cyan
    
    try {
        $events = Get-WinEvent -LogName $logName -MaxEvents $maxEvents -ErrorAction SilentlyContinue | 
                  Where-Object { $_.TimeCreated -ge $startTime }
        
        if ($events) {
            $allEvents += $events
            Write-Host "Found $($events.Count) events in $logName" -ForegroundColor Green
        }
        else {
            Write-Host "No recent events found in $logName" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Could not access $logName`: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "Total events collected: $($allEvents.Count)" -ForegroundColor Green

if ($allEvents.Count -eq 0) {
    Write-Host "No events to send. Exiting." -ForegroundColor Yellow
    exit
}

# Split events into chunks of 500
$chunks = [System.Collections.ArrayList]::new()
for ($i = 0; $i -lt $allEvents.Count; $i += 500) {
    if (($allEvents.Count - $i) -gt 499) {
        $chunks.add($allEvents[$i..($i + 499)])
    }
    else {
        $chunks.add($allEvents[$i..($allEvents.Count - 1)])
    }
}

Write-Host "Sending events to Splunk in $($chunks.Count) chunks..." -ForegroundColor Yellow

$count = 1
$totalSuccess = 0
$totalErrors = 0

foreach ($chunk in $chunks) {
    $newbody = ''
    
    $chunk | ForEach-Object {
        # Create event object properly to avoid JSON escaping issues
        $eventObject = @{
            'EventID' = $_.Id
            'Level' = $_.LevelDisplayName
            'LogName' = $_.LogName
            'TimeCreated' = $_.TimeCreated.ToString()
            'TimeZone' = $tzinfo.ToString()
            'MachineName' = $_.MachineName
            'ProcessId' = $_.ProcessId
            'ThreadId' = $_.ThreadId
            'ProviderName' = $_.ProviderName
            'Message' = $_.Message
            'RecordId' = $_.RecordId
        }
        
        # Create the complete HEC event structure
        $hecEvent = @{
            "host" = $env:COMPUTERNAME
            "sourcetype" = "WinEventLog"
            "source" = $_.LogName
            "index" = $splunkindex
            "event" = $eventObject
        }
        
        # Convert to JSON and add to body
        $eventJson = $hecEvent | ConvertTo-Json -Compress -Depth 3
        $newbody += $eventJson
    }
    
    Write-Host "Sending chunk $count of $($chunks.Count)..." -ForegroundColor Cyan
    
    try {
        $response = Invoke-RestMethod -Uri $splunkserver -Method Post -Headers $headers -Body $newbody -UseBasicParsing
        Write-Host "Chunk $count sent successfully" -ForegroundColor Green
        $totalSuccess += $chunk.Count
    }
    catch {
        Write-Host "Error sending chunk $count`: $($_.Exception.Message)" -ForegroundColor Red
        $totalErrors += $chunk.Count
    }
    
    $count++
    Start-Sleep -Seconds .25  # Small delay between chunks
}

Write-Host "`nCompleted!" -ForegroundColor Green
Write-Host "Successfully sent: $totalSuccess events" -ForegroundColor Green
Write-Host "Failed to send: $totalErrors events" -ForegroundColor Red