# Process and Network Connection Collection Script
Write-Host "Starting Process and Network Connection Collection..." -ForegroundColor Green

# Configuration
$splunkserver = "https://YOUR-SPLUNK-SERVER:8088/services/collector"
$hectoken = "YOUR-HEC-TOKEN-HERE"
$splunkindex = "YOUR-INDEX-NAME"

# Bypass SSL certificate verification
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Setup headers
$headers = @{
    "Authorization" = "Splunk $hectoken"
    "Content-Type" = "application/json"
}

$tzinfo = (Get-TimeZone)
$allEvents = @()

Write-Host "Collecting running processes..." -ForegroundColor Yellow

# Get detailed process information - simplified approach
$processes = @()
try {
    Write-Host "  Getting WMI process data..." -ForegroundColor Gray
    $rawProcesses = @(Get-WmiObject Win32_Process -ErrorAction Stop)
    Write-Host "  Processing $($rawProcesses.Count) processes..." -ForegroundColor Gray
    
    $processCount = 0
    for ($i = 0; $i -lt $rawProcesses.Count; $i++) {
        $proc = $rawProcesses[$i]
        try {
            $owner = $proc.GetOwner()
            
            # Create object and add to array without output
            $null = $processes += [PSCustomObject]@{
                ProcessId = $proc.ProcessId
                ProcessName = $proc.Name
                CommandLine = if($proc.CommandLine) { $proc.CommandLine } else { "N/A" }
                ExecutablePath = if($proc.ExecutablePath) { $proc.ExecutablePath } else { "N/A" }
                ParentProcessId = $proc.ParentProcessId
                CreationDate = if($proc.CreationDate) { [int64]([DateTimeOffset]([Management.ManagementDateTimeConverter]::ToDateTime($proc.CreationDate))).ToUnixTimeSeconds() } else { $null }
                Owner = if($owner.User) { "$($owner.Domain)\$($owner.User)" } else { "Unknown" }
                WorkingSetSize = $proc.WorkingSetSize
                VirtualSize = $proc.VirtualSize
                PageFileUsage = $proc.PageFileUsage
                HandleCount = $proc.HandleCount
                ThreadCount = $proc.ThreadCount
                Priority = $proc.Priority
                EventType = "Process"
            }
            
            $processCount++
            if ($processCount % 100 -eq 0) {
                Write-Host "    Processed $processCount/$($rawProcesses.Count) processes..." -ForegroundColor Gray
            }
        }
        catch {
            continue
        }
    }
}
catch {
    Write-Host "  WMI failed, using Get-Process fallback..." -ForegroundColor Yellow
    try {
        $fallbackProcesses = @(Get-Process -ErrorAction Stop)
        for ($i = 0; $i -lt $fallbackProcesses.Count; $i++) {
            $p = $fallbackProcesses[$i]
            try {
                $null = $processes += [PSCustomObject]@{
                    ProcessId = $p.Id
                    ProcessName = $p.ProcessName
                    CommandLine = "N/A"
                    ExecutablePath = if($p.Path) { $p.Path } else { "N/A" }
                    ParentProcessId = "Unknown"
                    CreationDate = if($p.StartTime) { [int64]([DateTimeOffset]$p.StartTime).ToUnixTimeSeconds() } else { $null }
                    Owner = "Unknown"
                    WorkingSetSize = $p.WorkingSet64
                    VirtualSize = $p.VirtualMemorySize64
                    PageFileUsage = $p.PagedMemorySize64
                    HandleCount = $p.HandleCount
                    ThreadCount = $p.Threads.Count
                    Priority = $p.BasePriority
                    EventType = "Process"
                }
            }
            catch {
                continue
            }
        }
    }
    catch {
        Write-Host "  Both process collection methods failed!" -ForegroundColor Red
        $processes = @()
    }
}

# Add processes to main events array
$allEvents += $processes
Write-Host "Successfully collected $($processes.Count) processes" -ForegroundColor Green

Write-Host "Collecting network connections..." -ForegroundColor Yellow

# Get TCP connections
$connections = @()
try {
    Write-Host "  Getting TCP connections..." -ForegroundColor Gray
    $tcpConnections = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
    
    for ($i = 0; $i -lt $tcpConnections.Count; $i++) {
        $conn = $tcpConnections[$i]
        try {
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $null = $connections += [PSCustomObject]@{
                LocalAddress = $conn.LocalAddress
                LocalPort = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                State = $conn.State.ToString()
                ProcessId = $conn.OwningProcess
                ProcessName = if($process) { $process.ProcessName } else { "Unknown" }
                Protocol = "TCP"
                CreationTime = if($conn.CreationTime -and $conn.CreationTime -ne [DateTime]::MinValue) { [int64]([DateTimeOffset]$conn.CreationTime).ToUnixTimeSeconds() } else { $null }
                EventType = "NetworkConnection"
            }
        }
        catch {
            continue
        }
    }
    Write-Host "    Found $($connections.Count) TCP connections" -ForegroundColor Gray
}
catch {
    Write-Host "    TCP collection failed" -ForegroundColor Red
}

# Get UDP endpoints
try {
    Write-Host "  Getting UDP endpoints..." -ForegroundColor Gray
    $udpEndpoints = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)
    
    for ($i = 0; $i -lt $udpEndpoints.Count; $i++) {
        $udp = $udpEndpoints[$i]
        try {
            $process = Get-Process -Id $udp.OwningProcess -ErrorAction SilentlyContinue
            $null = $connections += [PSCustomObject]@{
                LocalAddress = $udp.LocalAddress
                LocalPort = $udp.LocalPort
                RemoteAddress = "N/A"
                RemotePort = "N/A"
                State = "Listening"
                ProcessId = $udp.OwningProcess
                ProcessName = if($process) { $process.ProcessName } else { "Unknown" }
                Protocol = "UDP"
                CreationTime = if($udp.CreationTime -and $udp.CreationTime -ne [DateTime]::MinValue) { [int64]([DateTimeOffset]$udp.CreationTime).ToUnixTimeSeconds() } else { $null }
                EventType = "NetworkConnection"
            }
        }
        catch {
            continue
        }
    }
    Write-Host "    Found $($udpEndpoints.Count) UDP endpoints" -ForegroundColor Gray
}
catch {
    Write-Host "    UDP collection failed" -ForegroundColor Red
}

# Add connections to main events array
$allEvents += $connections
Write-Host "Successfully collected $($connections.Count) total network connections" -ForegroundColor Green

Write-Host "Collecting loaded modules (limited)..." -ForegroundColor Yellow

# Get loaded modules for suspicious processes only - very limited
$suspiciousProcesses = $processes | Where-Object { 
    $_.ProcessName -match "powershell|cmd" 
} | Select-Object -First 3

Write-Host "  Analyzing $($suspiciousProcesses.Count) suspicious processes..." -ForegroundColor Gray

$moduleCount = 0
foreach ($proc in $suspiciousProcesses) {
    try {
        $modules = @(Get-Process -Id $proc.ProcessId -Module -ErrorAction SilentlyContinue | Select-Object -First 20)
        foreach ($module in $modules) {
            try {
                $null = $allEvents += [PSCustomObject]@{
                    ProcessId = $proc.ProcessId
                    ProcessName = $proc.ProcessName
                    ModuleName = $module.ModuleName
                    FileName = if($module.FileName) { $module.FileName } else { "Unknown" }
                    BaseAddress = if($module.BaseAddress) { $module.BaseAddress.ToString() } else { "Unknown" }
                    ModuleMemorySize = $module.ModuleMemorySize
                    FileVersion = if($module.FileVersion) { $module.FileVersion } else { "Unknown" }
                    EventType = "LoadedModule"
                }
                $moduleCount++
            }
            catch {
                continue
            }
        }
    }
    catch {
        continue
    }
}

Write-Host "Successfully collected $moduleCount loaded modules" -ForegroundColor Green
Write-Host "Total events collected: $($allEvents.Count)" -ForegroundColor Green

if ($allEvents.Count -eq 0) {
    Write-Host "No events found. Exiting." -ForegroundColor Yellow
    exit
}

# Split into chunks
$chunkSize = 200  # Smaller chunks
$chunks = [System.Collections.ArrayList]::new()
for ($i = 0; $i -lt $allEvents.Count; $i += $chunkSize) {
    if (($allEvents.Count - $i) -gt ($chunkSize - 1)) {
        $null = $chunks.add($allEvents[$i..($i + $chunkSize - 1)])
    }
    else {
        $null = $chunks.add($allEvents[$i..($allEvents.Count - 1)])
    }
}

Write-Host "Sending data to Splunk in $($chunks.Count) chunks..." -ForegroundColor Yellow

$count = 1
$totalSuccess = 0
$totalErrors = 0

foreach ($chunk in $chunks) {
    $newbody = ''
    
    foreach ($event in $chunk) {
        try {
            # Add timezone and collection timestamp
            $currentEpoch = [int64]([DateTimeOffset](Get-Date)).ToUnixTimeSeconds()
            $event | Add-Member -NotePropertyName "TimeZone" -NotePropertyValue $tzinfo.ToString() -Force
            $event | Add-Member -NotePropertyName "CollectionTime" -NotePropertyValue $currentEpoch -Force
            
            # Convert any remaining DateTime properties to epoch
            foreach ($prop in $event.PSObject.Properties) {
                if ($prop.Value -is [DateTime] -and $prop.Value -ne [DateTime]::MinValue) {
                    try {
                        $prop.Value = [int64]([DateTimeOffset]$prop.Value).ToUnixTimeSeconds()
                    }
                    catch {
                        $prop.Value = $null
                    }
                }
                elseif ($prop.Value -is [string] -and $prop.Value.Length -gt 0) {
                    # Clean problematic characters
                    $cleanValue = $prop.Value -replace '[^\x20-\x7E]', ''
                    $cleanValue = $cleanValue -replace '"', '\"'
                    $cleanValue = $cleanValue -replace '\\', '\\'
                    $prop.Value = $cleanValue
                }
            }
            
            # Create HEC event
            $hecEvent = @{
                "host" = $env:COMPUTERNAME
                "sourcetype" = "ProcessNetworkData"
                "source" = $event.EventType
                "index" = $splunkindex
                "event" = $event
            }
            
            $eventJson = $hecEvent | ConvertTo-Json -Compress -Depth 4
            $newbody += $eventJson + "`n"
        }
        catch {
            Write-Host "Error processing event: $($_.Exception.Message)" -ForegroundColor Yellow
            continue
        }
    }
    
    Write-Host "Sending chunk $count of $($chunks.Count) ($(($newbody.Length/1KB).ToString('N1')) KB)..." -ForegroundColor Cyan
    
    try {
        $response = Invoke-RestMethod -Uri $splunkserver -Method Post -Headers $headers -Body $newbody -UseBasicParsing
        Write-Host "Chunk $count sent successfully" -ForegroundColor Green
        $totalSuccess += $chunk.Count
    }
    catch {
        Write-Host "Error sending chunk $count`: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.Response) {
            $streamReader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $responseContent = $streamReader.ReadToEnd()
            Write-Host "Response: $responseContent" -ForegroundColor Red
            $streamReader.Close()
        }
        $totalErrors += $chunk.Count
    }
    
    $count++
    Start-Sleep -Seconds 1
}

Write-Host "`nProcess and Network Collection Completed!" -ForegroundColor Green
Write-Host "Successfully sent: $totalSuccess events" -ForegroundColor Green
Write-Host "Failed to send: $totalErrors events" -ForegroundColor Red