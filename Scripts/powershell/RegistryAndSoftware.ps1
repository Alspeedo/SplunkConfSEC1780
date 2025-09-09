# Registry and Persistence Mechanism Collection Script
Write-Host "Starting Registry and Persistence Collection..." -ForegroundColor Green

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

# Define registry keys of interest for persistence and forensics
$registryKeys = @{
    "AutoStart_CurrentUser_Run" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    "AutoStart_CurrentUser_RunOnce" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    "AutoStart_LocalMachine_Run" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    "AutoStart_LocalMachine_RunOnce" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    "AutoStart_Winlogon" = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    "RecentDocs" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    "TypedURLs" = "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs"
    "WordWheelQuery" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
    "ComDlg32_OpenSaveMRU" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU"
    "ComDlg32_LastVisited" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"
    "USBStor" = "HKLM:\System\CurrentControlSet\Enum\USBSTOR"
    "MountedDevices" = "HKLM:\System\MountedDevices"
    "NetworkCards" = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards"
}

Write-Host "Collecting registry artifacts..." -ForegroundColor Yellow

foreach ($keyName in $registryKeys.Keys) {
    $keyPath = $registryKeys[$keyName]
    Write-Host "Processing: $keyName" -ForegroundColor Cyan
    
    try {
        if (Test-Path $keyPath) {
            # Standard registry key processing
            try {
                $props = Get-ItemProperty $keyPath -ErrorAction SilentlyContinue
                foreach ($prop in $props.PSObject.Properties) {
                    if ($prop.Name -notmatch "^PS") {
                        $lastWriteTime = $null
                        try {
                            $item = Get-Item $keyPath -ErrorAction SilentlyContinue
                            if ($item -and $item.LastWriteTime -and $item.LastWriteTime -ne [DateTime]::MinValue) {
                                $lastWriteTime = [int64]([DateTimeOffset]$item.LastWriteTime).ToUnixTimeSeconds()
                            }
                        }
                        catch { }
                        
                        $null = $allEvents += [PSCustomObject]@{
                            RegistryKey = $keyName
                            ValueName = $prop.Name
                            ValueData = if($prop.Value) { $prop.Value.ToString() } else { "" }
                            ValueType = if($prop.TypeNameOfValue) { $prop.TypeNameOfValue } else { "Unknown" }
                            LastModified = $lastWriteTime
                            EventType = "RegistryArtifact"
                        }
                    }
                }
            }
            catch { 
                Write-Host "    Error reading properties for $keyName" -ForegroundColor Yellow
            }
            
            # Get subkeys for MRU lists and similar
            if ($keyName -match "MRU|RecentDocs|TypedURLs|USBStor") {
                try {
                    $subKeys = @(Get-ChildItem $keyPath -ErrorAction SilentlyContinue | Select-Object -First 50)
                    foreach ($subKey in $subKeys) {
                        try {
                            $subProps = Get-ItemProperty $subKey.PSPath -ErrorAction SilentlyContinue
                            foreach ($prop in $subProps.PSObject.Properties) {
                                if ($prop.Name -notmatch "^PS") {
                                    $subLastWriteTime = $null
                                    if ($subKey.LastWriteTime -and $subKey.LastWriteTime -ne [DateTime]::MinValue) {
                                        $subLastWriteTime = [int64]([DateTimeOffset]$subKey.LastWriteTime).ToUnixTimeSeconds()
                                    }
                                    
                                    $null = $allEvents += [PSCustomObject]@{
                                        RegistryKey = "$keyName\$($subKey.PSChildName)"
                                        ValueName = $prop.Name
                                        ValueData = if($prop.Value) { $prop.Value.ToString() } else { "" }
                                        ValueType = if($prop.TypeNameOfValue) { $prop.TypeNameOfValue } else { "Unknown" }
                                        LastModified = $subLastWriteTime
                                        EventType = "RegistryArtifact"
                                    }
                                }
                            }
                        }
                        catch {
                            continue
                        }
                    }
                }
                catch { 
                    Write-Host "    Error reading subkeys for $keyName" -ForegroundColor Yellow
                }
            }
            
            Write-Host "    Processed $keyName successfully" -ForegroundColor Green
        }
        else {
            Write-Host "    Registry key not found: $keyPath" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "    Error processing $keyName`: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Collect services with limited scope
Write-Host "Collecting autostart services..." -ForegroundColor Yellow
try {
    $servicesPath = "HKLM:\System\CurrentControlSet\Services"
    if (Test-Path $servicesPath) {
        $services = @(Get-ChildItem $servicesPath -ErrorAction SilentlyContinue | 
                     Where-Object { 
                         $serviceProps = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                         $serviceProps.Start -eq 2 -or $serviceProps.Start -eq 3  # Automatic or Manual start
                     } | Select-Object -First 100)  # Limit to prevent overload
        
        foreach ($service in $services) {
            try {
                $serviceProps = Get-ItemProperty $service.PSPath -ErrorAction SilentlyContinue
                $serviceLastWriteTime = $null
                if ($service.LastWriteTime -and $service.LastWriteTime -ne [DateTime]::MinValue) {
                    $serviceLastWriteTime = [int64]([DateTimeOffset]$service.LastWriteTime).ToUnixTimeSeconds()
                }
                
                $null = $allEvents += [PSCustomObject]@{
                    RegistryKey = "AutoStart_Services"
                    ServiceName = $service.PSChildName
                    DisplayName = if($serviceProps.DisplayName) { $serviceProps.DisplayName } else { "Unknown" }
                    ImagePath = if($serviceProps.ImagePath) { $serviceProps.ImagePath } else { "Unknown" }
                    StartType = if($serviceProps.Start) { $serviceProps.Start } else { "Unknown" }
                    ServiceType = if($serviceProps.Type) { $serviceProps.Type } else { "Unknown" }
                    Description = if($serviceProps.Description) { $serviceProps.Description } else { "Unknown" }
                    LastModified = $serviceLastWriteTime
                    EventType = "RegistryArtifact"
                }
            }
            catch {
                continue
            }
        }
        Write-Host "    Processed $($services.Count) services" -ForegroundColor Green
    }
}
catch {
    Write-Host "    Error collecting services: $($_.Exception.Message)" -ForegroundColor Red
}

# Collect installed software
Write-Host "Collecting installed software..." -ForegroundColor Yellow
$installedSoftware = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($path in $installedSoftware) {
    try {
        $softwareItems = @(Get-ItemProperty $path -ErrorAction SilentlyContinue | 
                          Where-Object { $_.DisplayName } | 
                          Select-Object -First 200)  # Limit software entries
        
        foreach ($item in $softwareItems) {
            $null = $allEvents += [PSCustomObject]@{
                RegistryKey = "InstalledSoftware"
                DisplayName = if($item.DisplayName) { $item.DisplayName } else { "Unknown" }
                DisplayVersion = if($item.DisplayVersion) { $item.DisplayVersion } else { "Unknown" }
                Publisher = if($item.Publisher) { $item.Publisher } else { "Unknown" }
                InstallDate = if($item.InstallDate) { $item.InstallDate } else { "Unknown" }
                InstallLocation = if($item.InstallLocation) { $item.InstallLocation } else { "Unknown" }
                UninstallString = if($item.UninstallString) { $item.UninstallString } else { "Unknown" }
                Size = if($item.EstimatedSize) { $item.EstimatedSize } else { 0 }
                EventType = "InstalledSoftware"
            }
        }
        Write-Host "    Found $($softwareItems.Count) software items in $(Split-Path $path -Leaf)" -ForegroundColor Green
    }
    catch { 
        Write-Host "    Error reading software from $path" -ForegroundColor Yellow
    }
}

Write-Host "Total registry artifacts collected: $($allEvents.Count)" -ForegroundColor Green

if ($allEvents.Count -eq 0) {
    Write-Host "No registry data found. Exiting." -ForegroundColor Yellow
    exit
}

# Split into chunks
$chunkSize = 300  # Smaller chunks for registry data
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
            
            # Convert any DateTime properties to epoch before JSON serialization
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
                    # Clean problematic characters from string fields
                    $cleanValue = $prop.Value -replace '[^\x20-\x7E]', ''
                    $cleanValue = $cleanValue -replace '"', '\"'
                    $cleanValue = $cleanValue -replace '\\', '\\'
                    $prop.Value = $cleanValue
                }
            }
            
            # Create proper HEC event structure
            $hecEvent = @{
                "host" = $env:COMPUTERNAME
                "sourcetype" = "RegistryForensics"
                "source" = $event.EventType
                "index" = $splunkindex
                "event" = $event
            }
            
            # Convert to JSON and add to body
            $eventJson = $hecEvent | ConvertTo-Json -Compress -Depth 4
            $newbody += $eventJson + "`n"
        }
        catch {
            Write-Host "Error processing registry event: $($_.Exception.Message)" -ForegroundColor Yellow
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
            try {
                $streamReader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $responseContent = $streamReader.ReadToEnd()
                Write-Host "Response: $responseContent" -ForegroundColor Red
                $streamReader.Close()
            }
            catch { }
        }
        $totalErrors += $chunk.Count
    }
    
    $count++
    Start-Sleep -Seconds 1
}

Write-Host "`nRegistry Collection Completed!" -ForegroundColor Green
Write-Host "Successfully sent: $totalSuccess events" -ForegroundColor Green
Write-Host "Failed to send: $totalErrors events" -ForegroundColor Red