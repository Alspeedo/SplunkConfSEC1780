# User Activity and Logon Session Collection Script
Write-Host "Starting User Activity Collection..." -ForegroundColor Green

# Configuration - Update these values for your environment
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

Write-Host "Collecting current user sessions..." -ForegroundColor Yellow

# Get current logged on users
try {
    $loggedOnUsers = Get-WmiObject Win32_LoggedOnUser | ForEach-Object {
        $user = [WMI]$_.Antecedent
        $session = [WMI]$_.Dependent
        [PSCustomObject]@{
            Username = $user.Name
            Domain = $user.Domain
            LogonId = $session.LogonId
            LogonType = $session.LogonType
            StartTime = $session.StartTime
            AuthenticationPackage = $session.AuthenticationPackage
            EventType = "CurrentSession"
        }
    }
    $allEvents += $loggedOnUsers
    Write-Host "Found $($loggedOnUsers.Count) current user sessions" -ForegroundColor Green
}
catch {
    Write-Host "Error collecting user sessions: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Collecting user profiles..." -ForegroundColor Yellow

# Get user profiles
try {
    $userProfiles = Get-WmiObject Win32_UserProfile | Where-Object { -not $_.Special } | ForEach-Object {
        try {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($_.SID)
            $username = $sid.Translate([System.Security.Principal.NTAccount]).Value
        }
        catch {
            $username = "Unknown"
        }
        
        [PSCustomObject]@{
            SID = $_.SID
            Username = $username
            LocalPath = $_.LocalPath
            LastUseTime = if($_.LastUseTime) { [Management.ManagementDateTimeConverter]::ToDateTime($_.LastUseTime) } else { $null }
            Loaded = $_.Loaded
            RoamingConfigured = $_.RoamingConfigured
            RoamingPath = $_.RoamingPath
            RoamingPreference = $_.RoamingPreference
            EventType = "UserProfile"
        }
    }
    $allEvents += $userProfiles
    Write-Host "Found $($userProfiles.Count) user profiles" -ForegroundColor Green
}
catch {
    Write-Host "Error collecting user profiles: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Collecting recent logon events..." -ForegroundColor Yellow

# Get recent logon/logoff events from Security log
try {
    $logonEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625,4634,4647,4648; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 1000 -ErrorAction SilentlyContinue
    
    foreach ($event in $logonEvents) {
        $eventXml = [xml]$event.ToXml()
        $eventData = @{}
        
        foreach ($data in $eventXml.Event.EventData.Data) {
            $eventData[$data.Name] = $data.'#text'
        }
        
        $logonEvent = [PSCustomObject]@{
            TimeCreated = $event.TimeCreated
            EventID = $event.Id
            LogonType = $eventData.LogonType
            TargetUserName = $eventData.TargetUserName
            TargetDomainName = $eventData.TargetDomainName
            SubjectUserName = $eventData.SubjectUserName
            SubjectDomainName = $eventData.SubjectDomainName
            WorkstationName = $eventData.WorkstationName
            IpAddress = $eventData.IpAddress
            IpPort = $eventData.IpPort
            LogonProcessName = $eventData.LogonProcessName
            AuthenticationPackageName = $eventData.AuthenticationPackageName
            FailureReason = $eventData.FailureReason
            Status = $eventData.Status
            SubStatus = $eventData.SubStatus
            EventType = "LogonEvent"
        }
        $allEvents += $logonEvent
    }
    Write-Host "Found $($logonEvents.Count) recent logon events" -ForegroundColor Green
}
catch {
    Write-Host "Error collecting logon events: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Collecting scheduled tasks..." -ForegroundColor Yellow

# Get scheduled tasks
try {
    $scheduledTasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
        $taskInfo = Get-ScheduledTaskInfo $_.TaskName -ErrorAction SilentlyContinue
        $actions = ($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; "
        
        [PSCustomObject]@{
            TaskName = $_.TaskName
            TaskPath = $_.TaskPath
            State = $_.State
            Author = $_.Author
            Description = $_.Description
            Actions = $actions
            LastRunTime = if($taskInfo) { $taskInfo.LastRunTime } else { $null }
            NextRunTime = if($taskInfo) { $taskInfo.NextRunTime } else { $null }
            LastTaskResult = if($taskInfo) { $taskInfo.LastTaskResult } else { $null }
            NumberOfMissedRuns = if($taskInfo) { $taskInfo.NumberOfMissedRuns } else { $null }
            EventType = "ScheduledTask"
        }
    }
    $allEvents += $scheduledTasks
    Write-Host "Found $($scheduledTasks.Count) scheduled tasks" -ForegroundColor Green
}
catch {
    Write-Host "Error collecting scheduled tasks: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Collecting startup programs..." -ForegroundColor Yellow

# Get startup programs from multiple sources
$startupLocations = @(
    @{Path = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"; Type = "UserStartup"},
    @{Path = "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"; Type = "AllUsersStartup"},
    @{Path = "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Startup"; Type = "ProgramDataStartup"}
)

foreach ($location in $startupLocations) {
    if (Test-Path $location.Path) {
        Get-ChildItem $location.Path -ErrorAction SilentlyContinue | ForEach-Object {
            $startupItem = [PSCustomObject]@{
                Name = $_.Name
                FullPath = $_.FullName
                CreationTime = $_.CreationTime
                LastWriteTime = $_.LastWriteTime
                Size = $_.Length
                StartupType = $location.Type
                EventType = "StartupProgram"
            }
            $allEvents += $startupItem
        }
    }
}

Write-Host "Collecting recent file access..." -ForegroundColor Yellow

# Get recent files from common locations
$recentLocations = @(
    "$env:APPDATA\Microsoft\Windows\Recent",
    "$env:APPDATA\Microsoft\Office\Recent"
)

foreach ($location in $recentLocations) {
    if (Test-Path $location) {
        Get-ChildItem $location -ErrorAction SilentlyContinue | ForEach-Object {
            # For .lnk files, try to get target
            $target = $_.FullName
            if ($_.Extension -eq ".lnk") {
                try {
                    $shell = New-Object -ComObject WScript.Shell
                    $shortcut = $shell.CreateShortcut($_.FullName)
                    $target = $shortcut.TargetPath
                }
                catch {
                    $target = "Unable to resolve"
                }
            }
            
            $recentFile = [PSCustomObject]@{
                Name = $_.Name
                FullPath = $_.FullName
                TargetPath = $target
                CreationTime = $_.CreationTime
                LastAccessTime = $_.LastAccessTime
                LastWriteTime = $_.LastWriteTime
                Size = $_.Length
                RecentLocation = $location
                EventType = "RecentFile"
            }
            $allEvents += $recentFile
        }
    }
}

Write-Host "Collecting jump list data..." -ForegroundColor Yellow

# Get jump list files
$jumpListPath = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
if (Test-Path $jumpListPath) {
    Get-ChildItem $jumpListPath -Filter "*.automaticDestinations-ms" -ErrorAction SilentlyContinue | ForEach-Object {
        $jumpList = [PSCustomObject]@{
            Name = $_.Name
            FullPath = $_.FullName
            CreationTime = $_.CreationTime
            LastAccessTime = $_.LastAccessTime
            LastWriteTime = $_.LastWriteTime
            Size = $_.Length
            EventType = "JumpList"
        }
        $allEvents += $jumpList
    }
}

Write-Host "Total user activity events collected: $($allEvents.Count)" -ForegroundColor Green

if ($allEvents.Count -eq 0) {
    Write-Host "No events found. Exiting." -ForegroundColor Yellow
    exit
}

# Split into chunks
$chunkSize = 1000
$chunks = [System.Collections.ArrayList]::new()
for ($i = 0; $i -lt $allEvents.Count; $i += $chunkSize) {
    if (($allEvents.Count - $i) -gt ($chunkSize - 1)) {
        $chunks.add($allEvents[$i..($i + $chunkSize - 1)])
    }
    else {
        $chunks.add($allEvents[$i..($allEvents.Count - 1)])
    }
}

Write-Host "Sending data to Splunk in $($chunks.Count) chunks..." -ForegroundColor Yellow

$count = 1
$totalSuccess = 0
$totalErrors = 0

foreach ($chunk in $chunks) {
    $newbody = ''
    
    $chunk | ForEach-Object {
        try {
            # Add timezone and collection timestamp as epoch
            $currentEpoch = [int64]([DateTimeOffset](Get-Date)).ToUnixTimeSeconds()
            $_ | Add-Member -NotePropertyName "TimeZone" -NotePropertyValue $tzinfo.ToString() -Force
            $_ | Add-Member -NotePropertyName "CollectionTime" -NotePropertyValue $currentEpoch -Force
            
            # Convert any DateTime properties to epoch before JSON serialization
            foreach ($prop in $_.PSObject.Properties) {
                if ($prop.Value -is [DateTime] -and $prop.Value -ne [DateTime]::MinValue) {
                    try {
                        $epochValue = [int64]([DateTimeOffset]$prop.Value).ToUnixTimeSeconds()
                        $prop.Value = $epochValue
                    }
                    catch {
                        $prop.Value = $null
                    }
                }
                elseif ($prop.Value -is [string]) {
                    # Clean any problematic characters from string fields
                    $cleanValue = $prop.Value -replace '[^\x20-\x7E]', '' # Remove non-printable characters
                    $cleanValue = $cleanValue -replace '"', '\"' # Escape quotes
                    $cleanValue = $cleanValue -replace '\\', '\\' # Escape backslashes
                    $prop.Value = $cleanValue
                }
            }
            
            # Create proper HEC event structure
            $hecEvent = @{
                "host" = $env:COMPUTERNAME
                "sourcetype" = "UserActivity"
                "source" = $_.EventType
                "index" = $splunkindex
                "event" = $_
            }
            
            # Convert to JSON and add to body
            $eventJson = $hecEvent | ConvertTo-Json -Compress -Depth 4
            $newbody += $eventJson + "`n"
        }
        catch {
            Write-Host "Error processing event: $($_.Exception.Message)" -ForegroundColor Yellow
            continue
        }
    }
    
    Write-Host "Sending chunk $count of $($chunks.Count)..." -ForegroundColor Cyan
    Write-Host "Chunk size: $($newbody.Length) characters" -ForegroundColor Gray
    
    try {
        $response = Invoke-RestMethod -Uri $splunkserver -Method Post -Headers $headers -Body $newbody -UseBasicParsing
        Write-Host "Chunk $count sent successfully" -ForegroundColor Green
        $totalSuccess += $chunk.Count
    }
    catch {
        Write-Host "Error sending chunk $count`: $($_.Exception.Message)" -ForegroundColor Red
        
        # Debug: Show first few characters of the problematic chunk
        Write-Host "Problematic chunk preview: $($newbody.Substring(0, [Math]::Min(200, $newbody.Length)))" -ForegroundColor Yellow
        $totalErrors += $chunk.Count
    }
    
    $count++
    Start-Sleep -Seconds 1
}

Write-Host "`nUser Activity Collection Completed!" -ForegroundColor Green
Write-Host "Successfully sent: $totalSuccess events" -ForegroundColor Green
Write-Host "Failed to send: $totalErrors events" -ForegroundColor Red