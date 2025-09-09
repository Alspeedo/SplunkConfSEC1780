# High-Traffic Directory File Collection Script
Write-Host "Starting Directory File Collection..." -ForegroundColor Green

# Configuration
# Configuration - Update these values for your environment
$splunkserver = "https://YOUR-SPLUNK-SERVER:8088/services/collector"
$hectoken = "YOUR-HEC-TOKEN-HERE"
$splunkindex = "YOUR-INDEX-NAME"
$maxDepth = 5  # Set how deep to recurse (0 = no recursion, 5 = 5 levels deep, -1 = unlimited)
$maxFilesPerDir = 15000  # Maximum files to collect per directory
$maxSystemFiles = 2500  # Maximum files to collect from system directories

# Bypass SSL certificate verification
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Setup headers
$headers = @{
    "Authorization" = "Splunk $hectoken"
    "Content-Type" = "application/json"
}

$tzinfo = (Get-TimeZone)
$allFiles = @()

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Max Depth: $(if($maxDepth -eq -1){'Unlimited'}else{$maxDepth})" -ForegroundColor White
Write-Host "  Max Files Per Directory: $maxFilesPerDir" -ForegroundColor White
Write-Host "  Max System Files: $maxSystemFiles" -ForegroundColor White
Write-Host ""

# Define high-traffic directories to scan for each user profile
$highTrafficDirs = @(
    "Desktop",
    "Downloads", 
    "Documents",
    "Pictures",
    "Videos",
    "Music",
    "AppData\Roaming",
    "AppData\Local\Temp",
    "AppData\Local",
    "OneDrive",
    "Dropbox",
    "Google Drive"
)

# Additional system directories of interest
$systemDirs = @(
    "C:\Temp",
    "C:\Windows\Temp", 
    "C:\Users\Public\Desktop",
    "C:\Users\Public\Downloads",
    "C:\Users\Public\Documents"
)

Write-Host "Collecting user profiles..." -ForegroundColor Yellow

# Get all user profiles
$userProfiles = Get-WmiObject Win32_UserProfile | Where-Object { 
    -not $_.Special -and 
    $_.LocalPath -like "C:\Users\*" -and
    $_.LocalPath -notlike "*\Administrator*" -and
    $_.LocalPath -notlike "*\Guest*" -and
    $_.LocalPath -notlike "*\DefaultAppPool*"
}

Write-Host "Found $($userProfiles.Count) user profiles to scan" -ForegroundColor Green

# Scan each user profile's high-traffic directories
foreach ($profile in $userProfiles) {
    $userPath = $profile.LocalPath
    $username = Split-Path $userPath -Leaf
    
    Write-Host "Scanning directories for user: $username" -ForegroundColor Cyan
    
    foreach ($dir in $highTrafficDirs) {
        $fullPath = Join-Path $userPath $dir
        
        if (Test-Path $fullPath) {
            Write-Host "  Scanning: $fullPath (Depth: $(if($maxDepth -eq -1){'Unlimited'}elseif($maxDepth -eq 0){'Current Only'}else{$maxDepth}))" -ForegroundColor Gray
            
            try {
                # Get files with configurable depth and limits
                if ($maxDepth -eq 0) {
                    # No recursion - current directory only
                    $files = Get-ChildItem -Path $fullPath -File -Force -ErrorAction SilentlyContinue |
                             Select-Object -First $maxFilesPerDir
                }
                elseif ($maxDepth -eq -1) {
                    # Unlimited recursion
                    $files = Get-ChildItem -Path $fullPath -File -Recurse -Force -ErrorAction SilentlyContinue |
                             Select-Object -First $maxFilesPerDir
                }
                else {
                    # Recursive with depth limit
                    $files = Get-ChildItem -Path $fullPath -File -Recurse -Force -ErrorAction SilentlyContinue |
                             Where-Object { $_.FullName.Split('\').Count -le ($fullPath.Split('\').Count + $maxDepth) } |
                             Select-Object -First $maxFilesPerDir
                }
                
                foreach ($file in $files) {
                    try {
                        # Get file hash for important file types
                        $fileHash = $null
                        $isExecutable = $file.Extension -match '\.(exe|dll|bat|cmd|ps1|vbs|js)$'
                        $isDocument = $file.Extension -match '\.(doc|docx|xls|xlsx|ppt|pptx|pdf|txt)$'
                        
                        if ($isExecutable -or ($isDocument -and $file.Length -lt 50MB)) {
                            try {
                                $fileHash = (Get-FileHash $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                            }
                            catch { $fileHash = $null }
                        }
                        
                        # Get file owner
                        $fileOwner = $null
                        try {
                            $acl = Get-Acl $file.FullName -ErrorAction SilentlyContinue
                            $fileOwner = if ($acl) { $acl.Owner } else { "Unknown" }
                        }
                        catch { $fileOwner = "Unknown" }
                        
                        # Calculate directory depth from user profile
                        $relativePath = $file.FullName.Replace($userPath, "")
                        $directoryDepth = ($relativePath.Split('\').Count - 2)  # Subtract 2 for empty string and filename
                        
                        $fileInfo = [PSCustomObject]@{
                            Username = $username
                            UserProfilePath = $userPath
                            DirectoryType = $dir
                            FileName = $file.Name
                            FileExtension = $file.Extension
                            FullPath = $file.FullName
                            FileSizeBytes = $file.Length
                            FileSizeKB = [math]::Round($file.Length / 1KB, 2)
                            FileSizeMB = [math]::Round($file.Length / 1MB, 2)
                            CreationTime = if($file.CreationTime -and $file.CreationTime -ne [DateTime]::MinValue) { [int64]([DateTimeOffset]$file.CreationTime).ToUnixTimeSeconds() } else { $null }
                            LastWriteTime = if($file.LastWriteTime -and $file.LastWriteTime -ne [DateTime]::MinValue) { [int64]([DateTimeOffset]$file.LastWriteTime).ToUnixTimeSeconds() } else { $null }
                            LastAccessTime = if($file.LastAccessTime -and $file.LastAccessTime -ne [DateTime]::MinValue) { [int64]([DateTimeOffset]$file.LastAccessTime).ToUnixTimeSeconds() } else { $null }
                            FileAttributes = $file.Attributes.ToString()
                            IsHidden = [bool]($file.Attributes -band [System.IO.FileAttributes]::Hidden)
                            IsSystem = [bool]($file.Attributes -band [System.IO.FileAttributes]::System)
                            IsReadOnly = [bool]($file.Attributes -band [System.IO.FileAttributes]::ReadOnly)
                            IsExecutable = $isExecutable
                            IsDocument = $isDocument
                            FileOwner = $fileOwner
                            FileHash = $fileHash
                            RelativePath = $relativePath
                            DirectoryDepth = $directoryDepth
                            EventType = "UserFile"
                        }
                        
                        $allFiles += $fileInfo
                    }
                    catch {
                        # Skip files that can't be processed
                        continue
                    }
                }
                
                Write-Host "    Found $($files.Count) files" -ForegroundColor Green
            }
            catch {
                Write-Host "    Error scanning $fullPath`: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "    Directory not found: $fullPath" -ForegroundColor Yellow
        }
    }
}

# Scan system directories
Write-Host "`nScanning system directories..." -ForegroundColor Yellow

foreach ($sysDir in $systemDirs) {
    if (Test-Path $sysDir) {
        Write-Host "  Scanning: $sysDir" -ForegroundColor Gray
        
        try {
            $files = Get-ChildItem -Path $sysDir -File -Force -ErrorAction SilentlyContinue |
                     Select-Object -First $maxSystemFiles
            
            foreach ($file in $files) {
                try {
                    # Get file hash for executables
                    $fileHash = $null
                    $isExecutable = $file.Extension -match '\.(exe|dll|bat|cmd|ps1|vbs|js)$'
                    
                    if ($isExecutable) {
                        try {
                            $fileHash = (Get-FileHash $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                        }
                        catch { $fileHash = $null }
                    }
                    
                    $fileInfo = [PSCustomObject]@{
                        Username = "SYSTEM"
                        UserProfilePath = "N/A"
                        DirectoryType = "SystemDirectory"
                        FileName = $file.Name
                        FileExtension = $file.Extension
                        FullPath = $file.FullName
                        FileSizeBytes = $file.Length
                        FileSizeKB = [math]::Round($file.Length / 1KB, 2)
                        FileSizeMB = [math]::Round($file.Length / 1MB, 2)
                        CreationTime = if($file.CreationTime -and $file.CreationTime -ne [DateTime]::MinValue) { [int64]([DateTimeOffset]$file.CreationTime).ToUnixTimeSeconds() } else { $null }
                        LastWriteTime = if($file.LastWriteTime -and $file.LastWriteTime -ne [DateTime]::MinValue) { [int64]([DateTimeOffset]$file.LastWriteTime).ToUnixTimeSeconds() } else { $null }
                        LastAccessTime = if($file.LastAccessTime -and $file.LastAccessTime -ne [DateTime]::MinValue) { [int64]([DateTimeOffset]$file.LastAccessTime).ToUnixTimeSeconds() } else { $null }
                        FileAttributes = $file.Attributes.ToString()
                        IsHidden = [bool]($file.Attributes -band [System.IO.FileAttributes]::Hidden)
                        IsSystem = [bool]($file.Attributes -band [System.IO.FileAttributes]::System)
                        IsReadOnly = [bool]($file.Attributes -band [System.IO.FileAttributes]::ReadOnly)
                        IsExecutable = $isExecutable
                        IsDocument = $false
                        FileOwner = "SYSTEM"
                        FileHash = $fileHash
                        RelativePath = $file.FullName.Replace("C:\", "")
                        DirectoryDepth = 0
                        EventType = "SystemFile"
                    }
                    
                    $allFiles += $fileInfo
                }
                catch {
                    continue
                }
            }
            
            Write-Host "    Found $($files.Count) files" -ForegroundColor Green
        }
        catch {
            Write-Host "    Error scanning $sysDir`: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host "`nTotal files collected: $($allFiles.Count)" -ForegroundColor Green

if ($allFiles.Count -eq 0) {
    Write-Host "No files found. Exiting." -ForegroundColor Yellow
    exit
}

# Split into chunks
$chunkSize = 1000  # Smaller chunks for file data
$chunks = [System.Collections.ArrayList]::new()
for ($i = 0; $i -lt $allFiles.Count; $i += $chunkSize) {
    if (($allFiles.Count - $i) -gt ($chunkSize - 1)) {
        $chunks.add($allFiles[$i..($i + $chunkSize - 1)])
    }
    else {
        $chunks.add($allFiles[$i..($allFiles.Count - 1)])
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
                "sourcetype" = "DirectoryFiles"
                "source" = $_.EventType
                "index" = $splunkindex
                "event" = $_
            }
            
            # Convert to JSON and add to body
            $eventJson = $hecEvent | ConvertTo-Json -Compress -Depth 4
            $newbody += $eventJson + "`n"
        }
        catch {
            Write-Host "Error processing file: $($_.Exception.Message)" -ForegroundColor Yellow
            continue
        }
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
    Start-Sleep -Seconds .25
}

Write-Host "`nDirectory File Collection Completed!" -ForegroundColor Green
Write-Host "Successfully sent: $totalSuccess file records" -ForegroundColor Green
Write-Host "Failed to send: $totalErrors file records" -ForegroundColor Red