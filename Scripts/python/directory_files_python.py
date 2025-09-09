#!/usr/bin/env python3
"""
Simple Directory File Collection Script
Collects file information from common user directories and sends to Splunk HEC
"""

import json
import requests
import os
import time
from datetime import datetime
from pathlib import Path
import urllib3

# Suppress SSL warnings for lab environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration - Update these values for your environment
SPLUNK_SERVER = "https://YOUR-SPLUNK-SERVER:8088/services/collector"
HEC_TOKEN = "YOUR-HEC-TOKEN-HERE"
SPLUNK_INDEX = "YOUR-INDEX-NAME"

# Collection settings - easily adjustable
MAX_FILES_PER_DIRECTORY = 5000  # Maximum files to collect per directory
CHUNK_SIZE = 200  # Number of file records per batch to Splunk
DELAY_BETWEEN_CHUNKS = 0.5  # Seconds to wait between chunks

# Common user directories to scan
USER_DIRECTORIES = [
    "Desktop",
    "Downloads", 
    "Documents"
]

def get_user_profiles():
    """Get list of user profile directories"""
    users_dir = Path("C:/Users")
    user_profiles = []
    
    if users_dir.exists():
        for user_path in users_dir.iterdir():
            if user_path.is_dir() and user_path.name not in ["Public", "Default", "All Users"]:
                user_profiles.append(user_path)
    
    return user_profiles

def collect_files_from_directory(directory_path, max_files):
    """Collect file information from a specific directory"""
    files_data = []
    file_count = 0
    
    try:
        # Use pathlib for clean directory traversal
        path_obj = Path(directory_path)
        
        if not path_obj.exists():
            return files_data
            
        # Walk through directory and subdirectories
        for file_path in path_obj.rglob("*"):
            if file_count >= max_files:
                break
                
            try:
                # Only process files, not directories
                if file_path.is_file():
                    stat_info = file_path.stat()
                    
                    file_data = {
                        "FileName": file_path.name,
                        "FileExtension": file_path.suffix.lower(),
                        "FullPath": str(file_path),
                        "FileSizeBytes": stat_info.st_size,
                        "FileSizeKB": round(stat_info.st_size / 1024, 2),
                        "FileSizeMB": round(stat_info.st_size / (1024 * 1024), 2),
                        "CreationTime": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                        "LastModifiedTime": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                        "LastAccessTime": datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                        "DirectoryPath": str(file_path.parent),
                        "RelativePath": str(file_path.relative_to(directory_path)) if directory_path in str(file_path) else str(file_path),
                        "EventType": "FileInfo"
                    }
                    
                    files_data.append(file_data)
                    file_count += 1
                    
            except (PermissionError, OSError) as e:
                # Skip files we can't access
                continue
                
    except Exception as e:
        print(f"    Error scanning {directory_path}: {str(e)}")
    
    return files_data

def collect_all_files():
    """Collect files from all user directories"""
    print("Collecting file information...")
    all_files = []
    
    # Get user profiles
    user_profiles = get_user_profiles()
    print(f"Found {len(user_profiles)} user profiles")
    
    # Scan each user's directories
    for user_profile in user_profiles:
        username = user_profile.name
        print(f"\nScanning directories for user: {username}")
        
        for directory in USER_DIRECTORIES:
            directory_path = user_profile / directory
            print(f"  Scanning: {directory_path}")
            
            files = collect_files_from_directory(directory_path, MAX_FILES_PER_DIRECTORY)
            
            # Add user context to each file record
            for file_data in files:
                file_data["Username"] = username
                file_data["UserProfilePath"] = str(user_profile)
                file_data["DirectoryType"] = directory
            
            all_files.extend(files)
            print(f"    Found {len(files)} files")
    
    # Also scan some common system directories
    system_directories = [
        "C:/Temp",
        "C:/Windows/Temp"
    ]
    
    print(f"\nScanning system directories...")
    for sys_dir in system_directories:
        print(f"  Scanning: {sys_dir}")
        files = collect_files_from_directory(sys_dir, MAX_FILES_PER_DIRECTORY // 2)
        
        # Add system context
        for file_data in files:
            file_data["Username"] = "SYSTEM"
            file_data["UserProfilePath"] = "N/A"
            file_data["DirectoryType"] = "SystemDirectory"
        
        all_files.extend(files)
        print(f"    Found {len(files)} files")
    
    return all_files

def send_to_splunk(files_data, chunk_size, delay):
    """Send file data to Splunk HEC in configurable chunks"""
    if not files_data:
        print("No files to send")
        return
        
    print(f"\nSending {len(files_data)} file records to Splunk in chunks of {chunk_size}...")
    
    headers = {
        "Authorization": f"Splunk {HEC_TOKEN}",
        "Content-Type": "application/json"
    }
    
    total_success = 0
    total_errors = 0
    
    # Process files in chunks
    for i in range(0, len(files_data), chunk_size):
        chunk = files_data[i:i + chunk_size]
        chunk_num = (i // chunk_size) + 1
        total_chunks = (len(files_data) + chunk_size - 1) // chunk_size
        
        # Build HEC payload
        payload = ""
        for file_data in chunk:
            # Add collection timestamp
            file_data["CollectionTime"] = datetime.now().isoformat()
            
            hec_event = {
                "host": os.environ.get("COMPUTERNAME", "unknown"),
                "sourcetype": "DirectoryFiles",
                "source": file_data["EventType"],
                "index": SPLUNK_INDEX,
                "event": file_data
            }
            payload += json.dumps(hec_event) + "\n"
        
        # Send to Splunk
        try:
            response = requests.post(
                SPLUNK_SERVER,
                headers=headers,
                data=payload,
                verify=False,  # Skip SSL verification for lab environments
                timeout=30
            )
            
            if response.status_code == 200:
                print(f"  Chunk {chunk_num}/{total_chunks} sent successfully ({len(chunk)} files)")
                total_success += len(chunk)
            else:
                print(f"  Error sending chunk {chunk_num}: HTTP {response.status_code}")
                total_errors += len(chunk)
                
        except Exception as e:
            print(f"  Error sending chunk {chunk_num}: {str(e)}")
            total_errors += len(chunk)
        
        # Delay between chunks
        if delay > 0 and i + chunk_size < len(files_data):
            time.sleep(delay)
    
    print(f"\nResults:")
    print(f"  Successfully sent: {total_success} file records")
    print(f"  Failed to send: {total_errors} file records")

def main():
    """Main execution function"""
    print("Starting Directory File Collection...")
    print(f"Configuration:")
    print(f"  Max files per directory: {MAX_FILES_PER_DIRECTORY}")
    print(f"  Chunk size: {CHUNK_SIZE}")
    print(f"  Delay between chunks: {DELAY_BETWEEN_CHUNKS}s")
    print(f"  Directories to scan: {', '.join(USER_DIRECTORIES)}")
    print()
    
    # Collect all file information
    all_files = collect_all_files()
    
    print(f"\nTotal files collected: {len(all_files)}")
    
    if all_files:
        send_to_splunk(all_files, CHUNK_SIZE, DELAY_BETWEEN_CHUNKS)
    
    print("\nDirectory file collection completed!")

if __name__ == "__main__":
    main()
