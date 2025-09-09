#!/usr/bin/env python3
"""
Simple Windows Event Log Collection Script
Collects recent Windows event logs and sends to Splunk HEC
"""

import json
import requests
import win32evtlog
import win32con
import time
from datetime import datetime, timedelta
import urllib3

# Suppress SSL warnings for lab environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration - Update these values for your environment
SPLUNK_SERVER = "https://YOUR-SPLUNK-SERVER:8088/services/collector"
HEC_TOKEN = "YOUR-HEC-TOKEN-HERE"
SPLUNK_INDEX = "YOUR-INDEX-NAME"

# Collection settings - easily adjustable
HOURS_BACK = 48  # How far back to collect events
MAX_EVENTS_PER_LOG = 5000  # Maximum events per log type
CHUNK_SIZE = 100  # Number of events per batch to Splunk
DELAY_BETWEEN_CHUNKS = 0.5  # Seconds to wait between chunks

# Event logs to collect
EVENT_LOGS = ["Application", "System", "Security"]

def get_recent_events(log_name, hours_back, max_events):
    """Collect recent events from specified Windows event log"""
    print(f"Collecting from {log_name} log...")
    
    events = []
    try:
        # Open the event log
        handle = win32evtlog.OpenEventLog(None, log_name)
        
        # Calculate start time
        start_time = datetime.now() - timedelta(hours=hours_back)
        
        # Read events (most recent first)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        event_count = 0
        
        while event_count < max_events:
            # Read events in batches
            batch_events = win32evtlog.ReadEventLog(handle, flags, 0)
            
            if not batch_events:
                break
                
            for event in batch_events:
                # Convert Windows timestamp to Python datetime
                event_time = datetime.fromtimestamp(int(event.TimeGenerated))
                
                # Only include events within our time range
                if event_time < start_time:
                    break
                    
                # Create simplified event object
                event_data = {
                    "EventID": event.EventID,
                    "EventType": event.EventType,
                    "TimeGenerated": event_time.isoformat(),
                    "SourceName": event.SourceName,
                    "ComputerName": event.ComputerName,
                    "EventCategory": event.EventCategory,
                    "RecordNumber": event.RecordNumber,
                    "StringInserts": event.StringInserts if event.StringInserts else [],
                    "LogName": log_name
                }
                
                events.append(event_data)
                event_count += 1
                
                if event_count >= max_events:
                    break
            
            if event_count >= max_events:
                break
                
        win32evtlog.CloseEventLog(handle)
        print(f"  Found {len(events)} events in {log_name}")
        
    except Exception as e:
        print(f"  Error collecting from {log_name}: {str(e)}")
        
    return events

def send_to_splunk(events, chunk_size, delay):
    """Send events to Splunk HEC in configurable chunks"""
    if not events:
        print("No events to send")
        return
        
    print(f"Sending {len(events)} events to Splunk in chunks of {chunk_size}...")
    
    headers = {
        "Authorization": f"Splunk {HEC_TOKEN}",
        "Content-Type": "application/json"
    }
    
    total_success = 0
    total_errors = 0
    
    # Process events in chunks
    for i in range(0, len(events), chunk_size):
        chunk = events[i:i + chunk_size]
        chunk_num = (i // chunk_size) + 1
        total_chunks = (len(events) + chunk_size - 1) // chunk_size
        
        # Build HEC payload
        payload = ""
        for event in chunk:
            hec_event = {
                "host": event.get("ComputerName", "unknown"),
                "sourcetype": "WinEventLog",
                "source": event["LogName"],
                "index": SPLUNK_INDEX,
                "event": event
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
                print(f"  Chunk {chunk_num}/{total_chunks} sent successfully ({len(chunk)} events)")
                total_success += len(chunk)
            else:
                print(f"  Error sending chunk {chunk_num}: HTTP {response.status_code}")
                total_errors += len(chunk)
                
        except Exception as e:
            print(f"  Error sending chunk {chunk_num}: {str(e)}")
            total_errors += len(chunk)
        
        # Delay between chunks to avoid overwhelming Splunk
        if delay > 0 and i + chunk_size < len(events):
            time.sleep(delay)
    
    print(f"\nResults:")
    print(f"  Successfully sent: {total_success} events")
    print(f"  Failed to send: {total_errors} events")

def main():
    """Main execution function"""
    print("Starting Windows Event Log Collection...")
    print(f"Configuration:")
    print(f"  Time range: {HOURS_BACK} hours back")
    print(f"  Max events per log: {MAX_EVENTS_PER_LOG}")
    print(f"  Chunk size: {CHUNK_SIZE}")
    print(f"  Delay between chunks: {DELAY_BETWEEN_CHUNKS}s")
    print()
    
    all_events = []
    
    # Collect from each event log
    for log_name in EVENT_LOGS:
        events = get_recent_events(log_name, HOURS_BACK, MAX_EVENTS_PER_LOG)
        all_events.extend(events)
    
    print(f"\nTotal events collected: {len(all_events)}")
    
    if all_events:
        send_to_splunk(all_events, CHUNK_SIZE, DELAY_BETWEEN_CHUNKS)
    
    print("\nEvent log collection completed!")

if __name__ == "__main__":
    main()
