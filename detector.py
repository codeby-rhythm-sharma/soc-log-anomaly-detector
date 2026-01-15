"""
SOC Log Anomaly Detector
=======================
Simple tool to scan security logs for suspicious patterns like failed logins.
Uses pattern matching to identify potential security threats with severity levels.
Perfect for learning SOC (Security Operations Center) log analysis basics.

NEW: Detects repeated suspicious events within 60-second windows (brute-force detection).
NEW: Batch file analysis with sample_soc_logs.txt for easy testing.
"""

import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

# Predefined dictionary mapping suspicious keywords to their descriptions and severity levels
# Why a dictionary? Fast lookup and easy to extend with new patterns
# Severity levels: HIGH (immediate attention), MEDIUM (investigate), LOW (monitor)
SUSPICIOUS_PATTERNS = {
    "failed password": ("Failed password attempt", "MEDIUM"),
    "authentication failure": ("Authentication failure", "MEDIUM"), 
    "invalid user": ("Invalid user login attempt", "HIGH"),
    "unauthorized access": ("Unauthorized access attempt", "HIGH"),
    "permission denied": ("Permission denied", "LOW"),
    "connection closed": ("Suspicious connection closure", "LOW"),
}

# Track recent events for time-window analysis (session memory)
recent_events = deque(maxlen=100)  # Keep last 100 events (performance)
pattern_counts = defaultdict(int)  # Count patterns in current 60-sec window

def parse_timestamp(log):
    """
    Extract timestamp from log (format: '2026-01-15 10:20:15').
    Returns None if no valid timestamp found.
    """
    timestamp_pattern = r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}'
    match = re.search(timestamp_pattern, log)
    if match:
        return datetime.strptime(match.group(), '%Y-%m-%d %H:%M:%S')
    return None

def detect_anomalies(log):
    """
    Core detection function: Scans log for known suspicious patterns.
    Also detects repeated events (3+ in 60 seconds) for brute-force alerts.
    
    Args:
        log (str): Raw log line from security systems (syslog, auth.log, etc.)
    
    Returns:
        list: Empty list if clean, or list of (description, severity) tuples
    """
    log_lower = log.lower()
    findings = []

    timestamp = parse_timestamp(log)
    
    # Check every known suspicious pattern against the log
    for pattern, (message, severity) in SUSPICIOUS_PATTERNS.items():
        if pattern in log_lower:
            findings.append((message, severity))
            pattern_counts[pattern] += 1

    # Check for repeated events in 60-second window
    if timestamp:
        recent_events.append((timestamp, log_lower))
        
        # Remove events older than 60 seconds
        cutoff_time = timestamp - timedelta(minutes=1)
        while recent_events and recent_events[0][0] < cutoff_time:
            recent_events.popleft()
        
        # Flag brute-force attacks (3+ same pattern in 1 minute)
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern_counts[pattern] >= 3:
                findings.append(("🚨 REPEATED ATTACK DETECTED (3+ in 60s)", "HIGH"))
                break

    return findings

def analyze_log(log):
    """
    User-friendly wrapper: Converts raw detection results into readable output.
    
    Args:
        log (str): Single log line to analyze
    
    Returns:
        str: Clean "normal" message OR formatted anomaly report
    """
    results = detect_anomalies(log)

    if not results:
        return "✔️ Log looks normal"

    output = "⚠️ Anomalies detected:\n"
    for issue, severity in results:
        if severity == "HIGH":
            marker = "🔴"
        elif severity == "MEDIUM":
            marker = "🟡"
        else:
            marker = "🟢"
        output += f"{marker} [{severity}] {issue}\n"

    return output

def analyze_file(log_file_path):
    """
    Analyze entire log file and show comprehensive report.
    
    Args:
        log_file_path (str): Path to SOC log file
        
    Returns:
        str: Summary report with anomaly counts
    """
    try:
        with open(log_file_path, 'r') as f:
            lines = f.readlines()
        
        total_lines = len(lines)
        anomalies = 0
        
        print(f"\n📊 Analyzing {total_lines} log entries...\n")
        
        for i, line in enumerate(lines, 1):
            result = analyze_log(line.strip())
            if "Anomalies detected" in result:
                anomalies += 1
            print(f"Line {i}: {result}")
        
        print(f"\n📈 SUMMARY: {anomalies}/{total_lines} lines have anomalies ({anomalies/total_lines*100:.1f}%)")
        return f"Analysis complete: {anomalies}/{total_lines} anomalies detected"
    
    except FileNotFoundError:
        return "❌ Error: Log file not found. Create 'sample_soc_logs.txt' first!"
    except Exception as e:
        return f"❌ Error reading file: {str(e)}"

if __name__ == "__main__":
    """
    Interactive CLI + File analysis mode for testing and learning.
    """
    print("SOC Log Anomaly Detector")
    print("1. Interactive mode: Enter logs manually") 
    print("2. Batch mode: Type 'file' to analyze sample_soc_logs.txt")
    print("\nEnter log lines (type 'exit' to quit, 'file' for batch analysis):")
    
    while True:
        user_input = input("> ").strip()
        
        if user_input.lower() == "exit":
            break
        elif user_input.lower() == "file":
            print(analyze_file("sample_soc_logs.txt"))
            print()
            continue
        
        print(analyze_log(user_input))
        print()
