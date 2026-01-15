"""
SOC Log Anomaly Detector
=======================
Simple tool to scan security logs for suspicious patterns like failed logins.
Uses pattern matching to identify potential security threats with severity levels.
Perfect for learning SOC (Security Operations Center) log analysis basics.

NEW: Detects repeated suspicious events within 60-second windows (brute-force detection).
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

# NEW: Track recent events for time-window analysis (session memory)
recent_events = deque(maxlen=100)  # Keep last 100 events (performance)
pattern_counts = defaultdict(int)  # Count patterns in current 60-sec window

def parse_timestamp(log):
    """
    NEW: Extract timestamp from log (format: '2026-01-15 10:20:15').
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
    NEW: Also detects repeated events (3+ in 60 seconds) for brute-force alerts.
    
    Why lowercase? Makes pattern matching case-insensitive (e.g. "Failed" vs "failed")
    Why list of tuples? Easy to extend and pairs message with severity perfectly.
    
    Args:
        log (str): Raw log line from security systems (syslog, auth.log, etc.)
    
    Returns:
        list: Empty list if clean, or list of (description, severity) tuples
    """
    # Step 1: Normalize case for reliable pattern matching
    log_lower = log.lower()
    findings = []  # Will store all matches found

    # NEW: Parse timestamp for time-window analysis
    timestamp = parse_timestamp(log)
    
    # Step 2: Check every known suspicious pattern against the log (ORIGINAL LOGIC)
    for pattern, (message, severity) in SUSPICIOUS_PATTERNS.items():
        # Simple substring check - fast and effective for log analysis
        if pattern in log_lower:
            findings.append((message, severity))
            pattern_counts[pattern] += 1  # NEW: Track frequency

    # NEW Step 3: Check for repeated events in 60-second window
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

    return findings  # Empty = clean log, populated = anomalies found


def analyze_log(log):
    """
    User-friendly wrapper: Converts raw detection results into readable output.
    
    Why emojis? Visual indicators make alerts scanable during incident response.
    Why this structure? Mimics SOC alerting format (severity + description).
    
    Args:
        log (str): Single log line to analyze
    
    Returns:
        str: Clean "normal" message OR formatted anomaly report
    """
    # Get raw findings from detector
    results = detect_anomalies(log)

    # Quick exit for clean logs (most common case)
    if not results:
        return "✔️ Log looks normal"

    # Build formatted alert with severity-based color coding
    output = "⚠️ Anomalies detected:\n"
    for issue, severity in results:
        # Severity-based emoji mapping for quick visual triage
        if severity == "HIGH":
            marker = "🔴"  # Critical - immediate action
        elif severity == "MEDIUM":
            marker = "🟡"  # Elevated - investigate soon
        else:  # LOW
            marker = "🟢"  # Informational - monitor
        
        output += f"{marker} [{severity}] {issue}\n"

    return output


if __name__ == "__main__":
    """
    Interactive CLI mode for testing and learning.
    Simulates SOC analyst workflow: enter logs → get instant analysis.
    """
    print("SOC Log Anomaly Detector")
    print("Enter log lines (type 'exit' to quit):")
    print("Example: '2026-01-15 10:20:15 Failed password for invalid user'")
    print("Try 3+ failed logins within 1 minute to see REPEATED ATTACK alert!")

    # Continuous loop mimics real-time log monitoring
    while True:
        log = input("> ")
        # Case-insensitive exit condition
        if log.lower() == "exit":
            break

        # Process and display result immediately
        print(analyze_log(log))
        print()  # Extra newline for readability between analyses
