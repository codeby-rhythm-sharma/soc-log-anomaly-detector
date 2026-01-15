"""
SOC Log Anomaly Detector
=======================
Simple tool to scan security logs for suspicious patterns like failed logins.
Uses pattern matching to identify potential security threats with severity levels.
Perfect for learning SOC (Security Operations Center) log analysis basics.
"""

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


def detect_anomalies(log):
    """
    Core detection function: Scans log for known suspicious patterns.
    
    Why lowercase? Makes pattern matching case-insensitive (e.g. "Failed" vs "failed")
    Why list of tuples? Easy to extend and pairs message with severity perfectly.
    
    Args:
        log (str): Raw log line from security systems (syslog, auth.log, etc.)
    
    Returns:
        list: Empty list if clean, or list of (description, severity) tuples
    """
    # Step 1: Normalize case for reliable pattern matching
    log = log.lower()
    findings = []  # Will store all matches found

    # Step 2: Check every known suspicious pattern against the log
    for pattern, (message, severity) in SUSPICIOUS_PATTERNS.items():
        # Simple substring check - fast and effective for log analysis
        if pattern in log:
            findings.append((message, severity))
            # Note: Could add regex for complex patterns in future versions

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
    print("Example: 'Failed password for invalid user from 192.168.1.100'")

    # Continuous loop mimics real-time log monitoring
    while True:
        log = input("> ")
        # Case-insensitive exit condition
        if log.lower() == "exit":
            break

        # Process and display result immediately
        print(analyze_log(log))
        print()  # Extra newline for readability between analyses