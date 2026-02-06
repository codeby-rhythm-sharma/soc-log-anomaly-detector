import json
import os
import re
from datetime import datetime

def load_rules(config_path="rules.json"):
    """Loads detection rules and severity levels from a JSON file."""
    # Internal defaults
    patterns = {
        "failed password": {
            "message": "Failed password attempt",
            "severity": "MEDIUM",
            "threshold": 3,
            "threshold_severity": "HIGH",
            "time_window": 60
        }
    }
    
    severity_levels = {
        "CRITICAL": "🔥",
        "HIGH": "🔴",
        "MEDIUM": "🟡",
        "LOW": "🟢"
    }

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
                if "severity_levels" in config:
                    severity_levels = config["severity_levels"]
                if "suspicious_patterns" in config:
                    patterns = {}
                    for pattern, details in config["suspicious_patterns"].items():
                        patterns[pattern] = {
                            "message": details.get("message", "Unknown anomaly"),
                            "severity": details.get("severity", "LOW"),
                            "threshold": details.get("threshold", 1),
                            "threshold_severity": details.get("threshold_severity", details.get("severity", "LOW")),
                            "time_window": details.get("time_window", 60)  # Default 60s window
                        }
        except (json.JSONDecodeError, IOError):
            print(f"⚠️ Warning: Could not read {config_path}. Using internal defaults.")
    
    return patterns, severity_levels

class AnomalyDetector:
    def __init__(self, config_path="rules.json"):
        self.patterns, self.severity_levels = load_rules(config_path)
        # Store timestamp history for each pattern: {pattern_name: [datetime_objects]}
        self.event_history = {pattern: [] for pattern in self.patterns}
        # Regex for common ISO-like timestamp: 2024-05-20 14:30:05
        self.timestamp_regex = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')

    def parse_timestamp(self, log_entry):
        """Extracts and parses timestamp from the log entry."""
        match = self.timestamp_regex.search(log_entry)
        if match:
            try:
                return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
        return None

    def validate_log_entry(self, log):
        """Basic validation for log entries."""
        if log is None: return False, None
        if not isinstance(log, str):
            try:
                log = log.decode('utf-8', errors='ignore') if isinstance(log, bytes) else str(log)
            except: return False, None
        
        cleaned = log.strip()
        if not cleaned or cleaned.startswith("#"): # Skip comments
            return False, None
        return True, cleaned

    def detect_anomalies(self, log):
        """Detects anomalies using a sliding time window."""
        current_time = self.parse_timestamp(log)
        
        # If no timestamp is present, we can't do time-window detection accurately.
        # For simplicity, we'll use the current system time if missing.
        if not current_time:
            current_time = datetime.now()

        log_lower = log.lower()
        findings = []

        for pattern, config in self.patterns.items():
            if pattern in log_lower:
                # Add the current event's timestamp to our history for this pattern
                self.event_history[pattern].append(current_time)
                
                # MAINTAIN SLIDING WINDOW: This is the core logic.
                # We only keep timestamps that are within the 'time_window' (e.g., last 60 seconds).
                # Anything older than (current_time - window) is removed.
                window_seconds = config["time_window"]
                if window_seconds > 0:
                    self.event_history[pattern] = [
                        ts for ts in self.event_history[pattern] 
                        if (current_time - ts).total_seconds() <= window_seconds
                    ]
                
                # Count how many matches are LEFT in our window
                count = len(self.event_history[pattern])

                threshold = config["threshold"]
                
                if count >= threshold:
                    message = config["message"]
                    severity = config["threshold_severity"]
                    if threshold > 1:
                        message = f"{message} ({count} occurrences in {window_seconds}s)"
                    findings.append((message, severity))
                elif count > 0:
                    # Optional: Log that a suspicious event occurred but threshold not met
                    # For now, let's only report when threshold is hit or if threshold is 1
                    if threshold <= 1:
                        findings.append((config["message"], config["severity"]))

        return findings

    def analyze_log(self, log):
        """Analyzes log entry and returns formatted result."""
        is_valid, cleaned_log = self.validate_log_entry(log)
        if not is_valid:
            return None # Silent skip for empty/invalid
        
        results = self.detect_anomalies(cleaned_log)

        if not results:
            return f"✔️ [Normal] {cleaned_log[:50]}..."

        output = f"⚠️ Anomalies detected in: {cleaned_log[:50]}...\n"
        for issue, severity in results:
            marker = self.severity_levels.get(severity, "⚪")
            output += f"   {marker} [{severity}] {issue}\n"

        return output

detector = AnomalyDetector()

def analyze_log(log):
    return detector.analyze_log(log)

def process_file(file_path):
    """Processes a log file line by line."""
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return

    print(f"\n--- Analyzing Log File: {os.path.basename(file_path)} ---")
    with open(file_path, "r") as f:
        # Sort logs chronologically if they have timestamps
        lines = [line.strip() for line in f if line.strip()]
        
        # Simple heuristic: if most lines have timestamps, we can sort
        # However, real logs are usually chronological. 
        # For a "beginner-friendly" approach, we'll process them in order.
        
        for line in lines:
            result = analyze_log(line)
            if result:
                print(result)

if __name__ == "__main__":
    print("SOC Log Anomaly Detector (Timestamp Aware)")
    print("1. Enter logs manually")
    print("2. Analyze sample_logs/timestamped_logs.txt")
    print("Type 'exit' to quit.")

    while True:
        choice = input("\nSelect an option (1/2/exit): ").strip().lower()
        if choice == '1':
            print("Enter log lines (e.g., '2026-02-06 22:40:05 - failed password'):")
            while True:
                log = input("> ")
                if log.lower().strip() == "exit": break
                print(analyze_log(log))
        elif choice == '2':
            process_file("sample_logs/timestamped_logs.txt")
        elif choice == 'exit':
            break
        else:
            print("Invalid choice.")
