import json
import os

def load_rules(config_path="rules.json"):
    """Loads detection rules and severity levels from a JSON file.
       Falls back to internal defaults if the file is missing or invalid.
    """
    # Internal defaults used only if config file is missing or empty
    #Default suspicious patterns  
    patterns = {
        "failed password": {
            "message": "Failed password attempt",
            "severity": "MEDIUM",
            "threshold": 1,
            "threshold_severity": "MEDIUM"
        },
        "authentication failure": {
            "message": "Authentication failure",
            "severity": "MEDIUM",
            "threshold": 1,
            "threshold_severity": "MEDIUM"
        },
        "invalid user": {
            "message": "Invalid user login attempt",
            "severity": "HIGH",
            "threshold": 1,
            "threshold_severity": "HIGH"
        },
        "unauthorized access": {
            "message": "Unauthorized access attempt",
            "severity": "HIGH",
            "threshold": 1,
            "threshold_severity": "HIGH"
        },
        "permission denied": {
            "message": "Permission denied",
            "severity": "LOW",
            "threshold": 1,
            "threshold_severity": "LOW"
        },
        "connection closed": {
            "message": "Suspicious connection closure",
            "severity": "LOW",
            "threshold": 1,
            "threshold_severity": "LOW"
        }
    }
    
    #Severity level to emoji mapping
    severity_levels = {
        "HIGH": "🔴",
        "MEDIUM": "🟡",
        "LOW": "🟢"
    }
    
    #Load external configuration if it exists
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
                
                # Load severity levels if provided
                if "severity_levels" in config:
                    severity_levels = config["severity_levels"]
                
                # Load patterns if provided
                if "suspicious_patterns" in config:
                    patterns = {}
                    for pattern, details in config["suspicious_patterns"].items():
                        patterns[pattern] = {
                            "message": details.get("message", "Unknown anomaly"),
                            "severity": details.get("severity", "LOW"),
                            "threshold": details.get("threshold", 1),
                            "threshold_severity": details.get("threshold_severity", details.get("severity", "LOW"))
                        }
        except (json.JSONDecodeError, IOError):
            #Fallback to defaults if config fails to load 
            print(f"⚠️ Warning: Could not read {config_path}. Using internal defaults.")
    
    return patterns, severity_levels

class AnomalyDetector:
    """Rule-based SOC log anomaly detector."""
    def __init__(self, config_path="rules.json"):
        self.patterns, self.severity_levels = load_rules(config_path)
        self.counts = {pattern: 0 for pattern in self.patterns}
    
    def validate_log_entry(self, log):
        """
        Validates log entry to prevent crashes from unexpected or malformed input.
        
        Issue #5: Add basic input validation for log entries
        - Skips empty or whitespace-only lines (handles "", " ", "\n")
        - Handles non-string types safely (converts to string or rejects)
        - Prevents crashes due to bad input (None types, bytes with errors)
        
        Args:
            log: Input log entry (any type - str, bytes, None, int, etc.)
            
        Returns:
            tuple: (is_valid: bool, cleaned_log: str or None)
                   Returns (False, None) if input should be skipped
                   Returns (True, cleaned_string) if input is valid
        """
        # Check for None input (prevents AttributeError on .lower())
        if log is None:
            return False, None
        
        # Ensure it's a string (handles numbers, objects, bytes safely)
        if not isinstance(log, str):
            try:
                # Handle bytes with encoding errors gracefully
                if isinstance(log, bytes):
                    log = log.decode('utf-8', errors='ignore')
                else:
                    log = str(log)
            except Exception:
                # If conversion fails (very malformed input), treat as invalid
                return False, None
        
        # Remove leading/trailing whitespace
        cleaned = log.strip()
        
        # Check for empty string after stripping (handles "", "   ", "\t", "\n")
        if not cleaned:
            return False, None
            
        return True, cleaned

    def detect_anomalies(self, log):
        """
        Detects anomalies in log entries.
        Assumes input is already validated by analyze_log.
        """
        log = log.lower()
        findings = []

        #Scan log for each known pattern
        for pattern, config in self.patterns.items():
            if pattern in log:
                self.counts[pattern] += 1  #Increment occurrence count
                
                message = config["message"]
                severity = config["severity"]
                threshold = config["threshold"]

                #Escalate severity if threshold is reached
                if self.counts[pattern] >= threshold:
                    severity = config["threshold_severity"]
                    if threshold > 1:
                        message = f"{message} (Threshold reached: {self.counts[pattern]} matches)"
                
                findings.append((message, severity))

        return findings

    def analyze_log(self, log):
        """
        Analyzes log entry and returns formatted result.
        Handles empty/invalid input gracefully with user-friendly messages.
        """
        # Issue #5: Input validation - Handle unexpected input gracefully
        is_valid, cleaned_log = self.validate_log_entry(log)
        if not is_valid:
            return "⏭️  Skipped empty or invalid log entry."
        
        results = self.detect_anomalies(cleaned_log)

        if not results:
            return "✔️ Log looks normal"

        output = "⚠️ Anomalies detected:\n"
        for issue, severity in results:
            marker = self.severity_levels.get(severity, "⚪")
            output += f"{marker} [{severity}] {issue}\n"

        return output
    
#Global detector instance
detector = AnomalyDetector()

def analyze_log(log):
    """Module-level convenience function"""
    return detector.analyze_log(log)

if __name__ == "__main__":
    #CLI entry point 
    print("SOC Log Anomaly Detector")
    print("Enter log lines (type 'exit' to quit):")

    while True:
        try:
            log = input("> ")
        except (EOFError, KeyboardInterrupt):
            # Issue #5: Prevent crashes from Ctrl+C or Ctrl+D (beginner-friendly)
            print("\n👋 Exiting...")
            break
        
        if log.lower().strip() == "exit":
            break

        print(analyze_log(log))