import json
import os

def load_rules(config_path="rules.json"):
    """Loads detection rules and severity levels from a JSON file."""
    # Internal defaults used only if config file is missing or empty
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
    
    severity_levels = {
        "HIGH": "🔴",
        "MEDIUM": "🟡",
        "LOW": "🟢"
    }

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
            print(f"⚠️ Warning: Could not read {config_path}. Using internal defaults.")
    
    return patterns, severity_levels

class AnomalyDetector:
    def __init__(self, config_path="rules.json"):
        self.patterns, self.severity_levels = load_rules(config_path)
        self.counts = {pattern: 0 for pattern in self.patterns}

    def detect_anomalies(self, log):
        log = log.lower()
        findings = []

        for pattern, config in self.patterns.items():
            if pattern in log:
                self.counts[pattern] += 1
                
                message = config["message"]
                severity = config["severity"]
                threshold = config["threshold"]
                
                if self.counts[pattern] >= threshold:
                    severity = config["threshold_severity"]
                    if threshold > 1:
                        message = f"{message} (Threshold reached: {self.counts[pattern]} matches)"
                
                findings.append((message, severity))

        return findings

    def analyze_log(self, log):
        results = self.detect_anomalies(log)

        if not results:
            return "✔️ Log looks normal"

        output = "⚠️ Anomalies detected:\n"
        for issue, severity in results:
            marker = self.severity_levels.get(severity, "⚪")
            output += f"{marker} [{severity}] {issue}\n"

        return output

detector = AnomalyDetector()

def analyze_log(log):
    return detector.analyze_log(log)

if __name__ == "__main__":
    print("SOC Log Anomaly Detector")
    print("Enter log lines (type 'exit' to quit):")

    while True:
        log = input("> ")
        if log.lower() == "exit":
            break

        print(analyze_log(log))

