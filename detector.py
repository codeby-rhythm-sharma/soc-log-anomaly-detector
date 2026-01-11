import re

SUSPICIOUS_PATTERNS = [
    "failed password",
    "authentication failure",
    "invalid user",
    "unauthorized access",
    "permission denied"
]
def detect_anomalies(log):
    log = log.lower()
    findings = []

    if "failed password" in log:
        findings.append(("Failed password attempt", "MEDIUM"))

    if "invalid user" in log:
        findings.append(("Invalid user login attempt", "HIGH"))

    if "unauthorized access" in log:
        findings.append(("Unauthorized access attempt", "HIGH"))

    if "connection closed" in log:
        findings.append(("Suspicious connection closure", "LOW"))

    return findings


def analyze_log(log):
    results = detect_anomalies(log)

    if not results:
        return "✔️ Log looks normal"

    output = "⚠️ Anomalies detected:\n"
    for issue, severity in results:
        marker = "🔴" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🟢"
        output += f"{marker} [{severity}] {issue}\n"
    
    return output

if __name__ == "__main__":
    print("SOC Log Anomaly Detector")
    print("Enter log lines (type 'exit' to quit):")

    while True:
        log = input("> ")
        if log.lower() == "exit":
            break

        print(analyze_log(log))

    
