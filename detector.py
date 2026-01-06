import re

SUSPICIOUS_PATTERNS = [
    "failed password",
    "authentication failure",
    "invalid user",
    "unauthorized access",
    "permission denied"
]

def detect_anomalies(log_line):
    log_line = log_line.lower()
    matches = [p for p in SUSPICIOUS_PATTERNS if p in log_line]
    return matches

if __name__ == "__main__":
    print("SOC Log Anomaly Detector")
    print("Enter log lines (type 'exit' to quit):")

    while True:
        log = input("> ")
        if log.lower() == "exit":
            break

        anomalies = detect_anomalies(log)
        if anomalies:
            print("⚠️ Anomaly detected:", ", ".join(anomalies))
        else:
            print("✔️ Log looks normal")
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
        return "✔️ No anomalies detected."

    output = "⚠️ Anomalies detected:\n"
    for issue, severity in results:
        output += f"- [{severity}] {issue}\n"

    return output


log_entry = input("Enter SOC log entry: ")
print(analyze_log(log_entry))
