SUSPICIOUS_PATTERNS = {
    "failed password": ("Failed password attempt", "MEDIUM"),
    "authentication failure": ("Authentication failure", "MEDIUM"),
    "invalid user": ("Invalid user login attempt", "HIGH"),
    "unauthorized access": ("Unauthorized access attempt", "HIGH"),
    "permission denied": ("Permission denied", "LOW"),
    "connection closed": ("Suspicious connection closure", "LOW"),
}

def detect_anomalies(log):
    log = log.lower()
    findings = []

    for pattern, (message, severity) in SUSPICIOUS_PATTERNS.items():
        if pattern in log:
            findings.append((message, severity))

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

