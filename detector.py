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
