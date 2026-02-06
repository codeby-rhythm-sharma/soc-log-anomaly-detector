# SOC Log Anomaly Detector

A cybersecurity project that detects suspicious patterns in SOC (Security Operations Center) log entries using rule-based analysis. The project includes a configurable detection system and a GUI for managing detection rules.

## Features

- **Configurable Detection** — Define custom keywords, patterns, and alert messages
- **Dynamic Severity Mapping** — Custom severity levels with visual indicators
- **Threshold-Based Escalation** — Automatically escalates alerts after repeated matches
- **Dark Mode GUI** — Interface for SOC-style workflows
- **Robust Fallbacks** — Uses safe defaults if configuration files are missing

## Tech Stack

- Python
- tkinter (GUI)

## Detection Logic

The detector scans log entries using rules defined in `rules.json`. It supports **timestamp-aware sliding windows**, meaning it can detect multiple occurrences within a specific timeframe.

Each rule includes:

| Field | Description |
|-------|-------------|
| Pattern | Keyword or phrase to match (e.g., `failed password`) |
| Message | Alert description |
| Severity | Initial alert level (LOW / MEDIUM / HIGH) |
| Threshold | Number of matches required to trigger an anomaly |
| Threshold Severity | Severity level after the threshold is reached |
| Time Window | Timeframe (in seconds) to count occurrences (sliding window) |

### Supported Log Format
To use timestamp-based detection, logs should start with an ISO-like timestamp:
`YYYY-MM-DD HH:MM:SS - Log message content`

Example:
`2026-02-06 22:40:05 - Failed password for admin`

If no timestamp is found, the detector uses the system's current time.

## Usage

1. (Optional) Configure rules via GUI:
```bash
python config_gui.py
```

2. Run the detector:
```bash
python detector.py
```

Choose option `1` for manual input or `2` to run against the provided `sample_logs/timestamped_logs.txt`.

## Bonus: SOC Alerting Best Practices
Real-world SOC systems often implement:
- **Alert Suppression:** Don't alert for the same event from the same IP for 5 minutes after the first alert.
- **Contextual Enrichment:** Automatically lookup the geographic location of an IP address.
- **Kill Chain Mapping:** Tagging anomalies with MITRE ATT&CK techniques (e.g., Brute Force).

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `command not found` | Use `python3` instead of `python` |
| Stop the detector | Type `exit` or press `Ctrl + C` |

## License

Open-source and intended for **educational purposes**.

---
⭐ If you find this project useful, please consider giving it a star!
It helps the project grow and motivates maintenance.

## Notice

This is the official repository maintained by [@codeby-rhythm-sharma](https://github.com/codeby-rhythm-sharma). Community forks are not officially maintained.
