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

The detector scans log entries using rules defined in `rules.json`.

Each rule includes:

| Field | Description |
|-------|-------------|
| Pattern | Keyword or phrase to match |
| Message | Alert description |
| Severity | Initial alert level (LOW / MEDIUM / HIGH) |
| Threshold | Number of matches required |
| Threshold Severity | Severity after threshold escalation |

## Rule Configuration (GUI)

Launch the configuration interface:

```bash
python config_gui.py
```

Features:

- Create and edit detection rules
- Dark mode interface
- Instant save to `rules.json`

## Installation

```bash
git clone https://github.com/codeby-rhythm-sharma/soc-log-anomaly-detector.git
cd soc-log-anomaly-detector
```

## Usage

1. (Optional) Configure rules via GUI:

```bash
python config_gui.py
```

2. Run the detector:

```bash
python detector.py
```

Enter log entries manually or paste log lines. Type `exit` to stop.

## Example

**Input:**
```
Failed password for invalid user admin from 192.168.1.10
```

**Output:**
```
⚠️ Anomalies detected:
🟡 [MEDIUM] Failed password attempt
🔴 [HIGH] Invalid user login attempt
```

Severity escalates based on configured thresholds.

## Sample Logs

Sample SOC log files are provided in the `sample_logs/` directory:

- Contains raw log entries only
- Includes normal, suspicious, and attack-like logs
- Useful for testing detection behavior

To use:
1. Navigate to `sample_logs/`
2. Copy log lines into the detector input
3. Observe detection results

## Contributing

Contributions are welcome.

1. Check Issues labeled `good first issue` or `beginner`
2. Fork the repository
3. Create a feature branch
4. Submit a Pull Request

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `command not found` | Use `python3` instead of `python` |
| Stop the detector | Type `exit` or press `Ctrl + C` |

## License

<<<<<<< HEAD
Command not found?**
Use `python3` instead of `python`

How to stop the detector?**
Type `exit` or press `Ctrl + C`

---
⭐ If you find this project useful, please consider giving it a star!
It helps the project grow and motivates maintenance.

📜 License

Open-source and intended for **educational purposes**.

---

⚠️ Notice

This is the **official repository** maintained by **@codeby-rhythm-sharma**.
Community forks are not officially maintained.
=======
Open-source. Intended for educational purposes.
>>>>>>> fba78b6 (docs: clean README and remove casual language)

## Notice

This is the official repository maintained by [@codeby-rhythm-sharma](https://github.com/codeby-rhythm-sharma). Community forks are not officially maintained.