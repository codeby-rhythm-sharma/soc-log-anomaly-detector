Bhai 👍 README achha tha, bas thoda cleanup + duplication removal + clarity chahiye tha.
Neeche clean, professional, maintainer-friendly final version de raha hoon — seedha replace kar de👇

---

SOC Log Anomaly Detector 🛡️

A beginner-friendly cybersecurity project that detects suspicious patterns in SOC (Security Operations Center) log entries using rule-based analysis.
The project includes a configurable detection system** and a modern GUI for managing detection rules.



🚀 Features

Configurable Detection – Define custom keywords, patterns, and alert messages
Dynamic Severity Mapping – Custom severity levels with visual markers (emojis)
Threshold-Based Escalation – Automatically escalates alerts after repeated matches
Dark Mode GUI – Clean, modern interface for SOC-style workflows
Robust Fallbacks – Uses safe defaults if configuration files are missing


💻 Tech Stack

Python
tkinter (for GUI)


🧠 Detection Logic

The detector scans log entries using rules defined in `rules.json`.

Each rule includes:

Pattern – Keyword or phrase to match
Message – Alert description
Severity – Initial alert level (LOW / MEDIUM / HIGH)
Threshold – Number of matches required
Threshold Severity – Severity after threshold escalation


🛠️ Rule Configuration (GUI)

Manage detection rules visually using the GUI:

```bash
python config_gui.py
```

GUI Capabilities

Create and edit detection rules
Dark mode interface
Instant save to `rules.json`

---

▶️ How to Run

1️⃣ Clone the Repository

```bash
git clone https://github.com/codeby-rhythm-sharma/soc-log-anomaly-detector.git
cd soc-log-anomaly-detector
```

2️⃣ (Optional) Configure Rules

```bash
python config_gui.py
```

3️⃣ Run the Detector

```bash
python detector.py
```

Type log entries manually or paste log lines.
Type `exit` to stop the program.



📝 Example

Input

```text
Failed password for invalid user admin from 192.168.1.10
`
Output

text
⚠️ Anomalies detected:
🟡 [MEDIUM] Failed password attempt
🔴 [HIGH] Invalid user login attempt


Severity may escalate based on configured thresholds.*

📂 Sample SOC Logs

A sample SOC log file is provided in the `sample_logs/` directory.

Contains **only raw log entries**
Includes **normal, suspicious, and attack-like logs**
Useful for testing and understanding expected log formats

Usage

1. Navigate to `sample_logs/`
2. Copy log lines into the detector input
3. Observe anomaly detection behavior

---

🤝 Open Source Contributions

This project welcomes beginner contributions.

Check **Issues** labeled `good first issue` or `beginner`
Fork the repository
Create a feature branch
Submit a Pull Request

---

❓ Troubleshooting

Command not found?**
Use `python3` instead of `python`

How to stop the detector?**
Type `exit` or press `Ctrl + C`

---

📜 License

Open-source and intended for **educational purposes**.

---

⚠️ Notice

This is the **official repository** maintained by **@codeby-rhythm-sharma**.
Community forks are not officially maintained.


