# SOC Log Anomaly Detector 🛡️

A beginner-friendly cybersecurity project that detects suspicious patterns in SOC (Security Operations Center) log entries using rule-based analysis. This project now features a configurable detection system and a modern GUI for rule management.

---

## 🚀 Features

- **Configurable Detection**: Define custom keywords, patterns, and alert messages.
- **Dynamic Severity Mapping**: Fully customizable severity levels and visual markers (emojis).
- **Threshold-Based Escalation**: Automatically escalate severity based on the number of occurrences (e.g., multiple failed logins).
- **Dark Mode GUI**: A modern, easy-to-use configuration tool for managing your detection rules.
- **Robust Fallback**: Uses sensible internal defaults if configuration files are missing.

---

## 💻 Tech Stack

- Python (with `tkinter` for GUI)

---

## 🧠 Detection Logic

The tool scans logs for patterns defined in `rules.json`. Each rule can have:
- **Pattern**: The keyword to look for.
- **Message**: The alert description displayed to the analyst.
- **Severity**: The initial alert level (e.g., LOW, MEDIUM, HIGH).
- **Threshold**: Number of matches required before escalation.
- **Threshold Severity**: The alert level used once the threshold is met.

---

## 🛠️ Configuration (GUI)

You can manage all your rules visually using the provided configuration tool:

```bash
python config_gui.py
```

### GUI Features:
- **+ New Rule**: Clear the editor to create a fresh detection rule.
- **Dark Mode**: Designed for modern SOC analyst workflows.
- **Instant Persistence**: Save changes directly to `rules.json`.

---

## 💻 How to Run

1. **Clone the repository**:
   ```bash
   git clone https://github.com/codeby-rhythm-sharma/soc-log-anomaly-detector.git
   cd soc-log-anomaly-detector
   ```

2. **(Optional) Configure Rules**:
   Launch the GUI to add or modify detection patterns:
   ```bash
   python config_gui.py
   ```

3. **Run the Detector**:
   Start analyzing log entries:
   ```bash
   python detector.py
   ```

---

## 📝 Usage & Examples

Input:
```Plaintext
Failed password for invalid user admin from 192.168.1.10
```

Output:
```Plaintext
⚠️ Anomalies detected:
🟡 [MEDIUM] Failed password attempt
🔴 [HIGH] Invalid user login attempt
```

*Note: If thresholds are set, the output will reflect the escalated severity and match count.*

---

## 🔐 Current Focus
- Cybersecurity tooling in Python
- Beginner-friendly open-source projects
- Log analysis and threat detection

---

## 🤝 Open Source Contributions

This project is part of ACWOC and welcomes beginner contributions.

- Check the Issues tab for tasks labeled `good first issue` or `beginner`.
- Fork the repo, make your changes, and submit a Pull Request (PR).

---

## 📜 License

This project is open-source and available for educational purposes.

---

## ❓ Troubleshooting

**Q: I get a `command not found` error.**
A: Try using `python3` instead of `python`.

**Q: How do I stop the program?**
A: Type `exit` when asked for a log entry, or press `Ctrl + C` on your keyboard.

## ⚠️ Notice
This is the official repository maintained by @codeby-rhythm-sharma.
Any forks are community copies and are not officially maintained.

