# SOC Log Anomaly Detector 🛡️

A beginner-friendly cybersecurity tool designed to detect suspicious patterns in Security Operations Center (SOC) log entries using simple rule-based analysis.

---

## 🚀 Features

* **Pattern Recognition**: Automatically detects common security threats like "failed password", "unauthorized access", and "invalid user".
* **Severity Grading**: Categorizes anomalies by severity (LOW, MEDIUM, HIGH).
* **Beginner Friendly**: Simple, readable Python code easy to understand and extend.
* **Interactive CLI**: Run the tool directly from your terminal.

---

## 🧠 Detection Logic

The tool scans logs for specific keywords and assigns a severity level:

| Keyword / Pattern | Severity | Description |
| :--- | :--- | :--- |
| `invalid user` | **HIGH** 🔴 | Attempts to login with non-existent users |
| `unauthorized access` | **HIGH** 🔴 | Access attempts without proper permissions |
| `failed password` | **MEDIUM** 🟠 | Incorrect password attempts |
| `connection closed` | **LOW** 🟡 | Unexpected or suspicious disconnections |

---

## 🛠️ Setup & Installation

Follow these steps to get the project running on your local machine.

### 1. Prerequisites
You need **Python 3.x** installed. You can check if you have it by running:

```bash
python --version
# OR
python3 --version
```

### 2. Clone the Repository

Open your terminal and run the following commands to download the project:
```bash
git clone [https://github.com/codeby-rhythm-sharma/soc-log-anomaly-detector.git](https://github.com/codeby-rhythm-sharma/soc-log-anomaly-detector.git)
cd soc-log-anomaly-detector
```
---

## 💻 How to Run

Once you are inside the project folder, you can run the detector using Python:

```bash
python detector.py
```
Note: If your system uses python3 by default, use python3 detector.py.

---

## 📝 Usage & Examples

When you run the script, it will ask you to input a log entry. Here are some examples of how the tool analyzes different logs.

### Example 1: High Severity Alert

Input:
```Plaintext
Jun 14 10:05:22 server sshd[2042]: Invalid user admin from 192.168.1.5
```

Output :
```Plaintext
⚠️ Anomalies detected:
- [HIGH] Invalid user login attempt
```

### Example 2: Medium Severity Alert

Input: 
```Plaintext 
Failed password for user root at 10:00 PM
```

Output:
```Plaintext
⚠️ Anomalies detected:
- [MEDIUM] Failed password attempt
```

### Example 3: Normal Log (No Anomaly)

Input:
```Plaintext
System restart successful at 09:00 AM
```

Output:
```Plaintext
✔️ No anomalies detected.
```

---

## 🤝 How to Contribute
We welcome contributions, especially from ACWOC participants!

Please read our CONTRIBUTION GUIDE before you start. It contains important rules about creating branches, commit messages, and pull requests.

Quick Start for Contributors:

- Check the Issues tab for tasks labeled good first issue or beginner.

- Comment on the issue to get it assigned to you.

- Fork the repo, make your changes, and submit a Pull Request (PR).

---

## 📜 License

This project is open-source and available for educational purposes.

---

## ❓ Troubleshooting

**Q: I get a `command not found` error.**

A: Try using `python3` instead of `python`.

**Q: How do I stop the program?**

A: Type `exit` when asked for a log entry, or press `Ctrl + C` on your keyboard to force quit.

---