# SOC Log Anomaly Detector 🛡️

A beginner-friendly cybersecurity project that detects suspicious patterns in SOC (Security Operations Center) log entries using simple rule-based analysis. This project is designed for students who are new to security monitoring and log analysis.

---

## 🚀 Features

- Detects common suspicious log patterns
- Handles authentication failures and unauthorized access attempts
- Simple and readable Python code
- Easy to extend with new detection rules

---

## 💻 Tech Stack

- Python

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

## 💻 How to Run

Open your terminal and run the following commands to download the project:
```bash
git clone https://github.com/codeby-rhythm-sharma/soc-log-anomaly-detector.git
cd soc-log-anomaly-detector
```

Once you are inside the project folder, you can run the detector using Python:

```bash
python detector.py
```

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
⚠️ Anomaly detected: invalid user
```

### Example 2: Medium Severity Alert

Input: 
```Plaintext 
Failed password for user root at 10:00 PM
```

Output:
```Plaintext
⚠️ Anomaly detected: failed password
```

### Example 3: Normal Log (No Anomaly)

Input:
```Plaintext
System restart successful at 09:00 AM
```

Output:
```Plaintext
✔️ Log looks normal
```

---

## 🔐 Current Focus
- Cybersecurity tooling in Python
- Beginner-friendly open-source projects
- Log analysis and threat detection

---

## 🤝 Open Source Contributions

This project is part of ACWOC and welcomes beginner contributions.

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
