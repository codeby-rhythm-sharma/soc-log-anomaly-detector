<div align="center">

# SOC Log Anomaly Detector  ⚠️️🔍

### Detection Engineering Framework for Security Monitoring & Threat Analysis

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=21&pause=2600&color=C8A27C&center=true&vCenter=true&width=950&lines=Detection+Engineering+Workflows;SOC+Monitoring+and+Alert+Analysis;Rule-Based+Threat+Detection;Security+Event+Classification;Open+Source+Maintained+Project" />

<br>

<img src="https://img.shields.io/badge/Threat%20Detection-Rule%20Based-C8A27C?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Alerting-Severity%20Classification-black?style=for-the-badge"/>
<img src="https://img.shields.io/badge/SOC-Workflow%20Simulation-C8A27C?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Open%20Source-Project%20Maintainer-black?style=for-the-badge"/>

</div>

---

## Overview

SOC Log Anomaly Detector is a security monitoring and detection-engineering framework designed to identify suspicious activity patterns within system and authentication logs through configurable rule-based analysis.

The project simulates core Security Operations Center (SOC) workflows by analyzing security events, classifying threat severity, generating alerts, and escalating repeated suspicious behavior through threshold-based detection mechanisms.

Built with flexibility and extensibility in mind, the framework enables security practitioners, students, and contributors to experiment with detection logic, alert prioritization, and incident-monitoring workflows in a practical environment.

---

## Detection Highlights

| Capability              | Implementation                      |
| ----------------------- | ----------------------------------- |
| Threat Detection        | Rule-Based Security Event Analysis  |
| Alerting                | Configurable Alert Generation       |
| Severity Classification | LOW • MEDIUM • HIGH                 |
| Escalation Logic        | Threshold-Based Severity Escalation |
| Detection Rules         | Dynamic JSON-Based Configuration    |
| Monitoring Workflow     | SOC-Oriented Event Analysis         |
| Contributor Support     | Open Source Maintained Project      |

---

## Detection Workflow

```text
Security Log Entry
        │
        ▼
Pattern Matching Engine
        │
        ▼
Rule Validation
        │
        ▼
Severity Classification
        │
        ▼
Threshold Evaluation
        │
        ▼
Alert Generation
        │
        ▼
Escalated Security Event
```

The framework processes incoming log events, evaluates them against configurable detection rules, assigns an initial severity level, and automatically escalates alerts when repeated suspicious activity exceeds defined thresholds.

---

## Core Detection Engine

### Rule-Based Threat Detection

* Detects suspicious behavior through configurable pattern-matching rules
* Supports security-event identification without modifying application code
* Enables rapid experimentation with custom detection logic

### Severity Classification

* Categorizes alerts into LOW, MEDIUM, and HIGH severity levels
* Improves analyst visibility into potentially malicious activity
* Supports structured alert prioritization workflows

### Threshold-Based Escalation

* Tracks repeated occurrences of suspicious behavior
* Automatically increases severity when detection thresholds are exceeded
* Simulates realistic SOC alert-management workflows

### Dynamic Rule Configuration

* Detection rules are managed through a centralized JSON configuration
* Supports customizable patterns, alert messages, thresholds, and severity mappings
* Allows security analysts to refine detection behavior efficiently

---

## Security Monitoring Use Cases

### Authentication Monitoring

Detect failed login attempts, invalid-user activity, and repeated authentication failures.

### Threat Hunting Workflows

Identify suspicious indicators and recurring attack patterns through log inspection.

### Security Operations Center (SOC) Simulation

Model real-world alerting and incident-monitoring workflows within a controlled environment.

### Detection Engineering Practice

Design, test, and improve detection logic using configurable rule sets and escalation strategies.

---

## Example Detection Scenario

### Input Log

```text
Failed password for invalid user admin from 192.168.1.10
```

### Detection Output

```text
[MEDIUM] Failed Password Attempt
[HIGH] Invalid User Login Attempt
```

Repeated occurrences automatically trigger threshold-based severity escalation according to configured detection policies.

---

## Detection Rule Structure

Each rule consists of:

| Component          | Purpose                                |
| ------------------ | -------------------------------------- |
| Pattern            | Keyword or event signature to detect   |
| Message            | Alert generated when matched           |
| Severity           | Initial alert classification           |
| Threshold          | Required occurrences before escalation |
| Threshold Severity | Severity after threshold breach        |

This design enables flexible and extensible security-event monitoring without modifying core detection logic.

---

## Technology Stack

### Detection & Analysis

* Rule-Based Detection
* Pattern Matching
* Alert Classification
* Threshold Escalation Logic

### Development

* Python
* JSON Configuration Management

### Interface & Configuration

* Tkinter GUI
* Dynamic Rule Management
* Security Workflow Configuration

---

## Repository Structure

```text
soc-log-anomaly-detector/
│
├── sample_logs/                 # Sample security logs
├── detector.py                  # Detection engine
├── config_gui.py                # Rule configuration interface
├── rules.json                   # Detection rule definitions
├── README.md
└── LICENSE
```

---

## Open Source Maintenance

This repository was actively maintained as part of community-driven open-source initiatives, providing contributors with opportunities to participate in security-focused software development and collaborative engineering practices.

Project maintenance responsibilities included:

* Reviewing and merging community pull requests
* Managing contributor workflows and project issues
* Improving project documentation and onboarding
* Supporting beginner contributors during open-source programs
* Maintaining code quality and repository structure
* Guiding feature enhancements and project improvements

The project served as both a security-engineering initiative and a collaborative open-source learning environment.

---

## Future Enhancements

* Regex-Based Detection Rules
* MITRE ATT&CK Technique Mapping
* Multi-Source Log Ingestion
* SIEM-Inspired Monitoring Dashboard
* Statistical Anomaly Detection Models
* Security Event Correlation Engine
* Threat Intelligence Feed Integration

---

## Contributors

### Project Maintainer

**Rhythm Sharma**

### Community Contributors

Contributions from open-source participants helped improve functionality, documentation, and overall project quality.

---

## License

Licensed under the MIT License.

---

<div align="center">

### Detection Engineering • Security Monitoring • Open Source Collaboration

<br>

<a href="https://github.com/codeby-rhythm-sharma">
<img src="https://img.shields.io/badge/More%20Security%20Projects-C8A27C?style=for-the-badge&logo=github&logoColor=black"/>
</a>

</div>


