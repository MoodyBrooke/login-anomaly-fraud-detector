# Login Anomaly Fraud Detector 🛡️

A beginner-friendly **cybersecurity + fraud detection** project that simulates how blue teams and fraud analysts spot suspicious login activity and possible account takeover.

This project reads a CSV file of login events, applies a set of detection rules, and produces:

- A **console report** of suspicious login events
- A **fraud_report.csv** file you can open in Excel or share with others

---

## 🔍 What this project detects

The script analyzes each login event and flags it as **suspicious** if it matches any of these rules:

1. **Multiple failed logins in a row**  
   - Detects possible **brute-force attacks**, password guessing, or credential stuffing.

2. **Logins at unusual hours (2–4 AM)**  
   - Flags activity during “weird hours” that may indicate bots or unauthorized access.

3. **Logins from a new country for that user**  
   - Detects potential **account takeover** when a user suddenly appears in a country they’ve never used before.

4. **Impossible travel between countries**  
   - If the same user logs in from two different countries within a short time window (e.g., **less than 4 hours**), the script flags it as **possible impossible travel**, since they couldn’t realistically travel that fast.

These are simplified versions of checks real fraud and security teams use in production systems.

---

## 🗂 Project structure

```text
login-anomaly-fraud-detector/
├── README.md
├── data/
│   └── sample_logins.csv       # Fake login data
└── src/
    └── detect_fraud.py         # Main fraud detection script
