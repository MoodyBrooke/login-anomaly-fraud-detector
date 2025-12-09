# Login Anomaly Fraud Detector 🛡️

A beginner-friendly **cybersecurity + fraud detection** project that simulates how blue teams and fraud analysts spot suspicious login activity and possible account takeover.

This project reads a CSV file of login events, applies a set of detection rules, and produces:

- A **console report** of suspicious login events  
- A **fraud_report.csv** file you can open in Excel or share with others

---

## 🔍 What this project detects

The script analyzes each login event and flags it as suspicious if it matches any of these rules:

### 1. Multiple failed logins in a row
Detects possible:
- Brute-force attacks  
- Password guessing  
- Credential stuffing  

### 2. Logins at unusual hours (2–4 AM)
Flags activity that may indicate:
- Bot behavior  
- Unauthorized access  
- Compromised accounts  

### 3. Logins from a new country for that user
Detects potential **account takeover** when a user suddenly appears in a country they’ve never used before.

### 4. Impossible travel between countries
If the same user logs in from two different countries within a short time window (e.g., **less than 4 hours**), the script flags it as suspicious since no one could realistically travel that fast.

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

## 💬 How to describe this project (resume / interview)

This project simulates how cybersecurity and fraud teams identify potential **account takeover** using login activity patterns.

> I built a Python-based login anomaly detector that flags suspicious behavior such as repeated failed logins, abnormal login times, new-country access, and impossible travel between locations. The script generates both a human-readable report and a CSV fraud report file for analysis.

This project helped me practice:
- Fraud detection logic  
- Log analysis  
- Security automation with Python  
- Writing clear technical documentation

---

## ✅ After pasting, do THIS:

1. Scroll to the bottom
2. In **Commit message**, type:
3. Select:
✅ Commit directly to main branch
4. Click:
✅ **Commit changes**

---

If you want — once that’s done, tell me and I’ll help you:

✅ Write your resume bullets  
✅ Craft a LinkedIn post using this project  
✅ Choose your next cybersecurity project
