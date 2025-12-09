# Login Anomaly Fraud Detector 🛡️

This is a beginner-friendly cybersecurity + fraud project.

It simulates a simple **fraud detection use case**: finding suspicious login activity that might indicate **account takeover** or **fraud**.

## What this project does

We use a small CSV file of fake login events (`data/sample_logins.csv`) and run a Python script (`src/detect_fraud.py`) that flags logins as **suspicious** if:

1. A user has multiple failed logins in a row (possible brute-force or password-guessing)
2. A user logs in from a **new country** we have never seen for them (possible stolen credentials)
3. A user logs in at **unusual hours** for normal activity (e.g., 2–4 AM)

The script outputs a simple **report** showing which login events look suspicious and why.

## Why this matters (fraud + cybersecurity)

In real environments, security/fraud teams monitor login activity to detect:

- Account takeover (stolen passwords)
- Bot attacks and credential stuffing
- Suspicious access from unusual locations
- Abnormal behavior patterns

This project is a tiny, simplified version of that concept that is beginner-friendly but still useful to discuss in interviews.

## Project structure

```text
login-anomaly-fraud-detector/
├── README.md
├── data/
│   └── sample_logins.csv
└── src/
    └── detect_fraud.py
