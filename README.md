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


Make sure you see the big `# Login Anomaly Fraud Detector 🛡️` at the top in the editor.

---

## 🪜 STEP 5 – Save your changes (Commit)

1. Scroll **down to the bottom** of the page.
2. In the **“Commit changes”** section:
   - In the small **Commit message** box, type:
     ```text
     Fix README formatting and structure
     ```
   - Leave everything else as-is (Commit directly to the `main` branch).
3. Click the green button:

   > **Commit changes**

---

## 🪜 STEP 6 – Check how it looks

1. GitHub will take you back to the main repo page.
2. Scroll down under the file list.
3. You should now see:
   - Big bold title  
   - Nicely formatted sections  
   - Bullets and headings  

If you see that, you’re done ✅

---

If you want, paste a screenshot of how your README looks now, and I’ll tell you exactly how I’d talk about this repo to a recruiter.
::contentReference[oaicite:0]{index=0}
