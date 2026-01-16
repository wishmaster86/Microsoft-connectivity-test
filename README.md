# Microsoft Connectivity Test

A comprehensive **Microsoft 365 network connectivity analysis tool** that validates DNS, TCP, TLS, and TLS Inspection behavior against the official Microsoft Endpoint list, and visualizes the results in a modern, human‑friendly web dashboard.

This project is designed for **network engineers, security teams, and system administrators** who need deep visibility into why Microsoft 365 connectivity succeeds or fails in real‑world enterprise networks.

---

## ✨ Features Overview

### Python Analyzer Script

* Downloads the **official Microsoft Endpoint JSON** dynamically
* Multithreaded connectivity testing (DNS → TCP → TLS)
* TLS handshake validation
* TLS inspection detection
* Retry logic with exponential backoff + jitter
* IPv4 & IPv6 awareness
* Rich failure classification (DNS / TCP / TLS / TLS Inspection)
* Detailed troubleshooting hints & recommended actions
* Environment metadata capture
* Machine‑readable JSON output
* CI‑friendly exit codes

### Web Dashboard

* Loads analyzer JSON output directly in the browser
* Beautiful dark UI with icons and color‑coding
* Summary statistics & health indicators
* Search and filter by service, target, or failure type
* IPv6 visibility toggle
* Tooltips with full error details
* Export filtered results to CSV

---

## 📂 Repository Structure

```
Microsoft-Connectivity-Test/
├── Microsoft_connectivity_test.py   # Main analyzer script
├── microsoft-worldwide.json         # Downloaded Microsoft source file
├── connection_results.json          # Generated output
├── connection_test.log              # Detailed execution log
├── dashboard.html                   # Web visualization
└── README.md                        # This file
```

---

## 🚀 Getting Started

### Requirements

* Python **3.10+**
* Internet access (to download Microsoft endpoint list)

### Install Dependencies

```bash
pip install requests
```

(All other modules are from the Python standard library.)

---

## ▶️ Running the Analyzer

```bash
python Microsoft_connectivity_test.py
```

This will:

1. Download the Microsoft endpoint list
2. Test all DNS / IP / port combinations
3. Generate:

   * `connection_results.json`
   * `connection_test.log`

---

## 🧠 What the Script Tests

For each Microsoft service endpoint:

1. **DNS Resolution**

   * Detects name resolution failures

2. **TCP Connectivity**

   * Tests firewall and routing reachability

3. **TLS Handshake**

   * Validates TLS negotiation
   * Captures protocol version, cipher, and certificate info

4. **TLS Inspection Detection**

   * Detects untrusted CA interception
   * Detects hostname mismatches

5. **Retry Behavior**

   * Retries failed connections
   * Uses exponential backoff with jitter

---

## ❌ Failure Classification

| Type           | Meaning                | Typical Cause                   |
| -------------- | ---------------------- | ------------------------------- |
| DNS            | Name resolution failed | DNS misconfiguration / firewall |
| TCP            | Connection blocked     | Firewall / routing              |
| TLS            | Handshake failed       | Old TLS stack / cert issues     |
| TLS_INSPECTION | Intercepted TLS        | SSL inspection device           |

Each failure includes:

* Error code
* Full error message
* Probable cause
* Recommended action

---

## 📄 JSON Output Structure

```json
{
  "environment": { ... },
  "summary": { ... },
  "services": { ... },
  "results": [ ... ]
}
```

### Summary Section

* Total tests
* Success / failure counts
* Failures by type
* Average latency

### Results Section

Each test includes:

* Service name
* Target (DNS or IP)
* Port
* Required flag
* Success status
* Failure classification
* Retry information
* Timing breakdown
* TLS certificate details (if applicable)

---

## 🌐 Web Dashboard Usage

### Open the Dashboard

Simply open:

```text
dashboard.html
```

No server required — runs fully client‑side.

---

### Load Results

* Click **Choose File**
* Select `connection_results.json`

---

### Dashboard Features

#### 📊 Summary Cards

* Total tests
* Successful / failed connections
* Average latency
* Failure counts per type

#### 🔍 Search & Filters

* Search by service or target
* Filter by failure type
* Toggle IPv6 visibility

#### 🧾 Detailed Table

* Color‑coded status
* Failure badges
* Tooltips with full error text

#### 📤 Export to CSV

* Exports only the **currently filtered view**

---

## 🧪 Exit Codes (Automation‑Friendly)

| Exit Code | Meaning                 |
| --------- | ----------------------- |
| 0         | All tests successful    |
| 1         | Generic failures        |
| 10        | DNS failures detected   |
| 20        | TLS inspection detected |

Exit codes are emitted **only after full processing completes**.

---

## 🛡️ Recommended Use Cases

* Microsoft 365 connectivity troubleshooting
* Firewall rule validation
* TLS inspection verification
* Network readiness assessments
* Change impact analysis
* CI/CD health checks

---

## 🧩 Design Philosophy

This tool is intentionally:

* **Deterministic** – same inputs, same results
* **Explainable** – every failure includes guidance
* **Offline‑friendly** – dashboard works without backend
* **Enterprise‑grade** – suitable for audits and automation

---

## 🏆 Future Enhancements (Ideas)

* Historical comparisons (diff mode)
* Charts and trend analysis
* Service SLA scoring
* Required‑only health checks
* JSON schema validation
* Dark/light theme toggle

---

## 📜 License

MIT License — free to use, modify, and share.

---

## 🙌 Credits

* Microsoft Endpoint API
* Python standard library
* Font Awesome icons

---

If you find this tool useful, consider starring the repository ⭐

Happy troubleshooting!
