# **AI-Powered Application Security Automation Lab (LLM + MCP + AppSec Tools)**
Designed and implemented a secure AI-driven AppSec automation platform using MCP architecture, integrating GitHub PAT-based repository access, multi-tool scanning (SAST, SCA, Secrets), and automated reporting via LLM orchestration.

---

### 🔹 Overview

This project demonstrates a **conversational AI-driven AppSec platform** integrating:

* SAST → Semgrep
* SCA → Grype + Syft
* Secrets → Gitleaks
* DAST → OWASP ZAP (manual + AI analysis)
* Mobile → MobSF + JADX
* LLM → Claude Desktop + MCP + Ollama

---

### 🔹 Architecture

```
Claude Desktop
      ↓
   MCP Server
      ↓
Security Tools (Semgrep, Gitleaks, Grype, ZAP, MobSF)
      ↓
   JSON Results
      ↓
   LLM Analysis (Ollama)
      ↓
 PDF Reports + Dashboard + Defect Tracker
```

---

### 🔹 Key Features

* Chat-driven security testing
* Dual-mode scanning (manual + AI)
* Automated report generation (JSON → PDF)
* Centralized dashboard (Streamlit)
* Defect tracking ready

---

### 🔹 Sample Use Cases

* “Scan my repo for OWASP issues”
* “Analyze latest ZAP results”
* “Generate executive report”

---

### 🔹 Disclaimer

> This project is built for educational and demonstration purposes. All scans are performed on test environments.

---

## 🎯 **What Makes This Stand Out (For Interview)**

✔ Real tool integration (not mock)
✔ LLM + Security combo (rare skill)
✔ End-to-end pipeline (scan → analyze → report → dashboard)
✔ Supports manual + automated workflows

---

## 🔥 Next Upgrade (Optional but Powerful)

* Add Jira API → defect tracking
* Add GitHub webhook → auto scan
* Add Slack alerts
