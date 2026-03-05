# 🛡 Mini SIEM / SOC Dashboard

A production-style Security Operations Center (SOC) dashboard built with React. Designed to demonstrate real SOC analyst workflows, log analysis, and threat detection skills.

![Screenshot](https://via.placeholder.com/800x450/010409/58a6ff?text=Mini+SIEM+Dashboard)

---

## ✨ Features

| Feature | Description |
|---|---|
| 📊 **Dashboard** | Alert counts by severity, event timeline, top offending IPs |
| 🚨 **Alert Feed** | Real-time-style log feed with search + severity filter |
| 🗂 **Case Management** | Open/Investigating/Closed cases with analyst assignment |
| 📝 **Notes Timeline** | Per-case investigation notes with timestamps |
| 📁 **PDF Export** | One-click incident report generation |
| ⚔️ **MITRE ATT&CK** | Every alert mapped to ATT&CK technique IDs |

---

## 🔍 Real Log Formats

The dashboard uses authentic log formats hiring managers recognize:

- **Windows Security Event Logs** — Event IDs 4624, 4625, 4672, 4688, 4698
- **Apache Access Logs** — HTTP methods, status codes, User-Agent strings
- **SSH Auth Logs** — Failed/accepted auth, session commands

---

## ⚔️ MITRE ATT&CK Coverage

| Technique | ID | Tactic |
|---|---|---|
| Brute Force | T1110 | Credential Access |
| Password Guessing | T1110.001 | Credential Access |
| Password Spraying | T1110.003 | Credential Access |
| Valid Accounts | T1078 | Defense Evasion |
| Windows Command Shell | T1059.003 | Execution |
| Unix Shell | T1059.004 | Execution |
| Exploitation for Privilege Escalation | T1068 | Privilege Escalation |
| Scheduled Task | T1053.005 | Persistence |
| Remote Services: SSH | T1021.004 | Lateral Movement |
| Exploit Public-Facing Application | T1190 | Initial Access |
| Credentials in Files | T1552.001 | Credential Access |

---

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

Open [http://localhost:5173](http://localhost:5173)

---

## 🗂 Project Structure

```
mini-siem-dashboard/
├── src/
│   ├── App.jsx          # Main dashboard component
│   ├── main.jsx         # React entry point
│   └── data/
│       └── logs.js      # Realistic log data (Windows, Apache, SSH)
├── index.html
├── vite.config.js
└── package.json
```

---

## 🧠 Skills Demonstrated

- **Log Analysis** — Parsing and triaging Windows, Apache, SSH logs
- **Threat Detection** — Correlation rules (brute force → success, dropper detection)
- **MITRE ATT&CK** — Technique mapping and tactic understanding
- **SOC Workflow** — Case lifecycle management, escalation, closure
- **Incident Response** — Timeline reconstruction, evidence documentation

---

## 📌 Roadmap

- [ ] Live log ingestion via WebSocket
- [ ] Elasticsearch backend integration
- [ ] Sigma rule detection engine
- [ ] User authentication (RBAC)
- [ ] Alert correlation engine

---

*Built as a portfolio project demonstrating SOC analyst skills. Log data is simulated for demonstration purposes.*
