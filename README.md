# URLIX

> **"See the Link. Spot the Threat."**

URLIX is a high-performance phishing and malicious link detection web application built for an 8-hour hackathon. It combines passive lexical heuristics, structural parsing, and threat intelligence to provide explainable risk assessments and actionable remediation without ever visiting or executing suspicious URLs.

---

## 🛠️ Tech Stack

- **Frontend**: React 19 + Vite 8 + TypeScript
- **Styling**: Tailwind CSS v4 (Cybersecurity Dark Theme)
- **Backend**: Python 3.12 + FastAPI + Uvicorn
- **Detection Engine**: Python (Passive heuristic & intelligence analysis)

---

## 📋 Prerequisites

- **Node.js**: `v20+` or `v24+` (verified on `v24.21.0` with `npm 11.19.0`)
- **Python**: `3.12+` (verified on `Python 3.12.10`)
- **Operating System**: Windows / macOS / Linux

---

## 🚀 Running the Project

Open two terminal sessions from the project root:

### Terminal 1: Backend (FastAPI)

```powershell
# 1. Navigate to the backend directory
cd backend

# 2. Activate the virtual environment
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# (or directly run: .\venv\Scripts\python.exe -m uvicorn main:app --reload --port 8000)

# macOS / Linux:
# source venv/bin/activate

# 3. Start the FastAPI server
uvicorn main:app --reload --port 8000
```

- **Backend URL**: [http://localhost:8000](http://localhost:8000)
- **Health Check**: [http://localhost:8000/api/health](http://localhost:8000/api/health)
- **Interactive Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

### Terminal 2: Frontend (React + Vite)

```powershell
# 1. Navigate to the frontend directory
cd frontend

# 2. Install dependencies (if not already done)
npm install

# 3. Start the development server
npm run dev
```

- **Frontend URL**: [http://localhost:5173](http://localhost:5173)

---

## 🛡️ Core Safety Principles

1. **Zero-Execution Passive Analysis**: URLIX decomposes and assesses URLs strictly through static lexical analysis, domain parsing, and safe network indicators (DNS/whois/reputation feeds). It **never issues HTTP/HTTPS requests** to submitted target URLs.
2. **Transparent Explainability**: Every flagged risk is backed by explicit heuristics (entropy, character obfuscation, IP hosting, brand typosquatting).
3. **No False Certainty**: Absence of known malicious indicators does not automatically classify a link as safe.
4. **No Premature Complexity**: Lightweight architecture designed for rapid iteration without extraneous databases or authentication during the hackathon.

---

## 🗺️ Project Milestones

- [x] **Milestone 1**: Core Project Setup, Vite + React + Tailwind v4 frontend, Python 3.12 virtual environment, FastAPI health endpoint (`/api/health`), frontend-backend communication bridge, verified landing page.
- [ ] **Milestone 2**: Passive Lexical & Structural Detection Engine in Python.
- [ ] **Milestone 3**: Threat Intelligence & Reputation Integrations.
- [ ] **Milestone 4**: Explainable Risk Scoring & Actionable Security Guidance UI.
