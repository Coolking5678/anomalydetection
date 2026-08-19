# AI-Based Security Log Anomaly Detector

A production-grade, modular Python desktop application that parses Linux SSH
authentication logs, engineers behavioural security features, and uses an
unsupervised **Isolation Forest** model to flag anomalous activity such as
brute-force attacks and off-hours access attempts.

---

## 📂 Project Structure

```
security-log-detector-desktop/
│
├── data/                  # Raw and parsed log files (auto-created)
├── src/
│   ├── __init__.py
│   ├── ingestion.py       # Log downloading & regex parsing
│   ├── features.py        # Feature engineering pipeline
│   ├── model.py           # Isolation Forest wrapper class
│   └── explainer.py       # Human-readable anomaly explanations
├── gui/
│   ├── __init__.py
│   └── app_window.py      # Tkinter / ttk desktop UI
├── main.py                # Application entry point
├── requirements.txt       # External Python dependencies
└── README.md              # This file
```

---

## ⚙️ Prerequisites

- **Python 3.10+** (must have `tkinter` available — standard on most installs)
- `pip` for package installation

> **Windows**: Python from python.org includes `tkinter` by default.  
> **Ubuntu/Debian**: `sudo apt install python3-tk` if needed.

---

## 🚀 Quick Start

### 1. Clone / navigate to the project directory

```bash
cd security-log-detector-desktop
```

### 2. (Recommended) Create a virtual environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Launch the application

```bash
python main.py
```

---

## 🖥️ Using the Application

### Loading a log file

| Option | Steps |
|--------|-------|
| **Download sample** | Click **⬇ Download Sample** — fetches `SSH_2k.log` from Loghub automatically |
| **Local file** | Click **Browse…** and select any `.log` file in standard Linux syslog SSH format |

### Running detection

1. Adjust the **Contamination** slider to set the expected fraction of anomalies  
   (default **3 %** — raise it if you expect a heavily attacked dataset).
2. Click **▶ Run Detection**.
3. The pipeline runs in a background thread so the UI stays responsive.

### Reading results

| Column | Description |
|--------|-------------|
| Timestamp | Event date/time |
| Source IP | Attacker or client IP address |
| Target User | Username targeted in the login attempt |
| Event Type | `FAILED_LOGIN` / `SUCCESS_LOGIN` / `INVALID_USER` / `OTHER` |
| Failures (5m) | Rolling 5-minute failed-attempt count from this IP |
| **Status** | **⚠ THREAT** (red) or **✓ Normal** (white) |
| Anomaly Reason | Top signals that triggered the anomaly flag |

### Exporting threats

Click **⬆ Export Flagged Threats** to save all anomalous rows to a `.csv` file
of your choice.

---

## 🧠 Model Details

| Parameter | Value |
|-----------|-------|
| Algorithm | `sklearn.ensemble.IsolationForest` |
| Estimators | 200 trees |
| Feature scaling | `StandardScaler` (z-score) |
| Contamination | Adjustable (0.01 – 0.15) |

### Engineered features

| Feature | Description |
|---------|-------------|
| `hour` | Hour of the event (0–23) |
| `is_night_access` | 1 if hour < 6 or hour > 22 |
| `rolling_fail_5m` | Failed-attempt count per IP in last 5 minutes |
| `is_admin_target` | 1 if username is `root`, `admin`, `test`, etc. |
| `ip_freq` | Source-IP frequency proportion across the dataset |

---

## 📋 Supported Log Format

Standard Linux/OpenSSH syslog format:

```
Jan  1 03:21:14 hostname sshd[12345]: Failed password for root from 192.168.1.1 port 22 ssh2
Jan  1 03:21:15 hostname sshd[12346]: Invalid user admin from 10.0.0.5 port 45678
Jan  1 08:00:01 hostname sshd[99999]: Accepted password for ubuntu from 172.16.0.1 port 22 ssh2
```

---

## 📦 Dependencies

```
pandas>=2.0.0
scikit-learn>=1.3.0
numpy>=1.24.0
```

> `tkinter` is part of the Python standard library and is **not** listed in
> `requirements.txt`.

---

## 🔒 Licence

MIT — use freely for security research and operations.
