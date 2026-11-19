# HoneyMed — Setup and Usage Instructions

HoneyMed is a self-contained IoMT (Internet of Medical Things) honeypot lab. It emulates a fake medical device network, captures attacker interactions, classifies them with machine learning, and displays the results in a Streamlit dashboard.

This guide covers how to install, start, use, test, and stop the project.

> **Lab use only.** Run the honeypot and attack simulator only on machines and networks you own. Do not expose it directly to the public internet.

---

## TL;DR — fastest reliable start (Docker)

Docker is the quickest path because the included image uses Python 3.11, which matches the ML dependencies.

```bash
# 1. Build the image
docker compose build

# 2. Train the model once (writes into ./data/models)
docker compose run --rm honeypot python main.py --mode train

# 3. Start honeypot + pipeline + API + dashboard
docker compose up -d

# 4. Open the dashboard
# http://localhost:8501
```

Generate activity in a second terminal:

```bash
docker compose exec honeypot python attacks/attack_simulator.py --target 127.0.0.1 --attack all
```

Alternatively, run the simulator from the host if its Python dependencies are installed:

```bash
python attacks/attack_simulator.py --target 127.0.0.1 --attack all
```

Wait ~5–10 seconds and refresh the dashboard. Stop everything with:

```bash
docker compose down
```

If you prefer to run the project directly with Python, follow [Quick start (native Python)](#3-quick-start-native-python).

---

## 1. What starts when you run HoneyMed

| Layer | Component | Default port | Purpose |
| ----- | --------- | ------------ | ------- |
| 1 | Web portal honeypot | `80` | Fake "VitalSync Pro 3000" patient monitor UI |
| 1 | SSH honeypot | `22` | Fake embedded medical-device SSH banner |
| 1 | MQTT honeypot | `1883` | Fake IoT vitals telemetry broker |
| 1 | HL7/MLLP honeypot | `2575` | Fake hospital HL7 endpoint |
| 1 | DICOM honeypot | `11112` | Fake PACS imaging server |
| 2 | Real-time pipeline | — | Polls captured events, extracts features, hashes them, stores them |
| 3 | ML classifier | — | Classifies events as Benign, DoS, PortScan, BruteForce, or Reconnaissance |
| 4 | Dashboard API | `5001` | REST API for events, stats, hashes, threat intelligence |
| 4 | Streamlit dashboard | `8501` | Live threat-intelligence UI |
| Optional | SIEM API | `5002` | Threat feed for SIEM platforms |

Data flow:

```text
Honeypot interactions
        │
        ▼
Web portal /internal/events  (aggregates honeypot events)
        │
        ▼
Pipeline: feature extraction → ML prediction → SHA-256 hash → SQLite
        │
        ├──► data/classified_events.db ──► Streamlit dashboard
        ├──► Dashboard API (port 5001)
        └──► Blockchain ledger (local SQLite simulation)
```

---

## 2. Prerequisites

### Required

- Linux, macOS, or Windows with WSL/PowerShell.
- **Python 3.11 or 3.12 recommended.** The Docker image uses Python 3.11.
  - Python 3.13/3.14 may work, but some ML packages such as XGBoost may not have compatible wheels yet. If `pip install` fails, use Python 3.11/3.12 or Docker.
- `pip` and `venv`.
- Permission to bind low ports (`80` and `22`), or use Docker, or change the configured ports.

### Ports used

Make sure these are free before starting:

```text
80     web honeypot
22     SSH honeypot
1883   MQTT honeypot
2575   HL7 honeypot
11112  DICOM honeypot
5001   dashboard API
8501   Streamlit dashboard
5002   SIEM API (optional)
```

On a normal Linux desktop, port `22` is often already used by the real OpenSSH server. If so, see [Troubleshooting](#11-troubleshooting).

### Optional

- Docker + Docker Compose — easiest isolated deployment.
- `curl` — for testing the REST API.
- `sqlite3` — for inspecting the database manually.

---

## 3. Quick start (native Python)

From the project root (`HoneyMed/`):

### 3.1 Create a virtual environment and install dependencies

```bash
python3.11 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Confirm the dependencies are available:

```bash
python -c "import flask, pandas, sklearn, streamlit; print('dependencies OK')"
```

### 3.2 Train the ML model first (required)

The pipeline needs a trained model and scaler. If they are missing, classification returns `MODEL_NOT_LOADED` and event storage fails.

```bash
python main.py --mode train
```

What this does:

1. Generates a synthetic dataset of 5,000 samples in `data/processed/`.
2. Trains Random Forest, Decision Tree, and XGBoost classifiers.
3. Saves the best model and scaler to `data/models/`.

Expected files:

```text
data/models/attack_classifier.pkl
data/models/feature_scaler.pkl
data/models/training_results.json
data/models/report_*.txt
```

Verify:

```bash
ls -lh data/models/
```

If XGBoost is not installed, training warns and skips it; Random Forest / Decision Tree still train.

### 3.3 Start the honeypot, pipeline, and API

Ports `80` and `22` are privileged, so use `sudo`:

```bash
sudo .venv/bin/python main.py --mode full
```

Alternative on Linux: grant the virtualenv Python permission to bind low ports once, then run without `sudo`:

```bash
sudo setcap 'cap_net_bind_service=+ep' "$(readlink -f .venv/bin/python)"
.venv/bin/python main.py --mode full
```

`setcap` applies to the underlying Python interpreter, so use it only on a machine you control. You can remove it later with `sudo setcap -r "$(readlink -f .venv/bin/python)"`.

Keep this terminal open. You should see:

```text
[1/3] Starting Honeypot Services...
[2/3] Starting Real-Time Pipeline...
[3/3] Starting Dashboard API...
All systems running!
```

Check that the services are live:

```bash
curl http://127.0.0.1:80/api/v1/device/info
curl http://127.0.0.1:5001/api/status
```

### 3.4 Start the dashboard (second terminal)

`--mode full` does **not** start the Streamlit UI. Start it separately:

```bash
source .venv/bin/activate
python -m streamlit run dashboard/streamlit_app.py
```

Or:

```bash
python main.py --mode dashboard
```

Open <http://localhost:8501> in a browser.

You can also open the fake device itself at <http://localhost/>. Its login page always rejects credentials by design and records the attempt.

### 3.5 Generate demo attacks (third terminal)

With the full system running:

```bash
python main.py --mode simulate --target 127.0.0.1
```

Or run one attack type at a time:

```bash
python attacks/attack_simulator.py --target 127.0.0.1 --attack portscan
python attacks/attack_simulator.py --target 127.0.0.1 --attack bruteforce
python attacks/attack_simulator.py --target 127.0.0.1 --attack dos
python attacks/attack_simulator.py --target 127.0.0.1 --attack hl7
python attacks/attack_simulator.py --target 127.0.0.1 --attack mqtt
python attacks/attack_simulator.py --target 127.0.0.1 --attack dicom
python attacks/attack_simulator.py --target 127.0.0.1 --attack api
python attacks/attack_simulator.py --target 127.0.0.1 --attack all
```

The pipeline polls every 5 seconds. Wait ~5–10 seconds, then refresh the dashboard. Events should appear under the attack labels with SHAs and confidence scores.

> The pipeline ignores events that existed before it started. If you launched attacks during startup, generate a few more after the pipeline reports `Pipeline started`.

### 3.6 Verify the pipeline and API

```bash
curl http://127.0.0.1:5001/api/status
curl "http://127.0.0.1:5001/api/events/recent?limit=10"
curl "http://127.0.0.1:5001/api/events/recent?limit=10&attacks_only=true"
curl http://127.0.0.1:5001/api/events/stats
curl http://127.0.0.1:5001/api/hashes/recent
```

Optional direct database check:

```bash
sqlite3 data/classified_events.db \
  "SELECT id, timestamp, attacker_ip, service, label, confidence FROM classified_events ORDER BY id DESC LIMIT 10;"
```

---

## 4. Run modes

`main.py` is the master entry point.

| Command | What it starts | Needs root? |
| ------- | -------------- | ----------- |
| `python main.py --mode train` | Generate synthetic data and train ML models | No |
| `python main.py --mode full` | Honeypot + pipeline + dashboard API | Yes, for ports 80/22 |
| `python main.py --mode honeypot` | Only the five honeypot services | Yes, for ports 80/22 |
| `python main.py --mode pipeline` | Only the real-time pipeline | No |
| `python main.py --mode api` | Only the dashboard REST API on `5001` | No |
| `python main.py --mode dashboard` | Only the Streamlit UI on `8501` | No |
| `python main.py --mode simulate` | Attack simulator against `--target` | No |
| `python main.py --mode hybrid-train` | Train on public + custom datasets (see note below) | No |
| `python main.py --mode blockchain` | Local blockchain/chaincode demo | No |
| `python main.py --mode siem-api` | SIEM API on `5002` | No |
| `python main.py --mode siem-push` | Push threats to configured SIEMs | No |

Useful individual-development flows:

```bash
# Terminal 1: honeypot only
sudo .venv/bin/python main.py --mode honeypot

# Terminal 2: pipeline only (must point at the web honeypot)
.venv/bin/python main.py --mode pipeline

# Terminal 3: API only
.venv/bin/python main.py --mode api

# Terminal 4: dashboard only
.venv/bin/python -m streamlit run dashboard/streamlit_app.py
```

> **Hybrid-training note:** `main.py --mode hybrid-train` currently calls an outdated
> `HybridTrainer` wrapper. Use the module directly instead:
>
> ```bash
> python -m ml_engine.hybrid_trainer --public-dir data/public_datasets --synthetic
> ```

If you change the web honeypot port from `80`, point the pipeline at it:

```bash
HONEYPOT_URL=http://127.0.0.1:8080 python main.py --mode pipeline
```

---

## 5. Using the dashboard

Open <http://localhost:8501>.

The dashboard reads directly from `data/classified_events.db`, so it updates as the pipeline inserts events.

Main sections:

- **Top metrics** — total events, attack count, unique attacker IPs, average confidence, recent attacks.
- **Attack distribution** — counts by label (`Benign`, `DoS`, `PortScan`, `BruteForce`, `Reconnaissance`).
- **Live events table** — timestamp, attacker IP, service, event type, prediction, confidence.
- **Timeline / attacker views** — activity trends and top source IPs.
- **Blockchain hashes** — SHA-256 values generated for each event.
- **Filters** — show/hide benign traffic, filter by IP prefix.
- **Auto-refresh** — select 3–60 seconds in the sidebar.

The fake patient-monitor UI is at <http://localhost/>. The login always fails intentionally. Useful bait endpoints:

```text
http://localhost/login
http://localhost/dashboard
http://localhost/api/v1/device/info
http://localhost/api/v1/vitals/current
http://localhost/api/v1/firmware/update
http://localhost/api/v1/config
http://localhost/hl7
```

These all record events and are classified by the pipeline.

---

## 6. REST API

The dashboard API runs on `http://localhost:5001`.

| Endpoint | Method | Description |
| -------- | ------ | ----------- |
| `/api/status` | GET | Health check, total events, total attacks |
| `/api/events/recent` | GET | Recent events (`?limit=50&attacks_only=true`) |
| `/api/events/stats` | GET | Label distribution, top attackers, timeline stats |
| `/api/events/search` | GET | Search by IP, service, label, event type |
| `/api/hashes/recent` | GET | Recent SHA-256 hashes for blockchain readiness |
| `/api/threat-intelligence` | GET | IOC-style threat feed |

Examples:

```bash
curl http://127.0.0.1:5001/api/status

curl "http://127.0.0.1:5001/api/events/search?label=BruteForce&limit=20"

curl "http://127.0.0.1:5001/api/events/recent?limit=5&attacks_only=true"
```

The API is for external consumers and integrations. The Streamlit dashboard does not require it because it reads SQLite directly.

---

## 7. Configuration

The central config file is `config/settings.yaml`. Restart the affected component after editing it.

Key sections:

- `honeypot.web_portal` — fake device name, model, firmware, host, port.
- `honeypot.hl7_listener` — HL7 port (`2575`).
- `honeypot.dicom_listener` — DICOM port (`11112`) and AE title.
- `honeypot.mqtt_listener` — MQTT port (`1883`) and topics.
- `honeypot.ssh_listener` — SSH port (`22`) and banner.
- `pipeline.flow_interval_seconds` — classification polling interval (default `5`).
- `ml_engine.model_path` / `scaler_path` — trained model locations.
- `ml_engine.confidence_threshold` — alert threshold (default `0.7`).
- `security.enable_encryption` — AES-256-GCM storage of raw events.
- `blockchain.mode` — `local` (SQLite simulation) or `fabric`.
- `siem.enabled_platforms` — add `splunk`, `qradar`, or `elastic`.
- `siem.auto_response.mode` — `simulate` or `enforce`.

### Changing ports

If port `80` or `22` is unavailable, edit `config/settings.yaml`:

```yaml
honeypot:
  web_portal:
    port: 8080
  ssh_listener:
    port: 2222
```

Then start the pipeline against the new web port:

```bash
HONEYPOT_URL=http://127.0.0.1:8080 python main.py --mode pipeline
```

If you use `--mode full` instead of a separate honeypot and pipeline, export the
variable first (and preserve it through `sudo`):

```bash
export HONEYPOT_URL=http://127.0.0.1:8080
sudo -E .venv/bin/python main.py --mode full
```

Important: the attack simulator uses hard-coded default ports (`80`, `22`, `1883`, `2575`, `11112`) in most methods. If you change honeypot ports, either:

- Temporarily change them back for the default demo, or
- Call simulator methods with custom ports from Python, for example:

```python
from attacks.attack_simulator import AttackSimulator

sim = AttackSimulator("127.0.0.1")
sim.attack_bruteforce_web(port=8080)
sim.attack_hl7_injection(port=2575)
sim.save_results()
```

---

## 8. Attack simulation

Run the simulator only against your local honeypot.

```bash
# All attack types (main.py wrapper)
python main.py --mode simulate --target 127.0.0.1

# Or the standalone simulator
python attacks/attack_simulator.py --target 127.0.0.1 --attack all
```

Attack types:

| `--attack` | What it does | Main target port |
| ---------- | ------------ | ---------------- |
| `portscan` | Scans common and medical ports | multiple |
| `bruteforce` | Credential stuffing against the fake web login | `80` |
| `dos` | HTTP flood plus rapid TCP connections | `80` |
| `hl7` | Crafted HL7 MLLP messages | `2575` |
| `mqtt` | MQTT connect / subscribe / publish probes | `1883` |
| `dicom` | DICOM A-ASSOCIATE requests | `11112` |
| `api` | Enumerates sensitive API paths | `80` |

Simulation results are saved under `data/raw/attack_log_*.json`.

---

## 9. Docker deployment

Docker is the easiest way to get the intended Python 3.11 environment and isolate the stack.

### 9.1 Train inside the image first

The pipeline cannot classify without a model, so train before starting the full stack:

```bash
docker compose build
docker compose run --rm honeypot python main.py --mode train
```

The `./data` volume is mounted into the container, so the model is written to the host's `data/models/`. Because the container runs as root, those files may be root-owned. If you later switch to running natively, fix ownership with `sudo chown -R "$USER":"$USER" data logs`.

### 9.2 Start everything

```bash
docker compose up -d
docker compose ps
docker compose logs -f
```

Open:

- Dashboard: <http://localhost:8501>
- REST API: <http://localhost:5001/api/status>
- Fake device: <http://localhost/>

Generate attacks by executing the simulator inside the running honeypot container:

```bash
docker compose exec honeypot python attacks/attack_simulator.py --target 127.0.0.1 --attack all
```

Or run it from the host if the host Python has the dependencies installed:

```bash
python attacks/attack_simulator.py --target 127.0.0.1 --attack all
```

### 9.3 Stop and reset

```bash
docker compose down
```

Data persists in `./data` and `./logs` because they are bind mounts. Containers run as root, so generated files may be owned by root; use `sudo` for cleanup if needed. To reset the demo state:

```bash
sudo rm -f data/classified_events.db data/blockchain_ledger.db
sudo rm -f logs/*.jsonl
```

Or remove them through a container:

```bash
docker compose run --rm honeypot rm -f \
  data/classified_events.db data/blockchain_ledger.db
```

Then restart. Keep `data/models/` if you do not want to retrain.

### 9.4 Docker port conflicts

If host SSH already uses port `22`, change the compose mapping from `"22:22"` to something like `"2222:22"`. The container still listens on `22` internally; only the host-side port changes. The same applies to `80` if another web server is running:

```yaml
ports:
  - "8080:80"
```

Attack scripts that use default port `80` will then need the custom port or a temporary config change.

---

## 10. Tests

Install `pytest` if it is not already available, then run the unit tests:

```bash
pip install pytest
python -m pytest tests/ -v
```

The tests cover config loading, feature extraction, model training/prediction, encryption, hashing, and privacy behavior.

> **The tests write real project data.** `tests/test_all.py` calls `save_dataset()` and
> `save_model()` with a small 500-sample dataset, overwriting files in `data/processed/`
> and `data/models/`. It also initializes `data/classified_events.db`. After running tests,
> retrain before a demo:
>
> ```bash
> python main.py --mode train
> ```

> Do **not** use `test_script.py` as a test runner. It is an old prototype that imports a removed `monitoring` package and will fail. Use `tests/` instead.

---

## 11. Troubleshooting

### `Permission denied` when binding port 80 or 22

Either run with `sudo`, grant low-port binding capability, or change the ports in `config/settings.yaml`.

```bash
sudo .venv/bin/python main.py --mode full
```

or:

```bash
sudo setcap 'cap_net_bind_service=+ep' "$(readlink -f .venv/bin/python)"
```

### `Address already in use`

Find the process using the port:

```bash
sudo ss -ltnp | grep -E ':(22|80|1883|2575|11112|5001|8501|5002)\b'
```

Common causes:

- Real SSH server on `22` — change the honeypot SSH port or stop the host SSH service temporarily.
- Another web server on `80` — change the web portal port.
- Another HoneyMed instance — stop it or use different ports.

### `ModuleNotFoundError: No module named 'flask'` (or `pandas`, `sklearn`)

The virtual environment is not active or pip installed into a different interpreter:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python -c "import flask, pandas, sklearn; print('OK')"
```

### `MODEL_NOT_LOADED` or a `KeyError: 'is_attack'` in the pipeline

The ML model is missing. Train it, then restart the pipeline:

```bash
python main.py --mode train
# restart main.py --mode full / pipeline
```

Confirm both files exist:

```bash
ls -l data/models/attack_classifier.pkl data/models/feature_scaler.pkl
```

### Dashboard is empty

Check in this order:

1. Is the pipeline running and reporting `Model loaded: True`?
2. Did you generate attacks **after** the pipeline started? It intentionally skips old events at startup.
3. Wait at least one polling interval (5 seconds by default), then refresh or enable auto-refresh.
4. Is the dashboard pointed at the same `data/classified_events.db`? Check the path shown in the sidebar.

```bash
curl http://127.0.0.1:5001/api/status
sqlite3 data/classified_events.db "SELECT COUNT(*) FROM classified_events;"
```

### `pip install` fails on Python 3.13/3.14

Use Python 3.11 or 3.12, or use Docker:

```bash
docker compose build
docker compose run --rm honeypot python main.py --mode train
docker compose up -d
```

XGBoost is optional; if it fails to install, the trainer skips it and still produces a working Random Forest model.

### `streamlit: command not found`

Run it as a module:

```bash
python -m streamlit run dashboard/streamlit_app.py
```

### Docker permission denied

Ensure the Docker daemon is running and your user can access it:

```bash
docker info
```

If needed, run with `sudo` or add your user to the `docker` group (log out and back in afterward).

### The SSH honeypot does not behave like a real SSH server

It is a banner-level emulator only. It captures the SSH version string and raw data; it does not provide an interactive shell. This is intentional.

---

## 12. Data, logs, and reset

Generated files:

```text
data/processed/            synthetic training dataset CSV
data/models/               trained model, scaler, reports
data/classified_events.db  classified events (SQLite)
data/blockchain_ledger.db  local blockchain simulation
logs/*.jsonl               structured JSON logs with SHA-256 hashes
data/raw/attack_log_*.json attack simulator output
```

Useful inspection commands:

```bash
# Recent classified events
sqlite3 data/classified_events.db \
  "SELECT id, timestamp, attacker_ip, service, label, confidence, is_attack FROM classified_events ORDER BY id DESC LIMIT 20;"

# Count by label
sqlite3 data/classified_events.db \
  "SELECT label, COUNT(*) FROM classified_events GROUP BY label;"

# Recent pipeline log lines
tail -n 50 logs/pipeline_realtime.jsonl
```

Full reset (keeps dependencies and source):

```bash
rm -f data/classified_events.db data/blockchain_ledger.db
rm -f logs/*.jsonl
rm -rf data/processed/*.csv data/models/*
```

Then retrain:

```bash
python main.py --mode train
```

---

## 13. Advanced modes

### Hybrid training (public + custom datasets)

Place public CSV datasets in `data/public_datasets/`, then run the trainer module directly:

```bash
python -m ml_engine.hybrid_trainer --public-dir data/public_datasets --synthetic
```

To also include logs captured by your honeypot:

```bash
python -m ml_engine.hybrid_trainer \
  --public-dir data/public_datasets \
  --custom-dir data/raw \
  --synthetic
```

If the public directory is empty, the standard `python main.py --mode train` path is the reliable demo option. The `main.py --mode hybrid-train` wrapper is currently out of date; use the module command above.

### Blockchain / chaincode demo

```bash
python main.py --mode blockchain
```

This uses the local SQLite ledger by default (`blockchain.mode: local`). Real Hyperledger Fabric requires a running Fabric peer and `blockchain.mode: fabric`.

### SIEM API and threat push

```bash
python main.py --mode siem-api
python main.py --mode siem-push
```

The SIEM API runs on port `5002` and serves threat data in formats consumable by Splunk, QRadar, and Elastic. To push to a platform, set the platform credentials in `config/settings.yaml` under `siem:`.

### Auto-response (IP blocking)

Configured under `siem.auto_response` in `config/settings.yaml`:

- `mode: simulate` — logs what would be blocked, does not change firewall rules.
- `mode: enforce` — attempts real blocking. Use only in a controlled lab.

---

## 14. Stop everything

In the terminal running `main.py --mode full`, press `Ctrl+C`.

Stop Streamlit with `Ctrl+C` in its terminal.

Stop Docker:

```bash
docker compose down
```

Check for leftover listeners:

```bash
sudo ss -ltnp | grep -E ':(22|80|1883|2575|11112|5001|8501|5002)\b'
```

---

## 15. Command cheat sheet

```bash
# Setup
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Train (required once)
python main.py --mode train

# Start backend stack (honeypot + pipeline + API)
sudo .venv/bin/python main.py --mode full

# Start dashboard (separate terminal)
python -m streamlit run dashboard/streamlit_app.py

# Simulate attacks (separate terminal)
python main.py --mode simulate --target 127.0.0.1

# Verify
curl http://127.0.0.1:5001/api/status
sqlite3 data/classified_events.db "SELECT COUNT(*) FROM classified_events;"

# Docker
docker compose build
docker compose run --rm honeypot python main.py --mode train
docker compose up -d
docker compose down
```

For architecture details and the research context, see `README.md`.
