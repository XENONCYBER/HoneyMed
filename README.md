# HoneyMed — Intelligent Honeypot Framework for IoMT Networks

An AI-powered honeypot system designed to protect Internet of Medical Things (IoMT) infrastructure by emulating medical devices, capturing attack data, and classifying threats in real-time using Machine Learning.

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                    LAYER 4: DASHBOARD                            │
│    Streamlit UI  ←→  REST API  ←→  Threat Intelligence Feed     │
└────────────────────────────┬─────────────────────────────────────┘
                             │
┌────────────────────────────┴─────────────────────────────────────┐
│                   LAYER 3: ML INFERENCE ENGINE                   │
│    Random Forest / XGBoost  →  Real-Time Classification          │
│    Predictions: Benign | DoS | PortScan | BruteForce | Recon    │
└────────────────────────────┬─────────────────────────────────────┘
                             │
┌────────────────────────────┴─────────────────────────────────────┐
│                LAYER 2: DATA PIPELINE                            │
│    Feature Extraction  →  SHA-256 Hashing  →  SQLite Storage     │
│    (Blockchain-Ready: hashes prepared for Hyperledger Fabric)    │
└────────────────────────────┬─────────────────────────────────────┘
                             │
┌────────────────────────────┴─────────────────────────────────────┐
│               LAYER 1: HONEYPOT (Edge Emulation)                 │
│   ┌──────────┐  ┌──────┐  ┌───────┐  ┌──────┐  ┌───────┐      │
│   │ Web UI   │  │ HL7  │  │ DICOM │  │ MQTT │  │  SSH  │      │
│   │ Port 80  │  │ 2575 │  │ 11112 │  │ 1883 │  │  22   │      │
│   └──────────┘  └──────┘  └───────┘  └──────┘  └───────┘      │
│       VitalSync Pro 3000 — Fake Patient Monitor                  │
└──────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
mini/
├── main.py                    # Master entry point
├── config/
│   └── settings.yaml          # Central configuration
├── honeypot/                  # Layer 1: Edge Emulation
│   ├── run_honeypot.py        # Orchestrator — starts all services
│   ├── services/
│   │   ├── web_portal.py      # Flask web UI (fake patient monitor)
│   │   ├── hl7_listener.py    # HL7 MLLP protocol honeypot
│   │   ├── dicom_listener.py  # DICOM PACS honeypot
│   │   ├── mqtt_listener.py   # MQTT IoT broker honeypot
│   │   └── ssh_listener.py    # SSH embedded device honeypot
│   ├── templates/             # HTML templates (medical device UI)
│   └── static/css/            # Medical device CSS theme
├── pipeline/                  # Layer 2: Data Pipeline
│   ├── feature_extractor.py   # Raw logs → ML features (+ SHA-256)
│   └── realtime_pipeline.py   # Continuous processing loop
├── ml_engine/                 # Layer 3: AI/ML Inference
│   ├── trainer.py             # Train RF/DT/XGBoost classifiers
│   └── predictor.py           # Real-time attack classification
├── dashboard/                 # Layer 4: Visualization
│   ├── api.py                 # REST API (Flask)
│   └── streamlit_app.py       # Streamlit threat dashboard
├── attacks/                   # Phase 2: Attack Simulation
│   ├── attack_simulator.py    # Automated attack scripts
│   └── benign_traffic.py      # Normal traffic generator
├── data/
│   ├── raw/                   # Raw JSON logs
│   ├── processed/             # Feature CSVs
│   └── models/                # Trained ML models (.pkl)
├── logs/                      # JSON-structured logs
├── tests/                     # Unit tests
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Quick Start

> For a complete setup, startup, configuration, Docker, and troubleshooting guide, see **[instructions.md](instructions.md)**.

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Train the ML Model

```bash
python main.py --mode train
```

This generates a synthetic dataset (5,000 samples) and trains Random Forest, Decision Tree, and XGBoost classifiers. The best model is saved to `data/models/`.

### 3. Launch the Full System

```bash
python main.py --mode full
```

This starts:

- **5 honeypot services** (ports 22, 80, 1883, 2575, 11112)
- **Real-time pipeline** (classifies events every 5 seconds)
- **REST API** on port 5001

### 4. Open the Dashboard

```bash
streamlit run dashboard/streamlit_app.py
```

Open `http://localhost:8501` in your browser.

### 5. Simulate Attacks (from another terminal)

```bash
python main.py --mode simulate --target 127.0.0.1
```

Or run specific attacks:

```bash
python attacks/attack_simulator.py --target 127.0.0.1 --attack bruteforce
python attacks/attack_simulator.py --target 127.0.0.1 --attack portscan
python attacks/attack_simulator.py --target 127.0.0.1 --attack dos
python attacks/attack_simulator.py --target 127.0.0.1 --attack hl7
```

## Honeypot Services

| Service        | Port  | Protocol | Emulates                           |
| -------------- | ----- | -------- | ---------------------------------- |
| Web Portal     | 80    | HTTP     | VitalSync Pro 3000 Patient Monitor |
| HL7 Listener   | 2575  | HL7/MLLP | Hospital Information System        |
| DICOM Listener | 11112 | DICOM    | PACS Medical Imaging Server        |
| MQTT Listener  | 1883  | MQTT     | IoT Vital Signs Telemetry          |
| SSH Listener   | 22    | SSH      | Embedded Medical Device Shell      |

## ML Classification

The system classifies traffic into 5 categories:

| Label          | ID  | Description                                |
| -------------- | --- | ------------------------------------------ |
| Benign         | 0   | Normal medical device traffic              |
| DoS            | 1   | Denial of Service flood                    |
| PortScan       | 2   | Port scanning / API enumeration            |
| BruteForce     | 3   | Credential stuffing / login attacks        |
| Reconnaissance | 4   | Protocol-specific probing (HL7/DICOM/MQTT) |

## Blockchain Readiness

Every event processed by the pipeline generates a **SHA-256 hash**. These hashes are stored locally and are designed to be submitted to a **Hyperledger Fabric** blockchain ledger in the future "HoneyChain" extension.

## API Endpoints

| Endpoint                   | Method | Description                   |
| -------------------------- | ------ | ----------------------------- |
| `/api/status`              | GET    | System health check           |
| `/api/events/recent`       | GET    | Recent classified events      |
| `/api/events/stats`        | GET    | Aggregated statistics         |
| `/api/events/search`       | GET    | Search by IP/type/label       |
| `/api/hashes/recent`       | GET    | SHA-256 hashes for blockchain |
| `/api/threat-intelligence` | GET    | IOC threat feed               |

## Docker Deployment

```bash
docker-compose up -d
```

## Running Tests

```bash
python -m pytest tests/ -v
```

## Future: HoneyChain Extension

This project is designed as a plug-and-play module for a larger distributed system:

1. **SHA-256 hashes** → Push to Hyperledger Fabric ledger
2. **ML model input** → Redirect to read from blockchain-verified data
3. **Threat Intelligence API** → Enable cross-hospital threat sharing
4. **Smart contracts** → Auto-consume JSON-formatted logs
