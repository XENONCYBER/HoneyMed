# HoneyMed Presentation Script

Use this as a talk track. Do not read every sentence word-for-word; use it to keep the story flowing.

## Slide 1: Cover

Good morning everyone. Our project is titled An Intelligent Honeypot Framework for Attack Detection in IoMT Networks. We call the system HoneyMed. The basic idea is simple: instead of waiting for attackers to hit real hospital devices, we create realistic fake medical services, observe the attacker safely, classify the behavior using machine learning, and preserve the evidence locally.

## Slide 2: Contents

I will move from the problem to our design and then to results. First I will explain why IoMT security is different from normal network security. Then I will cover the research gap, requirements, dataset, architecture, model, dashboard, applications, limitations, and future work.

## Slide 3: Introduction

IoMT means Internet of Medical Things. These are connected medical devices such as patient monitors, imaging servers, MQTT-based sensors, and web dashboards used inside hospitals. These systems improve monitoring, but they also increase the attack surface because many medical protocols and devices were not originally designed for hostile internet exposure.

## Slide 4: Problem Statement

The problem we are solving is that normal IDS systems are noisy and generic. They can raise alerts, but they usually do not understand medical protocols like HL7 or DICOM. Healthcare attacks such as ransomware and botnets can affect patient safety, so we need a system that detects attacker behavior early, explains it, and stores evidence cleanly.

## Slide 5: Objectives

Our objectives are fourfold. First, build believable IoMT decoys. Second, capture and enrich attacker telemetry. Third, classify attacks in real time using ML. Fourth, show the results through a dashboard and SIEM-ready response path so that the output is useful to an analyst, not just stored in a file.

## Slide 6: Literature Survey 1

The first set of papers shows why the field needs this project. Deep learning IDS models can be accurate, but they are heavy. Healthcare deception frameworks exist, but they often need manual log analysis. Blockchain approaches protect stored records, but they do not actively capture attacks.

## Slide 7: Literature Survey 2

This set focuses on SIEM and protocol-specific work. Some systems connect honeypots to SIEM, and some study DICOM ransomware or HL7/DICOM weaknesses. The gap is that these are often either reactive, centralized, or not implemented as a live IoMT edge honeypot.

## Slide 8: Literature Survey 3

Here the focus is edge and medical honeypots. MedPot and lightweight honeypots are useful references, but static or low-interaction decoys can be identified by attackers and may miss deeper payloads. HoneyMed tries to be more operational by combining decoy services with ML and evidence handling.

## Slide 9: Literature Survey 4

These works show a repeated limitation: models may work on old datasets or generic IoT data, but IoMT has medical protocol behavior and edge constraints. Our design uses controlled live traffic from the honeypot itself so the model is tied to the actual environment.

## Slide 10: Literature Survey 5

The final survey group connects the gap clearly: device vulnerability studies identify risk, medical honeypot work proves deception is relevant, and edge systems reduce latency. HoneyMed combines those ideas into one pipeline: specialized decoys, local classification, dashboarding, and verifiable logs.

## Slide 11: Existing System & Limitation

Existing systems usually fall into separate categories: IDS, generic honeypots, cloud analytics, or manual log review. Each is useful, but incomplete. Our contribution is integration. HoneyMed is not just a detector; it is a controlled attacker-interaction environment with ML and forensic logging.

## Slide 12: Requirements Specifications

Functionally, the system needs to emulate medical and common IT services, capture payloads and metadata, normalize logs, classify threats, and update the dashboard and SIEM path. Non-functionally, it needs low latency, secure local storage, concurrent handling, and a clear analyst interface.

## Slide 13: System Requirements

The hardware needs are realistic for a mini-project or edge testbed: a multi-core CPU, 4 GB or more RAM, storage for logs and models, and normal network access. Software-wise, the stack is Python, Docker, ML libraries, Streamlit, SQLite, and SIEM integration APIs.

## Slide 14: Tools & Technologies

The tools were chosen for simplicity and demonstration value. Python handles listeners and ML. Docker makes the environment repeatable. Streamlit gives us a visual dashboard. SQLite gives local storage. SHA-256 hashes make event evidence verifiable.

## Slide 15: System Design

This section begins the system design. The main design choice is a layered architecture: clinical decoys first, evidence pipeline second, detection core third, and operations dashboard/response fourth.

## Slide 16: Dataset

Our dataset is hybrid. We use a public medical-network style baseline and custom traffic generated against the HoneyMed honeypot. The classes are Benign, DoS, PortScan, BruteForce, and Reconnaissance. The features include ports, protocol flags, payload size, entropy, credentials, request count, and status code.

## Slide 17: Architecture Diagram

This architecture diagram is the core of the project. On the left are the fake medical services: patient web UI, HL7, DICOM, MQTT, and SSH. The middle captures sessions and extracts features. The ML layer classifies and scores. The right side exposes the dashboard, REST API, ledger-ready hashes, and SIEM response.

## Slide 18: Architecture Components

The architecture has four main zones. The decoy zone creates believable services. The evidence pipeline stores structured telemetry. The detection core applies ML and risk scoring. The operations zone turns the result into something analysts can act on.

## Slide 19: Detailed Design 1

The detailed design starts at the protocol listener. Each service binds to a port, returns a believable banner or interface, records the attacker interaction, and stores it in a structured format. This creates useful training and investigation data without exposing real devices.

## Slide 20: Detailed Design 2

The second half is inference and response. The feature vector is scaled and passed to the classifier. The output label and confidence are stored locally, shown on the dashboard, and can trigger SIEM actions. A local LLM can be used to summarize logs in human language.

## Slide 21: Mathematical Model

Mathematically, each interaction becomes a feature vector. The scaler normalizes it, the classifier maps it to one of five classes, confidence is taken from the predicted probability, and a SHA-256 hash binds the evidence to the event details.

## Slide 22: Standard AI Model

We compared standard models. Decision Tree is fast but less stable. XGBoost is strong. The current training artifact selects Random Forest because it gives the best current balance of accuracy, precision, recall, F1-score, and lightweight inference.

## Slide 23: Proposed Project Model

Our proposed model is the complete HoneyMed flow: decoy services generate realistic attack data, the pipeline extracts features, Random Forest classifies events, and the dashboard plus SIEM layer converts detection into response. The important point is that the model is tied to our own honeypot telemetry.

## Slide 24: Methodology

The methodology followed the project phases. We began with research gap and problem framing, then moved to architecture and dataset planning, then implementation and validation. The final system demonstrates the full path from attacker interaction to classified and hash-backed evidence.

## Slide 25: Workflow Components

The workflow is practical. Start services, simulate controlled attacks, capture sessions, enrich logs, classify with ML, store evidence, and visualize everything. This is also how I will explain the demo if asked: I can show the decoy, the attack traffic, and the dashboard response.

## Slide 26: Results Dashboard

This dashboard is the most visible result. It shows total events, detected attacks, unique attackers, confidence, attack rate, attack type distribution, attacks over time, top attacker IPs, and targeted services. This proves the project is not only theoretical.

## Slide 27: Model Results

For model results, the key point is that the classifiers perform strongly on the HoneyMed dataset and the current selected model is Random Forest. The dashboard and model artifacts together show that we have both visual evidence and backend evaluation.

## Slide 28: Evidence Results

This slide shows the event feed and blockchain-ready hashes. This is important because cybersecurity is not just about classification. We also need evidence that can be checked later. The feature importance chart shows the model is learning meaningful signals like payload entropy, payload size, credentials, and scan-like behavior.

## Slide 29: Applications

The main applications are healthcare SOC training, early warning for medical protocol attacks, forensic evidence collection, dataset generation for future ML work, and SIEM enrichment. In short, HoneyMed can help security teams study attackers without exposing real medical equipment.

## Slide 30: Limitations

The limitations are also important. This is a controlled testbed, not a live hospital deployment. The protocols are selected, not exhaustive. Models need retraining as attacks evolve. Real hospital networks will add privacy rules, latency, noise, and device diversity.

## Slide 31: Future Work

Future work expands realism and collaboration. We can add surgical robot or infusion pump behavior, use federated learning across institutions, anchor event hashes in a blockchain ledger, and integrate stronger automated response through ticketing and firewall systems.

## Slide 32: Conclusion

To conclude, HoneyMed demonstrates an end-to-end IoMT security framework. It creates realistic medical decoys, captures attacker behavior, classifies it locally, visualizes it, and stores evidence in a verifiable way. The project turns unsafe exposure into controlled threat intelligence.

## Slide 33: References 1

These references support the earlier literature survey, starting from IoMT IDS, deception frameworks, blockchain for healthcare records, smart hospital anomaly detection, and federated hospital threat detection.

## Slide 34: References 2

This reference group supports SIEM integration, DICOM ransomware analysis, decentralized threat intelligence, HL7/DICOM vulnerabilities, and deep-learning intrusion detection in IoMT.

## Slide 35: References 3

These references cover medical honeypots, lightweight edge honeypots, real-time edge IDS, scalable IoMT surveys, and smart healthcare ML frameworks.

## Slide 36: References 4

This group covers IoMT IDS limitations, IoMT security recommendations, ML for IoT intrusion detection, botnet honeypots, and deep-learning cybersecurity datasets.

## Slide 37: References 5

The final references support IoT honeypot architecture, connected medical device vulnerabilities, medical-device honeypots, predictive threat intelligence with honeypot data, and edge computing for IoT security monitoring.

## Slide 38: Thank You

Thank you. I am ready for questions. If asked to summarize in one line, I would say: HoneyMed is a safe fake medical network that attracts attacks, classifies them with ML, and turns the result into dashboard-ready, evidence-backed threat intelligence.

## Demo pitch

If I get time to show the demo, I will say this:

I will first open the HoneyMed dashboard. This dashboard is connected to the local event databases generated by the honeypot. On the left side we have filters and refresh controls. In the main view we can see total events, detected attacks, unique attacker count, average confidence, and attack rate. The charts show attack type distribution and attacks over time.

Then I will explain what is happening behind it. The honeypot exposes fake medical services such as the patient web UI, HL7 listener, DICOM PACS endpoint, MQTT broker, and SSH banner. When an attacker or our controlled simulation interacts with these services, we record a structured event. The event includes service, timestamp, attacker IP, port, payload metadata, event type, and later the model prediction.

Next I will show the live event feed and hashes. I will say: this is where the project becomes useful for cybersecurity. Every event is not only classified, it is also stored with a SHA-256 hash. That means if somebody asks whether the evidence was modified, we have a path to verify integrity. It also makes the system ready for future blockchain or ledger integration.

Finally, I will connect it back to the ML model. The model does not classify based on random text. It uses features like payload entropy, payload size, port, protocol flags, scan-like behavior, credentials, request count, and status code. These features are meaningful for attacks like brute force, reconnaissance, port scanning, and DoS.

## Short version for questions

What is novel here?
HoneyMed combines four pieces in one flow: IoMT-specific deception, local evidence capture, ML classification, and analyst-facing dashboard/SIEM output.

Why honeypot instead of only IDS?
IDS observes traffic passively and can be noisy. A honeypot actively attracts attackers into a safe fake environment and produces high-value telemetry.

Why IoMT-specific?
Medical environments use protocols and workflows that generic honeypots often do not emulate. HL7, DICOM, MQTT, and patient-monitor web behavior make the decoy more relevant.

Why local logging?
Healthcare data is sensitive. Local-first logging reduces privacy risk and keeps forensic evidence available even before cloud or SIEM forwarding.

Why Random Forest?
In the current training artifact it gives the best balance of accuracy, stability, and lightweight inference for the HoneyMed dataset.

What is the biggest limitation?
The current system is validated in a controlled Docker/testbed environment. Real hospital deployment needs stronger isolation, privacy review, more device profiles, and long-term model updates.
