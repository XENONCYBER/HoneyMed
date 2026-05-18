from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from PIL import Image
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, MSO_AUTO_SIZE, PP_ALIGN
from pptx.util import Inches, Pt


ROOT = Path(r"C:\Users\sayal\OneDrive\Desktop\IoMT")
WORK = ROOT / "outputs" / "manual-20260517-iomt-mini-presentation" / "presentations" / "iomt-mini-project"
STARTER = WORK / "template-starter.pptx"
FINAL = ROOT / "Mini Project Presentation-CSE(Cyber Security).pptx"
OUTPUT_DIR = WORK / "output"
OUTPUT = OUTPUT_DIR / "HoneyMed_Mini_Project_Presentation.pptx"
BACKUP = WORK / "original-template-before-fill.pptx"
SCRIPT = ROOT / "script.md"

BLACK = RGBColor(30, 30, 30)
GRAY = RGBColor(70, 70, 70)
DARK_GREEN = RGBColor(67, 97, 43)
LIGHT_GREEN = RGBColor(235, 243, 228)
HEADER_GREEN = RGBColor(218, 232, 205)
ACCENT_BLUE = RGBColor(39, 97, 181)
ACCENT_ORANGE = RGBColor(225, 96, 45)
TABLE_BORDER = RGBColor(160, 176, 145)
WHITE = RGBColor(255, 255, 255)

FONT = "Arial"
DATE_TEXT = "5/17/2026"


def inch(value: float):
    return Inches(value)


def delete_shape(shape) -> None:
    element = shape._element
    element.getparent().remove(element)


def set_font(run, size=16, bold=False, color=BLACK):
    run.font.name = FONT
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = color


def set_para_font(paragraph, size=16, bold=False, color=BLACK):
    paragraph.font.name = FONT
    paragraph.font.size = Pt(size)
    paragraph.font.bold = bold
    paragraph.font.color.rgb = color


def clear_text_frame(tf) -> None:
    tf.clear()
    tf.margin_left = inch(0.05)
    tf.margin_right = inch(0.05)
    tf.margin_top = inch(0.04)
    tf.margin_bottom = inch(0.04)


def write_textbox(slide, x, y, w, h, text, size=16, bold=False, color=BLACK, align=PP_ALIGN.LEFT):
    box = slide.shapes.add_textbox(inch(x), inch(y), inch(w), inch(h))
    tf = box.text_frame
    tf.word_wrap = True
    tf.auto_size = MSO_AUTO_SIZE.TEXT_TO_FIT_SHAPE
    tf.vertical_anchor = MSO_ANCHOR.TOP
    clear_text_frame(tf)
    p = tf.paragraphs[0]
    p.alignment = align
    p.text = text
    set_para_font(p, size=size, bold=bold, color=color)
    return box


def write_title(slide, title: str) -> None:
    box = write_textbox(slide, 1.0, 0.48, 11.35, 0.48, title, size=20, bold=True, align=PP_ALIGN.CENTER)
    box.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE


def write_center(slide, text: str, y=2.75, size=32, color=BLACK) -> None:
    box = write_textbox(slide, 1.0, y, 11.35, 0.85, text, size=size, bold=True, color=color, align=PP_ALIGN.CENTER)
    box.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE


def write_bullets(slide, x, y, w, h, items, size=15, title_color=BLACK):
    box = slide.shapes.add_textbox(inch(x), inch(y), inch(w), inch(h))
    tf = box.text_frame
    tf.word_wrap = True
    tf.auto_size = MSO_AUTO_SIZE.TEXT_TO_FIT_SHAPE
    tf.vertical_anchor = MSO_ANCHOR.TOP
    clear_text_frame(tf)
    for idx, item in enumerate(items):
        p = tf.paragraphs[0] if idx == 0 else tf.add_paragraph()
        p.space_after = Pt(5)
        p.level = 0
        if isinstance(item, tuple):
            head, body = item
            r = p.add_run()
            r.text = f"{head}: "
            set_font(r, size=size, bold=True, color=title_color)
            r = p.add_run()
            r.text = body
            set_font(r, size=size, bold=False, color=GRAY)
        else:
            p.text = f"- {item}"
            set_para_font(p, size=size, color=GRAY)
    return box


def add_label(slide, x, y, w, h, text, fill=LIGHT_GREEN, size=13, bold=True):
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, inch(x), inch(y), inch(w), inch(h))
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill
    shape.line.color.rgb = TABLE_BORDER
    shape.line.width = Pt(0.75)
    tf = shape.text_frame
    clear_text_frame(tf)
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    p.text = text
    set_para_font(p, size=size, bold=bold, color=BLACK)
    return shape


def add_image_fit(slide, img_path: Path, x, y, w, h):
    with Image.open(img_path) as im:
        iw, ih = im.size
    box_ratio = w / h
    img_ratio = iw / ih
    if img_ratio > box_ratio:
        final_w = w
        final_h = w / img_ratio
        final_x = x
        final_y = y + (h - final_h) / 2
    else:
        final_h = h
        final_w = h * img_ratio
        final_x = x + (w - final_w) / 2
        final_y = y
    pic = slide.shapes.add_picture(str(img_path), inch(final_x), inch(final_y), width=inch(final_w), height=inch(final_h))
    return pic


def write_table(slide, x, y, w, h, data, col_widths=None, font_size=9, header=True):
    rows = len(data)
    cols = len(data[0])
    shape = slide.shapes.add_table(rows, cols, inch(x), inch(y), inch(w), inch(h))
    table = shape.table
    if col_widths:
        for i, cw in enumerate(col_widths):
            table.columns[i].width = inch(w * cw)
    for r, row in enumerate(data):
        for c, value in enumerate(row):
            cell = table.cell(r, c)
            cell.margin_left = inch(0.04)
            cell.margin_right = inch(0.04)
            cell.margin_top = inch(0.03)
            cell.margin_bottom = inch(0.03)
            cell.fill.solid()
            cell.fill.fore_color.rgb = HEADER_GREEN if header and r == 0 else WHITE
            for side in ["lnL", "lnR", "lnT", "lnB"]:
                ln = cell._tc.get_or_add_tcPr().find(f".//a:{side}", namespaces={"a": "http://schemas.openxmlformats.org/drawingml/2006/main"})
                if ln is not None:
                    ln.attrib.clear()
            tf = cell.text_frame
            tf.word_wrap = True
            tf.auto_size = MSO_AUTO_SIZE.TEXT_TO_FIT_SHAPE
            tf.clear()
            p = tf.paragraphs[0]
            p.text = str(value)
            p.alignment = PP_ALIGN.CENTER if c == 0 else PP_ALIGN.LEFT
            set_para_font(p, size=font_size, bold=(header and r == 0), color=BLACK if r == 0 else GRAY)
    return shape


def clean_slide(slide, slide_number: int) -> None:
    for shape in list(slide.shapes):
        if shape.has_table:
            delete_shape(shape)
            continue
        if getattr(shape, "has_text_frame", False):
            text = shape.text.strip()
            compact = text.replace("\n", "").strip()
            if re.fullmatch(r"\d{1,2}/\d{1,2}/\d{4}", compact):
                shape.text_frame.clear()
                p = shape.text_frame.paragraphs[0]
                p.text = DATE_TEXT
                set_para_font(p, size=9, color=GRAY)
            elif compact.isdigit():
                shape.text_frame.clear()
                p = shape.text_frame.paragraphs[0]
                p.text = str(slide_number)
                set_para_font(p, size=9, color=GRAY)
            else:
                delete_shape(shape)


lit_rows = [
    ("1", "Al-Turjman et al. (2021)", "Deep-learning IDS for IoT", "High accuracy, but resource-heavy and not DICOM-specific"),
    ("2", "Gupta and Singh (2022)", "Healthcare deception framework", "Useful medical decoy idea, but logs still need manual analysis"),
    ("3", "Sharma et al. (2023)", "Blockchain for EHR security", "Strong storage integrity, but not active threat logging"),
    ("4", "Wang et al. (2021)", "XGBoost anomaly detection", "Fast for smart hospitals, but centralized evidence storage"),
    ("5", "Kumar and Patel (2024)", "Federated hospital threat detection", "Preserves privacy, but adds latency and coordination overhead"),
    ("6", "Zhang et al. (2022)", "Honeypot + SIEM response", "Good response pipeline, but focused on generic IT protocols"),
    ("7", "Lopez and Garcia (2023)", "Ransomware in DICOM servers", "Protocol-specific insight, but reactive after infection path starts"),
    ("8", "Chen et al. (2025)", "Smart-contract threat sharing", "Trustless sharing, but complex for edge deployment"),
    ("9", "Ghaffar et al. (2022)", "HL7/DICOM vulnerability analysis", "Identifies protocol flaws without active detection layer"),
    ("10", "Awotunde et al. (2021)", "DL intrusion detection in IoMT", "Accurate but too heavy for edge-class deployment"),
    ("11", "Wang et al. (2021) MedPot", "Specialized medical honeypot", "Static behavior can be fingerprinted by adaptive malware"),
    ("12", "Dowling et al. (2021)", "Lightweight edge honeypot", "Low-interaction design misses richer attacker payloads"),
    ("13", "Rathore et al. (2021)", "Real-time IDS for edge", "Works on known attacks but weak on zero-day behavior"),
    ("14", "Hameed et al. (2021)", "Secure and scalable IoMT survey", "Prioritizes crypto/access control over deception"),
    ("15", "Newaz et al. (2020) HealthGuard", "ML smart healthcare framework", "Monitors physiological data more than network attack traffic"),
    ("16", "Thamilarasu et al. (2020)", "IoMT intrusion detection", "Evaluated on older datasets instead of live medical traffic"),
    ("17", "Yaacoub et al. (2020)", "IoMT security limitations", "Theoretical recommendations without empirical testbed"),
    ("18", "Hasan et al. (2020)", "ML IDS for IoT devices", "Does not fully handle memory and power constraints"),
    ("19", "Tambe et al. (2020)", "Specialized botnet honeypots", "Mostly Mirai-focused, not broad IoMT exploitation"),
    ("20", "Ferrag et al. (2020)", "DL cybersecurity datasets", "High false positives in noisy real-world traffic"),
    ("21", "Kelly et al. (2020)", "IoT honeypot architecture survey", "General IoT coverage, limited healthcare context"),
    ("22", "Mehta et al. (2023)", "Connected medical device vulnerabilities", "Assessment-focused instead of active defense"),
    ("23", "Williams and Chen (2023)", "Medical device honeypots", "Useful healthcare deception, but weak verifiable logging"),
    ("24", "Zhang and Hernandez (2024)", "DL threat intelligence from honeypots", "Centralized collection creates privacy and failure risk"),
    ("25", "Liu et al. (2022) EdgeGuard", "Edge computing for IoT monitoring", "Improves latency but lacks forensic integrity guarantees"),
]

refs = [
    "Al-Turjman, F., et al. Deep Learning-based Intrusion Detection System for IoMT. IEEE IoT Journal, 2021.",
    "Gupta, R., and Singh, A. Design and Implementation of a Deception Framework for Healthcare Networks. JMIR, 2022.",
    "Sharma, P., et al. Blockchain Technology for Electronic Health Records: A Comprehensive Review. IEEE Access, 2023.",
    "Wang, Y., et al. XGBoost-based Network Anomaly Detection in Smart Hospital Environments. Computers in Biology and Medicine, 2021.",
    "Kumar, S., and Patel, N. Federated Learning for Collaborative Threat Detection in Multi-Hospital Systems. IEEE TNSE, 2024.",
    "Zhang, L., et al. Integrating Honeypots with SIEM for Automated Incident Response in Critical Infrastructure. JISA, 2022.",
    "Lopez, M., and Garcia, D. Ransomware Propagation Vectors in DICOM PACS Servers. IJMI, 2023.",
    "Chen, X., et al. Decentralized Threat Intelligence Sharing using Smart Contracts. IEEE TIFS, 2025.",
    "Ghaffar, Z., et al. Vulnerability Analysis of HL7 and DICOM Protocols in Healthcare Networks. ACM, 2022.",
    "Awotunde, J. B., et al. Intrusion Detection in IoMT Networks Using Deep Learning. IEEE, 2021.",
    "Wang, Y., et al. MedPot: A Specialized Honeypot for Medical Network Environments. Springer, 2021.",
    "Dowling, S., et al. A Lightweight IoT Honeypot for Edge Networks. IEEE, 2021.",
    "Rathore, S., et al. Real-Time Intrusion Detection System for Edge Computing Environments. Elsevier, 2021.",
    "Hameed, K., et al. Towards Secure and Scalable IoMT: A Survey. IEEE, 2021.",
    "Newaz, A. I., et al. HealthGuard: A Machine Learning-Based Security Framework for Smart Healthcare. IEEE, 2020.",
    "Thamilarasu, G., et al. An Intrusion Detection System for Internet of Medical Things. IEEE, 2020.",
    "Yaacoub, J. P., et al. Securing Internet of Medical Things Systems: Limitations, Issues and Recommendations. IEEE, 2020.",
    "Hasan, M., et al. Intrusion Detection System for IoT Devices Using Machine Learning Techniques. Springer, 2020.",
    "Tambe, A., et al. Detection of Botnets Using Specialized IoT Honeypots. ACM, 2020.",
    "Ferrag, M. A., et al. Deep Learning for Cyber Security Intrusion Detection: Approaches and Datasets. Elsevier, 2020.",
    "Kelly, J., et al. A Comprehensive Survey of IoT Honeypot Architectures. Springer, 2020.",
    "Mehta, R., et al. Security Vulnerabilities in Connected Medical Devices. Elsevier, 2023.",
    "Williams, J., and Chen, T. Medical Device Honeypots: Detecting Attacks on Healthcare Infrastructure. JMIR, 2023.",
    "Zhang, L., and Hernandez, D. Deep Learning Models for Predictive Threat Intelligence Using Honeypot Data. ACM CCS, 2024.",
    "Liu, Y., Wang, X., and Chen, Z. EdgeGuard: Edge Computing for IoT Security Monitoring. IEEE IoT Journal, 2022.",
]


def build_deck() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    if FINAL.exists() and not BACKUP.exists():
        shutil.copy2(FINAL, BACKUP)

    prs = Presentation(str(STARTER))
    slides = list(prs.slides)
    for idx, slide in enumerate(slides, start=1):
        clean_slide(slide, idx)

    # 1. Cover
    s = slides[0]
    write_textbox(s, 0.8, 1.45, 11.8, 1.05, "An Intelligent Honeypot Framework for Attack Detection in IoMT Networks", 24, True, BLACK, PP_ALIGN.CENTER)
    write_textbox(s, 0.8, 2.38, 11.8, 0.35, "HoneyMed: Edge-based deception, ML classification, and forensic-ready local logging", 13, False, GRAY, PP_ALIGN.CENTER)
    cover = [
        ["Team members", "USN"],
        ["Ishan Chitkarsh", "1MS23CY023"],
        ["Prathmesh Sayal", "1MS23CY049"],
        ["Guide", "Dr. Vishalakshi Prabhu, Associate Professor"],
    ]
    write_table(s, 3.05, 3.25, 7.25, 1.85, cover, col_widths=[0.42, 0.58], font_size=12)
    write_textbox(s, 1.0, 5.62, 11.2, 0.55, "CYP67 - Mini Project Work | B.E. 6th Semester | Department of CSE (Cyber Security)", 12, False, GRAY, PP_ALIGN.CENTER)

    # 2. Contents
    s = slides[1]
    write_title(s, "Contents")
    contents = [
        "Introduction, problem statement, and objectives",
        "Literature survey and research gap",
        "Requirements, dataset, and system design",
        "Methodology, implementation workflow, and model design",
        "Results, discussion, applications, limitations, and future work",
        "References",
    ]
    write_bullets(s, 2.25, 1.55, 8.9, 4.8, contents, size=18)

    # 3. Introduction
    s = slides[2]
    write_title(s, "Introduction")
    write_bullets(s, 1.05, 1.45, 11.2, 4.8, [
        ("Internet of Medical Things", "patient monitors, imaging servers, MQTT sensors, and web dashboards are now connected to hospital networks."),
        ("Security concern", "many medical devices use outdated software, weak credentials, and unencrypted protocol flows."),
        ("Deception approach", "a honeypot creates believable fake medical services so attackers reveal their methods away from real patients."),
        ("HoneyMed idea", "combine IoMT protocol emulation with local ML classification, dashboarding, and forensic-ready logging."),
    ], size=17, title_color=DARK_GREEN)

    # 4. Problem Statement
    s = slides[3]
    write_title(s, "Problem Statement")
    write_bullets(s, 1.05, 1.35, 11.3, 4.9, [
        ("Healthcare attack surface", "ransomware, botnets, brute force, and protocol fuzzing increasingly target connected medical infrastructure."),
        ("Traditional IDS gap", "generic IDS tools are noisy, often miss new attack behavior, and do not understand HL7/DICOM-style medical workflows."),
        ("Operational problem", "local logs become too large for manual review, so security teams need real-time classification and explanation."),
        ("Project need", "a controlled IoMT honeypot that captures attack behavior, classifies it quickly, and preserves evidence locally."),
    ], size=17, title_color=DARK_GREEN)

    # 5. Objectives
    s = slides[4]
    write_title(s, "Objectives")
    objectives = [
        ("1. Build edge IoMT decoys", "Emulate Web UI, HL7, DICOM, MQTT, and SSH surfaces for a fake patient monitor."),
        ("2. Capture and enrich telemetry", "Convert raw sessions into structured logs with protocol, source, payload, timing, and metadata."),
        ("3. Classify attacks using ML", "Train and deploy Random Forest / XGBoost models for Benign, DoS, PortScan, BruteForce, and Reconnaissance."),
        ("4. Present actionable intelligence", "Expose results through Streamlit, REST endpoints, SIEM response hooks, and hash-backed evidence."),
    ]
    for i, item in enumerate(objectives):
        x = 0.85 + (i % 2) * 6.05
        y = 1.45 + (i // 2) * 2.25
        add_label(s, x, y, 5.55, 1.55, f"{item[0]}\n{item[1]}", fill=LIGHT_GREEN, size=12)

    # 6-10. Literature survey
    for page in range(5):
        s = slides[5 + page]
        write_title(s, f"Literature Survey ({page * 5 + 1}-{page * 5 + 5})")
        chunk = lit_rows[page * 5:(page + 1) * 5]
        data = [["No.", "Authors / Year", "Focus", "Limitation / Gap"]] + [list(row) for row in chunk]
        write_table(s, 0.45, 1.25, 12.45, 5.45, data, col_widths=[0.06, 0.22, 0.25, 0.47], font_size=7.7)

    # 11. Existing systems
    s = slides[10]
    write_title(s, "Existing System & Limitation")
    systems = [
        ["Existing approach", "What it does", "Limitation that HoneyMed addresses"],
        ["Generic IDS", "Monitors traffic and raises alerts", "High false positives and limited IoMT protocol context"],
        ["General honeypots", "Decoys for SSH, Telnet, FTP, web traffic", "Often miss HL7/DICOM/MQTT medical behavior"],
        ["Cloud-only analytics", "Sends logs to remote platform for scoring", "Latency, privacy concerns, and weaker local forensics"],
        ["Manual log review", "Analyst reads raw logs after incidents", "Too slow for high-volume attacks and zero-day investigation"],
    ]
    write_table(s, 0.75, 1.45, 11.8, 4.6, systems, col_widths=[0.22, 0.33, 0.45], font_size=9.5)

    # 12. Requirements
    s = slides[11]
    write_title(s, "Requirements Specifications")
    req = [
        ["Functional Requirements", "Non-Functional Requirements"],
        ["Emulate HL7 MLLP, DICOM, MQTT, SSH, and a medical web portal", "Low-latency capture and classification for live alerting"],
        ["Capture payload, IP, port, timestamp, protocol, and service metadata", "Secure local evidence storage with tamper-aware hashes"],
        ["Normalize logs and extract features for ML inference", "Handle multiple concurrent connections across exposed services"],
        ["Update dashboard, REST API, SIEM alerts, and local analysis store", "Clear analyst-facing dashboard for quick interpretation"],
    ]
    write_table(s, 1.0, 1.45, 11.2, 4.65, req, col_widths=[0.5, 0.5], font_size=9.5)

    # 13. System requirements
    s = slides[12]
    write_title(s, "Requirements Specifications")
    sys_req = [
        ["System Requirements", "Details"],
        ["Hardware", "Multi-core CPU, 4 GB+ RAM, 20 GB+ storage, Ethernet/Wi-Fi"],
        ["OS / Runtime", "Linux or Docker-capable OS with Docker Compose orchestration"],
        ["Languages", "Python 3.8+ for services, data pipeline, ML, and dashboard glue"],
        ["Libraries", "Scikit-learn, XGBoost, Streamlit, SQLite, local LLM integration library"],
        ["Security tooling", "Nmap/Hydra style controlled attack simulation and SIEM API integration"],
    ]
    write_table(s, 1.0, 1.45, 11.2, 4.65, sys_req, col_widths=[0.28, 0.72], font_size=10)

    # 14. Tools
    s = slides[13]
    write_title(s, "Requirements Specifications")
    tools = [
        ["Tool / Technology", "Purpose"],
        ["Python", "Protocol listeners, feature extraction, ML inference, orchestration"],
        ["Docker / Docker Compose", "Repeatable honeypot environment and service isolation"],
        ["Streamlit", "Threat intelligence dashboard and live analyst view"],
        ["SQLite", "Local event, classifier, ledger, and peer-response storage"],
        ["Scikit-learn / XGBoost", "Training and comparing classifiers for attack traffic"],
        ["SHA-256 hashing", "Evidence integrity for blockchain-ready local logs"],
        ["REST API / SIEM hooks", "Status, search, alert, and simulated response automation"],
    ]
    write_table(s, 2.15, 1.32, 9.05, 5.2, tools, col_widths=[0.32, 0.68], font_size=9.4)

    # 15. System design divider
    s = slides[14]
    write_center(s, "System Design", y=2.9, size=34)
    write_textbox(s, 1.5, 3.75, 10.35, 0.55, "From IoMT decoys to evidence-backed ML threat intelligence", 15, False, GRAY, PP_ALIGN.CENTER)

    # 16. Dataset
    s = slides[15]
    write_title(s, "Dataset")
    dataset = [
        ["Parameter", "Description"],
        ["Dataset approach", "Hybrid: public medical-network baseline + custom HoneyMed live simulation traffic"],
        ["Current project run", "5,000-sample HoneyMed dataset with a held-out test split"],
        ["Labels", "Benign, DoS, PortScan, BruteForce, Reconnaissance"],
        ["Feature groups", "Timing, target/source port, payload size/entropy, protocol flags, credentials, volume, status code"],
        ["Formats", "CSV processed dataset, JSONL raw logs, SQLite classified event stores"],
        ["Purpose", "Train, compare, and validate models before deployment in the Layer 3 inference engine"],
    ]
    write_table(s, 1.0, 1.25, 11.2, 5.1, dataset, col_widths=[0.28, 0.72], font_size=9.2)

    # 17. Architecture
    s = slides[16]
    write_title(s, "System Design")
    add_image_fit(s, ROOT / "artifacts" / "figures" / "fig04_system_architecture.png", 0.55, 1.23, 12.25, 4.95)
    write_textbox(s, 0.8, 6.28, 11.8, 0.35, "Four-layer flow: decoys capture attacker sessions, pipeline extracts evidence, ML scores threats, dashboard/SIEM turns it into response.", 10.5, False, GRAY, PP_ALIGN.CENTER)

    # 18. Components
    s = slides[17]
    write_title(s, "Major components in the Project Architecture")
    components = [
        ["Layer", "Component", "Role"],
        ["1", "Clinical Decoy Zone", "Fake VitalSync web UI, HL7 listener, DICOM PACS, MQTT broker, SSH banner"],
        ["2", "Evidence Pipeline", "Session capture, feature extraction, SHA-256 hash, local SQLite storage"],
        ["3", "Detection Core", "Model registry, inference service, risk scoring, event classifier"],
        ["4", "Operations Zone", "REST API, SOC dashboard, ledger-ready metadata, SIEM response automation"],
    ]
    write_table(s, 0.8, 1.45, 11.7, 4.75, components, col_widths=[0.1, 0.3, 0.6], font_size=9.7)

    # 19. Detailed design 1
    s = slides[18]
    write_title(s, "Detailed Design")
    write_bullets(s, 0.9, 1.35, 5.7, 4.7, [
        ("Edge listener design", "Each service opens a realistic endpoint, sends a protocol-specific banner, captures payloads, then closes the session safely."),
        ("Deception surfaces", "HTTP patient monitor, HL7 MLLP, DICOM PACS, MQTT vital-sign topics, and SSH embedded-device shell."),
        ("Capture structure", "Every interaction is stored with timestamp, attacker IP/port, service, event type, payload, and metadata."),
    ], size=13.5, title_color=DARK_GREEN)
    write_bullets(s, 6.75, 1.35, 5.65, 4.7, [
        ("Feature extraction", "Transforms raw sessions into numeric model inputs: entropy, payload size, scan-like behavior, protocol flags, and request frequency."),
        ("Evidence integrity", "SHA-256 hashes are generated so forensic evidence can be verified before blockchain/SIEM export."),
        ("Local-first design", "Raw logs and classified events remain available locally for analysis and demonstration."),
    ], size=13.5, title_color=DARK_GREEN)

    # 20. Detailed design 2
    s = slides[19]
    write_title(s, "Detailed Design")
    write_bullets(s, 0.9, 1.35, 5.7, 4.7, [
        ("Inference engine", "A scaler and classifier load from the model registry, then classify each feature vector into attack categories."),
        ("Risk scoring", "Confidence, threshold, protocol, and recent behavior are combined into an analyst-friendly risk interpretation."),
        ("Local LLM support", "Captured logs can be summarized into plain-language explanations for faster incident triage."),
    ], size=13.5, title_color=DARK_GREEN)
    write_bullets(s, 6.75, 1.35, 5.65, 4.7, [
        ("Dashboard", "Streamlit shows attack type distribution, attackers, targeted services, event feed, and hash evidence."),
        ("SIEM response", "Alert hooks and simulated IP blocking turn detection into an operational response workflow."),
        ("Query path", "REST endpoints expose status, stats, search, hashes, and response data for integration."),
    ], size=13.5, title_color=DARK_GREEN)

    # 21. Mathematical model
    s = slides[20]
    write_title(s, "Mathematical Model")
    model_lines = [
        ("Input vector", "x = [time, source/target ports, payload_size, entropy, protocol flags, credentials, request_count, status_code]"),
        ("Normalization", "x' = scaler.transform(x), so model features stay in a comparable numeric range."),
        ("Classification", "y = f(x') where y belongs to {Benign, DoS, PortScan, BruteForce, Reconnaissance}."),
        ("Confidence", "c = max(P(y | x')), used by the dashboard and response engine."),
        ("Evidence hash", "h = SHA256(timestamp + source + service + payload + prediction), making event records verifiable."),
    ]
    write_bullets(s, 0.95, 1.3, 11.3, 4.95, model_lines, size=15.5, title_color=DARK_GREEN)

    # 22. Standard AI model
    s = slides[21]
    write_title(s, "Standard AI Model")
    ai = [
        ["Model", "Accuracy", "Precision", "Recall", "F1-score", "Training note"],
        ["Decision Tree", "99.0%", "99.02%", "99.0%", "98.99%", "Fast baseline; lower CV stability"],
        ["Random Forest", "99.0%", "99.02%", "99.0%", "98.99%", "Selected current best model"],
        ["XGBoost", "98.0%", "98.06%", "98.0%", "98.0%", "Strong comparative model"],
    ]
    write_table(s, 0.65, 1.35, 6.15, 3.35, ai, col_widths=[0.2, 0.13, 0.13, 0.13, 0.13, 0.28], font_size=7.9)
    add_image_fit(s, ROOT / "artifacts" / "figures" / "fig06_confusion_matrix.png", 7.05, 1.15, 5.15, 4.95)

    # 23. Proposed model
    s = slides[22]
    write_title(s, "Proposed Project Model")
    for i, label in enumerate(["Decoy services", "Feature extraction", "RF inference", "Dashboard + SIEM"]):
        add_label(s, 0.9 + i * 3.05, 2.2, 2.55, 0.8, label, fill=LIGHT_GREEN, size=12)
        if i < 3:
            write_textbox(s, 3.32 + i * 3.05, 2.42, 0.35, 0.25, "->", 16, True, DARK_GREEN, PP_ALIGN.CENTER)
    write_bullets(s, 1.15, 3.55, 11.0, 1.85, [
        ("Why this is different", "the system does not only detect; it attracts attacks, captures protocol context, classifies behavior locally, and produces verifiable evidence."),
        ("Current best model", "Random Forest is selected in the latest training output because it gives the best current balance of accuracy, stability, and low inference cost."),
    ], size=14.5, title_color=DARK_GREEN)

    # 24. Methodology
    s = slides[23]
    write_title(s, "Methodology")
    add_image_fit(s, WORK / "template-inspect-phase2" / "assets" / "ppt" / "media" / "image5.png", 1.05, 1.35, 11.2, 1.45)
    write_bullets(s, 1.05, 3.1, 11.2, 2.85, [
        ("Phase 1", "define IoMT attack surface and research gaps."),
        ("Phase 2", "design architecture, dataset strategy, and model candidates."),
        ("Phase 3", "implement honeypot services, simulate attacks, train models, and validate dashboard evidence."),
        ("Final", "present a complete working flow from attacker interaction to classified, hash-backed event intelligence."),
    ], size=15, title_color=DARK_GREEN)

    # 25. Workflow components
    s = slides[24]
    write_title(s, "Project Workflow Components")
    workflow = [
        ["Step", "Component", "Output"],
        ["1", "Start HoneyMed services", "Fake medical endpoints are exposed in Docker"],
        ["2", "Run controlled attack simulations", "Nmap, brute force, web/API, MQTT/HL7 style traffic"],
        ["3", "Capture and enrich sessions", "Structured logs with attacker/service/payload metadata"],
        ["4", "Extract features and classify", "Model label plus confidence score"],
        ["5", "Store and visualize evidence", "Dashboard charts, event feed, hashes, SIEM-ready alerts"],
    ]
    write_table(s, 0.9, 1.4, 11.5, 4.85, workflow, col_widths=[0.09, 0.34, 0.57], font_size=10)

    # 26. Dashboard result
    s = slides[25]
    write_title(s, "Results & Discussion")
    add_image_fit(s, ROOT / "artifacts" / "screenshots" / "fig02_streamlit_threat_dashboard.png", 0.75, 1.15, 11.9, 5.2)
    write_textbox(s, 0.85, 6.4, 11.6, 0.35, "Dashboard evidence: 5,080 total events, 5,078 attacks detected, live attack mix, targeted services, and attacker view.", 10.5, False, GRAY, PP_ALIGN.CENTER)

    # 27. Model metrics
    s = slides[26]
    write_title(s, "Results & Discussion")
    add_image_fit(s, ROOT / "artifacts" / "figures" / "fig05_model_metrics.png", 0.65, 1.25, 6.2, 3.9)
    write_bullets(s, 7.0, 1.45, 5.35, 3.8, [
        ("Current selected model", "Random Forest from the latest training artifact."),
        ("Classes", "Benign, DoS, PortScan, BruteForce, Reconnaissance."),
        ("Why it matters", "fast enough for edge inference while keeping analyst-facing confidence scores."),
        ("Validation", "project stores model reports, confusion matrix, feature importance, and dashboard evidence."),
    ], size=13, title_color=DARK_GREEN)

    # 28. Hash/evidence result
    s = slides[27]
    write_title(s, "Results & Discussion")
    add_image_fit(s, ROOT / "artifacts" / "screenshots" / "fig03_streamlit_events_hashes.png", 0.55, 1.2, 5.95, 4.95)
    add_image_fit(s, ROOT / "artifacts" / "figures" / "fig07_feature_importance.png", 6.72, 1.35, 5.8, 3.15)
    write_textbox(s, 6.85, 4.75, 5.55, 1.1, "Most important features include payload entropy, payload size, credentials, scan-like behavior, and status code. These map directly to attack behavior instead of generic labels.", 12, False, GRAY, PP_ALIGN.LEFT)

    # 29. Applications
    s = slides[28]
    write_title(s, "Project Applications")
    write_bullets(s, 1.0, 1.35, 11.25, 4.9, [
        "Healthcare SOC training environment for IoMT-specific attacks.",
        "Early warning system for DICOM, HL7, MQTT, SSH, and medical web abuse patterns.",
        "Forensic collection layer that captures attacker behavior without risking patient systems.",
        "Dataset generation platform for future healthcare-security ML experiments.",
        "SIEM enrichment source for hospital incident response teams.",
    ], size=17)

    # 30. Limitations
    s = slides[29]
    write_title(s, "Project Limitations")
    write_bullets(s, 1.0, 1.35, 11.25, 4.9, [
        "Current validation is in a controlled Docker/testbed environment, not a live hospital network.",
        "Only selected protocols are emulated: HTTP, HL7, DICOM, MQTT, and SSH.",
        "ML accuracy depends on representative attack traffic and periodic model updates.",
        "Real deployments may introduce latency, device diversity, privacy policy constraints, and noisy traffic.",
        "The system should be isolated from production medical devices during testing.",
    ], size=16.5)

    # 31. Future work
    s = slides[30]
    write_title(s, "Future Work")
    write_bullets(s, 1.0, 1.35, 11.25, 4.9, [
        ("More realistic decoys", "add surgical robotics, imaging workflows, infusion pump behavior, and richer patient-monitor interactions."),
        ("Federated learning", "let multiple hospitals improve the model without sharing raw patient or telemetry data."),
        ("Blockchain-backed logs", "commit selected event hashes to a tamper-proof ledger for stronger evidence chains."),
        ("Expanded response automation", "connect SIEM alerts to ticketing, firewall rules, and MITRE ATT&CK mappings."),
    ], size=16.3, title_color=DARK_GREEN)

    # 32. Conclusion
    s = slides[31]
    write_title(s, "Conclusion")
    write_bullets(s, 1.0, 1.4, 11.2, 4.85, [
        ("HoneyMed addresses a real IoMT gap", "medical devices need protocol-aware deception, not only generic perimeter alerts."),
        ("The framework is end-to-end", "decoys, capture, feature extraction, ML inference, dashboarding, SIEM hooks, and local evidence storage are connected."),
        ("The result is demo-ready", "attacks can be simulated, events can be classified, and the dashboard shows evidence with hashes and confidence scores."),
        ("Main takeaway", "HoneyMed turns unsafe medical-device exposure into a controlled intelligence source for healthcare security teams."),
    ], size=16, title_color=DARK_GREEN)

    # 33-37. References
    for page in range(5):
        s = slides[32 + page]
        write_title(s, "References")
        ref_chunk = refs[page * 5:(page + 1) * 5]
        text = "\n\n".join(f"[{page * 5 + i + 1}] {ref}" for i, ref in enumerate(ref_chunk))
        write_textbox(s, 0.75, 1.25, 11.9, 5.2, text, size=10.7, color=GRAY)

    # 38. Thank you
    s = slides[37]
    write_center(s, "Thank You", y=2.3, size=34)
    write_textbox(s, 1.4, 3.25, 10.5, 0.5, "An Intelligent Honeypot Framework for Attack Detection in IoMT Networks", 16, True, BLACK, PP_ALIGN.CENTER)
    write_textbox(s, 1.4, 3.82, 10.5, 0.45, "Ishan Chitkarsh | Prathmesh Sayal", 14, False, GRAY, PP_ALIGN.CENTER)
    write_textbox(s, 1.4, 4.45, 10.5, 0.45, "Questions", 16, True, DARK_GREEN, PP_ALIGN.CENTER)

    prs.save(str(OUTPUT))
    prs.save(str(FINAL))
    print(json.dumps({"saved": str(FINAL), "copy": str(OUTPUT), "slides": len(prs.slides)}, indent=2))


def write_script() -> None:
    slide_titles = [
        "Cover", "Contents", "Introduction", "Problem Statement", "Objectives",
        "Literature Survey 1", "Literature Survey 2", "Literature Survey 3", "Literature Survey 4", "Literature Survey 5",
        "Existing System & Limitation", "Requirements Specifications", "System Requirements", "Tools & Technologies",
        "System Design", "Dataset", "Architecture Diagram", "Architecture Components", "Detailed Design 1", "Detailed Design 2",
        "Mathematical Model", "Standard AI Model", "Proposed Project Model", "Methodology", "Workflow Components",
        "Results Dashboard", "Model Results", "Evidence Results", "Applications", "Limitations", "Future Work", "Conclusion",
        "References 1", "References 2", "References 3", "References 4", "References 5", "Thank You",
    ]
    slide_pitch = [
        "Good morning everyone. Our project is titled An Intelligent Honeypot Framework for Attack Detection in IoMT Networks. We call the system HoneyMed. The basic idea is simple: instead of waiting for attackers to hit real hospital devices, we create realistic fake medical services, observe the attacker safely, classify the behavior using machine learning, and preserve the evidence locally.",
        "I will move from the problem to our design and then to results. First I will explain why IoMT security is different from normal network security. Then I will cover the research gap, requirements, dataset, architecture, model, dashboard, applications, limitations, and future work.",
        "IoMT means Internet of Medical Things. These are connected medical devices such as patient monitors, imaging servers, MQTT-based sensors, and web dashboards used inside hospitals. These systems improve monitoring, but they also increase the attack surface because many medical protocols and devices were not originally designed for hostile internet exposure.",
        "The problem we are solving is that normal IDS systems are noisy and generic. They can raise alerts, but they usually do not understand medical protocols like HL7 or DICOM. Healthcare attacks such as ransomware and botnets can affect patient safety, so we need a system that detects attacker behavior early, explains it, and stores evidence cleanly.",
        "Our objectives are fourfold. First, build believable IoMT decoys. Second, capture and enrich attacker telemetry. Third, classify attacks in real time using ML. Fourth, show the results through a dashboard and SIEM-ready response path so that the output is useful to an analyst, not just stored in a file.",
        "The first set of papers shows why the field needs this project. Deep learning IDS models can be accurate, but they are heavy. Healthcare deception frameworks exist, but they often need manual log analysis. Blockchain approaches protect stored records, but they do not actively capture attacks.",
        "This set focuses on SIEM and protocol-specific work. Some systems connect honeypots to SIEM, and some study DICOM ransomware or HL7/DICOM weaknesses. The gap is that these are often either reactive, centralized, or not implemented as a live IoMT edge honeypot.",
        "Here the focus is edge and medical honeypots. MedPot and lightweight honeypots are useful references, but static or low-interaction decoys can be identified by attackers and may miss deeper payloads. HoneyMed tries to be more operational by combining decoy services with ML and evidence handling.",
        "These works show a repeated limitation: models may work on old datasets or generic IoT data, but IoMT has medical protocol behavior and edge constraints. Our design uses controlled live traffic from the honeypot itself so the model is tied to the actual environment.",
        "The final survey group connects the gap clearly: device vulnerability studies identify risk, medical honeypot work proves deception is relevant, and edge systems reduce latency. HoneyMed combines those ideas into one pipeline: specialized decoys, local classification, dashboarding, and verifiable logs.",
        "Existing systems usually fall into separate categories: IDS, generic honeypots, cloud analytics, or manual log review. Each is useful, but incomplete. Our contribution is integration. HoneyMed is not just a detector; it is a controlled attacker-interaction environment with ML and forensic logging.",
        "Functionally, the system needs to emulate medical and common IT services, capture payloads and metadata, normalize logs, classify threats, and update the dashboard and SIEM path. Non-functionally, it needs low latency, secure local storage, concurrent handling, and a clear analyst interface.",
        "The hardware needs are realistic for a mini-project or edge testbed: a multi-core CPU, 4 GB or more RAM, storage for logs and models, and normal network access. Software-wise, the stack is Python, Docker, ML libraries, Streamlit, SQLite, and SIEM integration APIs.",
        "The tools were chosen for simplicity and demonstration value. Python handles listeners and ML. Docker makes the environment repeatable. Streamlit gives us a visual dashboard. SQLite gives local storage. SHA-256 hashes make event evidence verifiable.",
        "This section begins the system design. The main design choice is a layered architecture: clinical decoys first, evidence pipeline second, detection core third, and operations dashboard/response fourth.",
        "Our dataset is hybrid. We use a public medical-network style baseline and custom traffic generated against the HoneyMed honeypot. The classes are Benign, DoS, PortScan, BruteForce, and Reconnaissance. The features include ports, protocol flags, payload size, entropy, credentials, request count, and status code.",
        "This architecture diagram is the core of the project. On the left are the fake medical services: patient web UI, HL7, DICOM, MQTT, and SSH. The middle captures sessions and extracts features. The ML layer classifies and scores. The right side exposes the dashboard, REST API, ledger-ready hashes, and SIEM response.",
        "The architecture has four main zones. The decoy zone creates believable services. The evidence pipeline stores structured telemetry. The detection core applies ML and risk scoring. The operations zone turns the result into something analysts can act on.",
        "The detailed design starts at the protocol listener. Each service binds to a port, returns a believable banner or interface, records the attacker interaction, and stores it in a structured format. This creates useful training and investigation data without exposing real devices.",
        "The second half is inference and response. The feature vector is scaled and passed to the classifier. The output label and confidence are stored locally, shown on the dashboard, and can trigger SIEM actions. A local LLM can be used to summarize logs in human language.",
        "Mathematically, each interaction becomes a feature vector. The scaler normalizes it, the classifier maps it to one of five classes, confidence is taken from the predicted probability, and a SHA-256 hash binds the evidence to the event details.",
        "We compared standard models. Decision Tree is fast but less stable. XGBoost is strong. The current training artifact selects Random Forest because it gives the best current balance of accuracy, precision, recall, F1-score, and lightweight inference.",
        "Our proposed model is the complete HoneyMed flow: decoy services generate realistic attack data, the pipeline extracts features, Random Forest classifies events, and the dashboard plus SIEM layer converts detection into response. The important point is that the model is tied to our own honeypot telemetry.",
        "The methodology followed the project phases. We began with research gap and problem framing, then moved to architecture and dataset planning, then implementation and validation. The final system demonstrates the full path from attacker interaction to classified and hash-backed evidence.",
        "The workflow is practical. Start services, simulate controlled attacks, capture sessions, enrich logs, classify with ML, store evidence, and visualize everything. This is also how I will explain the demo if asked: I can show the decoy, the attack traffic, and the dashboard response.",
        "This dashboard is the most visible result. It shows total events, detected attacks, unique attackers, confidence, attack rate, attack type distribution, attacks over time, top attacker IPs, and targeted services. This proves the project is not only theoretical.",
        "For model results, the key point is that the classifiers perform strongly on the HoneyMed dataset and the current selected model is Random Forest. The dashboard and model artifacts together show that we have both visual evidence and backend evaluation.",
        "This slide shows the event feed and blockchain-ready hashes. This is important because cybersecurity is not just about classification. We also need evidence that can be checked later. The feature importance chart shows the model is learning meaningful signals like payload entropy, payload size, credentials, and scan-like behavior.",
        "The main applications are healthcare SOC training, early warning for medical protocol attacks, forensic evidence collection, dataset generation for future ML work, and SIEM enrichment. In short, HoneyMed can help security teams study attackers without exposing real medical equipment.",
        "The limitations are also important. This is a controlled testbed, not a live hospital deployment. The protocols are selected, not exhaustive. Models need retraining as attacks evolve. Real hospital networks will add privacy rules, latency, noise, and device diversity.",
        "Future work expands realism and collaboration. We can add surgical robot or infusion pump behavior, use federated learning across institutions, anchor event hashes in a blockchain ledger, and integrate stronger automated response through ticketing and firewall systems.",
        "To conclude, HoneyMed demonstrates an end-to-end IoMT security framework. It creates realistic medical decoys, captures attacker behavior, classifies it locally, visualizes it, and stores evidence in a verifiable way. The project turns unsafe exposure into controlled threat intelligence.",
        "These references support the earlier literature survey, starting from IoMT IDS, deception frameworks, blockchain for healthcare records, smart hospital anomaly detection, and federated hospital threat detection.",
        "This reference group supports SIEM integration, DICOM ransomware analysis, decentralized threat intelligence, HL7/DICOM vulnerabilities, and deep-learning intrusion detection in IoMT.",
        "These references cover medical honeypots, lightweight edge honeypots, real-time edge IDS, scalable IoMT surveys, and smart healthcare ML frameworks.",
        "This group covers IoMT IDS limitations, IoMT security recommendations, ML for IoT intrusion detection, botnet honeypots, and deep-learning cybersecurity datasets.",
        "The final references support IoT honeypot architecture, connected medical device vulnerabilities, medical-device honeypots, predictive threat intelligence with honeypot data, and edge computing for IoT security monitoring.",
        "Thank you. I am ready for questions. If asked to summarize in one line, I would say: HoneyMed is a safe fake medical network that attracts attacks, classifies them with ML, and turns the result into dashboard-ready, evidence-backed threat intelligence.",
    ]

    demo = """

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
"""

    lines = ["# HoneyMed Presentation Script", "", "Use this as a talk track. Do not read every sentence word-for-word; use it to keep the story flowing.", ""]
    for i, (title, pitch) in enumerate(zip(slide_titles, slide_pitch), 1):
        lines.append(f"## Slide {i}: {title}")
        lines.append("")
        lines.append(pitch)
        lines.append("")
    lines.append(demo.strip())
    lines.append("")
    SCRIPT.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"script": str(SCRIPT)}, indent=2))


if __name__ == "__main__":
    build_deck()
    write_script()
