# SDN-based IDS/IPS System with Natural Language Interface

This project implements a hybrid intrusion detection and prevention system (IDS/IPS) built on top of a Software Defined Network (SDN) using Mininet and POX. The system is integrated with a Large Language Model (LLM) to allow natural language-based security policy generation, which is translated into Snort rules and enforced in real-time.

## 📌 Project Overview

Our goal is to simplify and automate network security policy enforcement by combining:

- **SDN flexibility** (Mininet + POX),
- **Snort-based IDS/IPS monitoring**,
- **Natural Language Processing (NLP)** for rule generation,
- **ELK Stack** for real-time visualization.

The system allows users to define security intents using natural language, which are then transformed into Snort rules by an LLM. These rules are enforced on the SDN network, with attack traffic mirrored and monitored via Snort.

---

## 🗂️ Repository Structure

| File | Description |
|------|-------------|
| `train_model.ipynb` | Jupyter Notebook used to train the LLM on natural-language-to-Snort rule generation using Kaggle environment. |
| `topology.py` | Sets up the Mininet network topology, initializes h1 (attacker), h2 (victim), h3 (Snort), and starts the Snort process. |
| `snort.conf` | Custom Snort configuration file including rule paths and logging configuration. |
| `sdn_pipeline.conf` | Logstash configuration used to send Snort logs (`alert.log`, `blocked_ips.log`) to Elasticsearch for Kibana visualization. |
| `new_app.py` | Flask-based frontend backend where users can input natural language intents. Integrates with the LLM and shows responses. |
| `integrated_system.py` | Main automation and enforcement logic — parses alerts and enforces IPS (blocking) rules through POX. |
| `enhanced_monitor.py` | Mirrors traffic between h1 and h2 to h3 (Snort) for accurate packet inspection. |
| `attack_scenerios.py` | Simulated attacker behaviors for testing (e.g., ICMP ping, SSH brute force, HTTP scans). Useful for demo and automation. |

---

## 🛠️ Technologies Used

- **Mininet**: Network emulator for SDN simulation
- **POX**: SDN controller (Python-based)
- **Snort**: Signature-based IDS/IPS
- **Flask**: For web-based intent input interface
- **LLM (Flan-T5 Small)**: Fine-tuned to convert natural language into Snort rules
- **Logstash + Elasticsearch + Kibana (ELK)**: For log parsing, indexing, and visualization

---

## 🚀 How It Works

1. **User** submits a natural language security intent via the Flask UI (`new_app.py`).
2. The **LLM** generates a matching Snort rule and writes it to `local.rules`.
3. **Snort**, running on h3, detects any matching packets and logs the alert.
4. Alerts are:
    - Shipped to **Elasticsearch** via Logstash (`sdn_pipeline.conf`)
    - Forwarded to **POX**, which applies a **flow rule** to block the attacker (if IPS is enabled via `integrated_system.py`)
5. Logs and events are visualized on the **Kibana dashboard**.

---

## 📸 Kibana Visualization

- Real-time Snort alerts
- Blocked IP lists
- Protocol-wise traffic charts
- Custom dashboards for `snort-alerts-*` and `openflow-traffic-*`

---

## 🧪 Testing

Automated attack scenarios are included in `attack_scenerios.py`, which simulate:

- ICMP flooding
- Telnet brute-force
- HTTP scanning
- SSH password guessing

Each scenario can be triggered from h1 towards h2 to validate Snort detection and IPS response.

---

## 📈 Future Work

- RL-based adaptive policy suggestion
- Real-time feedback loop for model improvement
- Production deployment on real campus/testbed
- Extended support for content-based detection and anomaly detection models

---

## 👨‍💻 Contributors

- [Ayça Gül](https://github.com/aycagl)
- [Betül Özipek](https://github.com/betulozipek)
- [Tanem Çelik](https://github.com/tanemcelikk)

Supervised by **Assoc. Prof. Dr. Mehmet Demirci**  
Gazi University — Department of Computer Engineering


