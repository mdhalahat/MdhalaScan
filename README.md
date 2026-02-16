# MdhalaScan 🔍 by MdhalaHat

**Phishing Detection Tool**

A professional-grade command-line tool for detecting phishing threats in URLs , emails , IP Adresses, Files. Built for defensive security, education, and awareness.

## Features

🔎 What MdhalaScan Does

-** MdhalaScan performs multi-layer threat analysis across different attack surfaces:

🌐 URL Scanner

Detects suspicious patterns, domain anomalies, and phishing indicators

Cross-checks URLs with threat intelligence sources

Identifies obfuscation and deceptive structures

📧 Email Scanner

Analyzes headers for spoofing attempts

Detects suspicious content patterns

Validates sender inconsistencies

🌍 IP Address Scanner

Reputation checks

Threat intelligence correlation

Detection of malicious or blacklisted IPs

📁 File Scanner

Identifies suspicious indicators

Multi-layer heuristic analysis

🧠 Threat Intelligence Integration

Correlates scanned indicators with known malicious databases

Supports updated intelligence sources

Enhances detection accuracy using reputation-based analysis

📊 Risk Scoring Engine

Generates a 0–100 threat score

Clear classification (Low / Medium / High / Critical)

Transparent explanation of WHY something is suspicious

📄 Professional PDF Reports

Structured output for documentation and analysis

🔒 Privacy-First Design

No data storage

No logging

Fully local execution

⚡ Fast execution — typically under 2 seconds per scan.

## Installation

### Quick Install (Linux/Mac)
```bash
git clone https://github.com/mdhalahat/MdhalaScan.git
cd MdhalaScan
python3 -m venv venv
source venv/bin/activate  #always use venv environment
chmod +x setup.sh
./setup.sh
python3 mdhalascan.py

