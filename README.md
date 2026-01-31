# MdhalaScan 🔍 by MdhalaHat

**Phishing Detection Tool**

A professional-grade command-line tool for detecting phishing threats in URLs , emails , IP Adresses, Files. Built for defensive security, education, and awareness.

## Features

- **URL Phishing Scanner**: Multi-layer analysis of URLs
- **Email Phishing Scanner**: Header and content analysis
- **IP Scanner**: Multi-layer analysis of IPs
- **Files Scanner**: Multi-layer analysis of Files
- **Risk Scoring**: 0-100 threat score with clear risk levels
- **PDF reports**
- **Threat Intelligence**
- **Educational Focus**: Explains WHY something is suspicious
- **Privacy First**: No data storage or logging
- **Fast Execution**: Typically < 2 seconds per scan

## Installation

### Quick Install (Linux/Mac)
```bash
git clone https://github.com/mdhalahat/MdhalaScan.git
cd MdhalaPhishing
python3 -m venv venv
source venv/bin/activate
chmod +x setup.sh
./setup.sh
python3 mdhalascan.py

