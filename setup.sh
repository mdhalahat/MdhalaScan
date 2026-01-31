#!/bin/bash
echo "Installing MdhalaPhishing..."

# Install Python3 if not present
if ! command -v python3 &> /dev/null; then
    echo "Python3 not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip
fi

# Install required packages
pip3 install -r requirements.txt

pip install schedule

pip install requests beautifulsoup4 tldextract colorama reportlab

pip install reportlab

pip install pyperclip

# Make script executable
chmod +x mdhalascan.py

echo "Installation complete!"
echo "Run: python3 mdhalascan.py"
