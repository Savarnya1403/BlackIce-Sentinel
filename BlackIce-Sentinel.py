import os
import re
import requests
import magic
import hashlib
import json
import subprocess
import imaplib
import email
import yara
import threading
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from sklearn.ensemble import RandomForestClassifier
import joblib
import spiderfoot

# OWASP & Threat Intelligence API (Placeholder)
OWASP_API = "https://owasp-malware-database.com/api/check"
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"
EMAIL_ADDRESS = "your_email@gmail.com"
EMAIL_PASSWORD = "your_email_password"

# Function to check URL for phishing indicators
def check_phishing_url(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Check domain for typosquatting (e.g., g00gle.com instead of google.com)
    if re.search(r"[0-9]+|[.-]{2,}|[^a-zA-Z0-9.-]", domain):
        print(f"[!] Suspicious domain detected: {domain}")
        return True
    
    # Check against OWASP
    response = requests.get(OWASP_API, params={"url": url})
    if response.status_code == 200 and response.json().get("malicious", False):
        print(f"[!] URL flagged as phishing/malware: {url}")
        return True
    
    return False

# Function to analyze uploaded files
def analyze_file(file_path):
    try:
        file_type = magic.from_file(file_path, mime=True)
        print(f"[*] File type detected: {file_type}")
        
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()
        
        suspicious_patterns = [
            r"<script>.*?</script>",  # JavaScript
            r"powershell",  # PowerShell
            r"cmd\\.exe",  # Windows command execution
            r"eval\\(.*?\\)",  # Obfuscated JS
            r"import os",  # Python OS commands
            r"subprocess\\.run",  # Python execution
            r"CreateObject\\(",  # VBA scripting
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                print(f"[!] Suspicious script detected in {file_path}")
                return True
        
    except Exception as e:
        print(f"[!] Error analyzing file: {e}")
    return False

# Function to check file hash against VirusTotal
def check_virus_total(file_path):
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(f"{VIRUSTOTAL_URL}/{file_hash}", headers=headers)
        
        if response.status_code == 200 and response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0:
            print(f"[!] File flagged as malicious by VirusTotal: {file_path}")
            return True
    except Exception as e:
        print(f"[!] Error checking VirusTotal: {e}")
    return False

# Function to scan email attachments
def scan_email_attachments():
    try:
        mail = imaplib.IMAP4_SSL('imap.gmail.com')
        mail.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        mail.select('inbox')
        
        result, data = mail.search(None, 'ALL')
        for num in data[0].split():
            result, msg_data = mail.fetch(num, '(RFC822)')
            msg = email.message_from_bytes(msg_data[0][1])
            
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                filename = part.get_filename()
                if filename:
                    filepath = os.path.join("/tmp", filename)
                    with open(filepath, 'wb') as f:
                        f.write(part.get_payload(decode=True))
                    analyze_file(filepath)
    except Exception as e:
        print(f"[!] Error scanning email attachments: {e}")

# Function to run suspicious files in sandbox
def run_sandbox(file_path):
    try:
        subprocess.run(["sandbox-executor", file_path], timeout=30)
    except Exception as e:
        print(f"[!] Sandbox execution failed: {e}")

# Function to scan with SpiderFoot OSINT
def scan_osint(url):
    try:
        sf = spiderfoot.SFSpider()
        sf.scan(url)
    except Exception as e:
        print(f"[!] OSINT scan failed: {e}")

# Function to classify phishing URLs using AI
def classify_url(url):
    try:
        model = joblib.load("phishing_model.pkl")
        features = extract_features(url)
        prediction = model.predict([features])
        return prediction[0]
    except Exception as e:
        print(f"[!] AI classification error: {e}")
    return False

# Function to extract features for AI detection
def extract_features(url):
    return [len(url), url.count('.'), url.count('-')]

# Function to use headless browser for phishing detection
def headless_browser_analysis(url):
    try:
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        driver.get(url)
        page_source = driver.page_source
        driver.quit()
        return page_source
    except Exception as e:
        print(f"[!] Headless browser error: {e}")
    return ""

# Main Function
def main():
    url = input("Enter URL to scan: ")
    if check_phishing_url(url) or classify_url(url):
        print("[!] Do not open this URL!")
    else:
        print("[*] URL appears safe.")
    
    file_path = input("Enter file path to analyze: ")
    if os.path.exists(file_path):
        if analyze_file(file_path) or check_virus_total(file_path):
            print("[!] File contains suspicious elements! Avoid executing it.")
            run_sandbox(file_path)
        else:
            print("[*] File appears safe.")
    else:
        print("[!] File does not exist!")
    
    scan_email_attachments()
    scan_osint(url)

if __name__ == "__main__":
    main()
