🛡️ BlackIce Sentinel - Advanced Phishing & Malware Detector

🚀 Overview

BlackIce Sentinel is a cutting-edge cybersecurity tool designed to detect phishing links, malware-infected files, and malicious email attachments. It integrates OWASP, VirusTotal, SpiderFoot (OSINT), and AI-based detection models to provide real-time protection against cyber threats.



🔥 Features

✅ Phishing URL Analysis – Detects malicious and typosquatting domains.✅ Email Attachment Scanning – Extracts and analyzes attachments for malware.✅ Automated Sandbox Execution – Runs suspicious files in a virtualized test environment.✅ Dark Web Monitoring (OSINT) – Uses SpiderFoot to check dark web & open-source intelligence.✅ AI-Powered Detection – Uses machine learning to classify phishing URLs.✅ Headless Browser Analysis – Runs deep scans using an invisible browser.

📌 Installation

1️⃣ Clone the Repository

git clone https://github.com/yourusername/BlackIce-Sentinel.git
cd BlackIce-Sentinel

2️⃣ Install Dependencies

pip install -r requirements.txt

3️⃣ Set Up API Keys & Credentials

VirusTotal API (for malware scanning): Get your API key from VirusTotal.

OWASP API (for known threats): Register at OWASP Database.

SpiderFoot OSINT: Install it using pip install spiderfoot.

Email Credentials: Use a secure app password for Gmail or Outlook.

Edit the config.json file:

{
    "virustotal_api": "your_api_key_here",
    "owasp_api": "your_api_key_here",
    "email": "your_email@gmail.com",
    "email_password": "your_email_password"
}

🛠️ Usage

🔍 Scan a URL for Phishing Threats

python blackice.py --url https://suspicious-link.com

💡 Expected Output:

[*] Checking OWASP Threat Database...
[!] WARNING: This URL is flagged as a known phishing site!
[!] Do NOT open this URL.

📂 Scan a File for Malware

python blackice.py --file suspicious.exe

💡 Expected Output:

[*] Scanning file: suspicious.exe
[*] Checking against VirusTotal...
[!] File flagged as malicious by 12 security vendors!
[!] Running in sandbox for further analysis...

📧 Scan Email Attachments (IMAP Integration)

python blackice.py --email-scan

💡 Expected Output:

[*] Connecting to inbox...
[*] Found 3 attachments. Analyzing...
[!] Malicious macro detected in invoice.doc!

🕵️ Run Dark Web & OSINT Scanning

python blackice.py --osint https://suspicious-domain.com

💡 Expected Output:

[*] Gathering intelligence on suspicious-domain.com...
[*] Found mentions in dark web forums.
[!] High-risk domain! Exercise caution.

🤖 Contributing

Want to contribute? Feel free to submit pull requests or report issues!

🛡️ License

MIT License - Free for personal and commercial use.