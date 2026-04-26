<h1 align="center">🗺️ GMaps API Key Vulnerability Scanner</h1>

A comprehensive Python tool designed to audit Google Maps and Firebase API keys for overly permissive configurations. It checks a given API key against 18 different Google Cloud APIs to determine if it is publicly exposed and vulnerable to unauthorized use, potentially leading to financial loss for the key owner.

![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## ✨ Features

- **Comprehensive Scanning**: Tests API keys against 18 distinct Google Maps, Roads, Places, and Firebase endpoints.
- **Proof of Concept (PoC)**: For every vulnerable API detected, the tool provides the exact URL or `curl` command to demonstrate the vulnerability.
- **Multi-Format Reporting**:
  - **Terminal Output**: Color-coded console output for immediate feedback.
  - **Text Logs**: Timestamped `.txt` logs saved for record-keeping.
  - **HTML Reports**: Clean, styled, and responsive HTML reports.
  - **PDF Reports**: Auto-generated landscape PDF reports (requires Playwright).
- **Zero Footprint**: No external configuration files needed; just run the script and input the key.

## 🕵️‍♂️ Tested APIs

This tool checks for unauthorized access to the following Google Cloud APIs:

| Category | APIs Checked |
| :--- | :--- |
| **Maps** | Static Maps, Street View, Directions, Geocoding, Distance Matrix, Elevation, Time Zone |
| **Places** | Find Place From Text, Places Autocomplete, Place Details, Nearby Search, Text Search, Places Photo |
| **Roads** | Nearest Roads, Snap to Roads, Speed Limits |
| **Other** | Geolocation, Firebase Cloud Messaging (FCM) |

## 🛠️ Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/abhishekhargan/GmapAPIChecker.git
   cd apichecker
   ```

2. **Install required Python dependencies:**
   ```bash
   pip install requests
   ```

3. **(Optional) Install Playwright for PDF generation:**
   If you want the tool to automatically generate a PDF report alongside the HTML report, install Playwright:
   ```bash
   pip install playwright
   playwright install chromium
   ```
   *Note: If Playwright is not installed, the script will gracefully skip PDF generation and still output the HTML and TXT logs.*

## 🚀 Usage

Run the script from your terminal. It will prompt you to enter the API key.

```bash
python apichecker.py
```

**Example Output:**
```text
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ╔══════════════════════════════════╗ ┃
┃ ║ **** Google API Checker ****     ║ ┃
┃ ║ * Developed by Abhishek Hargan * ║ ┃
┃ ╚══════════════════════════════════╝ ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┘

Please enter the Google Maps API key you want to test: AIzaSy...

Starting scan for API key: AIzaSy...
...
API key is vulnerable for Static Maps API!
PoC link: https://maps.googleapis.com/maps/api/staticmap?...
...
```

## 📁 Output Files

All logs and reports are automatically saved in a dynamically created `logs/` directory. Each file is timestamped to prevent overwriting.

- `gmaps_scan_log_YYYYMMDD_HHMMSS.txt` - Raw console output.
- `gmaps_scan_report_YYYYMMDD_HHMMSS.html` - A styled, interactive **HTML report** containing a summary table with clickable PoC links.
- `gmaps_scan_report_YYYYMMDD_HHMMSS.pdf` - A printable landscape **PDF version** of the HTML report.

## ⚖️ Disclaimer & Ethical Use

This tool is provided for **educational purposes and authorized security auditing only**. 

- Do **NOT** use this tool against API keys that you do not own or have explicit written permission to test.
- Unauthorized scanning of API keys may violate terms of service and local laws.
- The developer assumes no liability and is not responsible for any misuse or damage caused by this program. **Use at your own risk.**

If you find a leaked API key during a Bug Bounty program, please report it responsibly to the vendor.

## 🧑‍💻 Credits

Developed by **Abhishek Hargan**
- [LinkedIn](https://www.linkedin.com/in/abhishekhargan)

---
**💡 Pro-Tip for Developers:** To secure your own Google Maps API keys, always implement [HTTP Referrer Restrictions](https://developers.google.com/maps/documentation/embed/get-api-key#restrict_key) or [IP Address Restrictions](https://developers.google.com/maps/documentation/embed/get-api-key#restrict_key) in the Google Cloud Console.
```
