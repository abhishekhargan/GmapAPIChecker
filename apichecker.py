import requests
import warnings
import json
import os
import datetime

# Create 'logs' directory if it doesn't exist
if not os.path.exists("logs"):
    os.makedirs("logs")

# Create log filename with timestamp
log_filename = os.path.join("logs", f"gmaps_scan_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

# Open log file at start
log_file = open(log_filename, "w", encoding="utf-8")

def log_print(*args, **kwargs):
    """Print to console and also write to log file"""
    print(*args, **kwargs)
    print(*args, file=log_file, **kwargs)

def scan_gmaps(apikey):
    results = []  # List of dicts: {'api_name': str, 'status': 'Vulnerable'/'Not Vulnerable', 'poc': str}

    log_print("Starting scan for API key:", apikey)
    log_print("")

    # Static Maps
    url = "https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=" + apikey
    response = requests.get(url, verify=False)
    if response.status_code == 200:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Static Maps API!")
        log_print("PoC link:", url)
        results.append({'api_name': 'Static Maps', 'status': 'Vulnerable', 'poc': url})
    elif b"PNG" in response.content:
        log_print("API key is not vulnerable for Static Maps API.")
        log_print("Reason: Manually check the URL.")
        results.append({'api_name': 'Static Maps', 'status': 'Not Vulnerable', 'poc': url})
    else:
        log_print("API key is not vulnerable for Static Maps API.")
        log_print("Reason:", str(response.content))
        results.append({'api_name': 'Static Maps', 'status': 'Not Vulnerable', 'poc': url})

    # Street View
    url = "https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key=" + apikey
    response = requests.get(url, verify=False)
    if response.status_code == 200:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Street View API!")
        log_print("PoC link:", url)
        results.append({'api_name': 'Street View', 'status': 'Vulnerable', 'poc': url})
    elif b"PNG" in response.content:
        log_print("API key is not vulnerable for Street View API.")
        log_print("Reason: Manually check the URL.")
        results.append({'api_name': 'Street View', 'status': 'Not Vulnerable', 'poc': url})
    else:
        log_print("API key is not vulnerable for Street View API.")
        log_print("Reason:", str(response.content))
        results.append({'api_name': 'Street View', 'status': 'Not Vulnerable', 'poc': url})

    # Directions
    url = "https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key=" + apikey
    response = requests.get(url, verify=False)
    if "error_message" not in response.text:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Directions API!")
        log_print("PoC link:", url)
        results.append({'api_name': 'Directions', 'status': 'Vulnerable', 'poc': url})
    else:
        log_print("API key is not vulnerable for Directions API.")
        log_print("Reason:", response.json().get("error_message", "Unknown"))
        results.append({'api_name': 'Directions', 'status': 'Not Vulnerable', 'poc': url})

    # Geocoding
    url = "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=" + apikey
    response = requests.get(url, verify=False)
    if "error_message" not in response.text:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Geocoding API!")
        log_print("PoC link:", url)
        results.append({'api_name': 'Geocoding', 'status': 'Vulnerable', 'poc': url})
    else:
        log_print("API key is not vulnerable for Geocoding API.")
        log_print("Reason:", response.json().get("error_message", "Unknown"))
        results.append({'api_name': 'Geocoding', 'status': 'Not Vulnerable', 'poc': url})

    # Distance Matrix
    url = "https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key=" + apikey
    response = requests.get(url, verify=False)
    if "error_message" not in response.text:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Distance Matrix API!")
        log_print("PoC link:", url)
        results.append({'api_name': 'Distance Matrix', 'status': 'Vulnerable', 'poc': url})
    else:
        log_print("API key is not vulnerable for Distance Matrix API.")
        log_print("Reason:", response.json().get("error_message", "Unknown"))
        results.append({'api_name': 'Distance Matrix', 'status': 'Not Vulnerable', 'poc': url})

    # Find Place From Text
    url = "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key=" + apikey
    response = requests.get(url, verify=False)
    if "error_message" not in response.text:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Find Place From Text API!")
        log_print("PoC link:", url)
        results.append({'api_name': 'Find Place From Text', 'status': 'Vulnerable', 'poc': url})
    else:
        log_print("API key is not vulnerable for Find Place From Text API.")
        log_print("Reason:", response.json().get("error_message", "Unknown"))
        results.append({'api_name': 'Find Place From Text', 'status': 'Not Vulnerable', 'poc': url})

    # Places Autocomplete
    url = "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key=" + apikey
    response = requests.get(url, verify=False)
    if "error_message" not in response.text:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Places Autocomplete API!")
        log_print("PoC link:", url)
        results.append({'api_name': 'Places Autocomplete', 'status': 'Vulnerable', 'poc': url})
    else:
        log_print("API key is not vulnerable for Places Autocomplete API.")
        log_print("Reason:", response.json().get("error_message", "Unknown"))
        results.append({'api_name': 'Places Autocomplete', 'status': 'Not Vulnerable', 'poc': url})

    # Elevation
    url = "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key=" + apikey
    response = requests.get(url, verify=False)
    if "error_message" not in response.text:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Elevation API!")
        log_print("PoC link:", url)
        results.append({'api_name': 'Elevation', 'status': 'Vulnerable', 'poc': url})
    else:
        log_print("API key is not vulnerable for Elevation API.")
        log_print("Reason:", response.json().get("error_message", "Unknown"))
        results.append({'api_name': 'Elevation', 'status': 'Not Vulnerable', 'poc': url})

    # Time Zone
    url = "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key=" + apikey
    response = requests.get(url, verify=False)
    if "errorMessage" not in response.text:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Time Zone API!")
        log_print("PoC link:", url)
        results.append({'api_name': 'Time Zone', 'status': 'Vulnerable', 'poc': url})
    else:
        log_print("API key is not vulnerable for Time Zone API.")
        log_print("Reason:", response.json().get("errorMessage", "Unknown"))
        results.append({'api_name': 'Time Zone', 'status': 'Not Vulnerable', 'poc': url})

    # Nearest Roads
    url = "https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key=" + apikey
    response = requests.get(url, verify=False)
    if "error" not in response.text:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Nearest Roads API!")
        log_print("PoC link:", url)
        results.append({'api_name': 'Nearest Roads', 'status': 'Vulnerable', 'poc': url})
    else:
        log_print("API key is not vulnerable for Nearest Roads API.")
        log_print("Reason:", response.json().get("error", {}).get("message", "Unknown"))
        results.append({'api_name': 'Nearest Roads', 'status': 'Not Vulnerable', 'poc': url})

    # Geolocation (POST)
    url = "https://www.googleapis.com/geolocation/v1/geolocate?key=" + apikey
    curl_cmd = f"curl -X POST -d '{{\"considerIp\": true}}' '{url}'"
    response = requests.post(url, json={'considerIp': True}, verify=False)
    if "error" not in response.text:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Geolocation API!")
        log_print("PoC curl:", curl_cmd)
        results.append({'api_name': 'Geolocation', 'status': 'Vulnerable', 'poc': curl_cmd})
    else:
        log_print("API key is not vulnerable for Geolocation API.")
        log_print("Reason:", response.json().get("error", {}).get("message", "Unknown"))
        results.append({'api_name': 'Geolocation', 'status': 'Not Vulnerable', 'poc': curl_cmd})

    # Snap To Roads
    url = "https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key=" + apikey
    response = requests.get(url, verify=False)
    if "error" not in response.text:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Snap To Roads API!")
        log_print("PoC link:", url)
        results.append({'api_name': 'Snap To Roads', 'status': 'Vulnerable', 'poc': url})
    else:
        log_print("API key is not vulnerable for Snap To Roads API.")
        log_print("Reason:", response.json().get("error", {}).get("message", "Unknown"))
        results.append({'api_name': 'Snap To Roads', 'status': 'Not Vulnerable', 'poc': url})

    # Speed Limits
    url = "https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key=" + apikey
    response = requests.get(url, verify=False)
    if "error" not in response.text:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Speed Limits API!")
        log_print("PoC link:", url)
        results.append({'api_name': 'Speed Limits', 'status': 'Vulnerable', 'poc': url})
    else:
        log_print("API key is not vulnerable for Speed Limits API.")
        log_print("Reason:", response.json().get("error", {}).get("message", "Unknown"))
        results.append({'api_name': 'Speed Limits', 'status': 'Not Vulnerable', 'poc': url})

    # Place Details
    url = "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key=" + apikey
    response = requests.get(url, verify=False)
    if "error_message" not in response.text:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Place Details API!")
        log_print("PoC link:", url)
        results.append({'api_name': 'Place Details', 'status': 'Vulnerable', 'poc': url})
    else:
        log_print("API key is not vulnerable for Place Details API.")
        log_print("Reason:", response.json().get("error_message", "Unknown"))
        results.append({'api_name': 'Place Details', 'status': 'Not Vulnerable', 'poc': url})

    # Nearby Search
    url = "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key=" + apikey
    response = requests.get(url, verify=False)
    if "error_message" not in response.text:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Nearby Search (Places) API!")
        log_print("PoC link:", url)
        results.append({'api_name': 'Nearby Search (Places)', 'status': 'Vulnerable', 'poc': url})
    else:
        log_print("API key is not vulnerable for Nearby Search (Places) API.")
        log_print("Reason:", response.json().get("error_message", "Unknown"))
        results.append({'api_name': 'Nearby Search (Places)', 'status': 'Not Vulnerable', 'poc': url})

    # Text Search
    url = "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key=" + apikey
    response = requests.get(url, verify=False)
    if "error_message" not in response.text:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Text Search (Places) API!")
        log_print("PoC link:", url)
        results.append({'api_name': 'Text Search (Places)', 'status': 'Vulnerable', 'poc': url})
    else:
        log_print("API key is not vulnerable for Text Search (Places) API.")
        log_print("Reason:", response.json().get("error_message", "Unknown"))
        results.append({'api_name': 'Text Search (Places)', 'status': 'Not Vulnerable', 'poc': url})

    # Places Photo
    url = "https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key=" + apikey
    response = requests.get(url, verify=False, allow_redirects=False)
    if response.status_code == 302:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Places Photo API!")
        log_print("PoC link:", url)
        results.append({'api_name': 'Places Photo', 'status': 'Vulnerable', 'poc': url})
    else:
        log_print("API key is not vulnerable for Places Photo API.")
        log_print("Reason: No redirect received.")
        results.append({'api_name': 'Places Photo', 'status': 'Not Vulnerable', 'poc': url})

    # FCM
    url = "https://fcm.googleapis.com/fcm/send"
    curl_cmd = f"curl --header \"Authorization: key={apikey}\" --header \"Content-Type: application/json\" https://fcm.googleapis.com/fcm/send -d '{{\"registration_ids\":[\"ABC\"]}}'"
    response = requests.post(
        url,
        json={"registration_ids": ["ABC"]},
        headers={"Authorization": "key=" + apikey},
        verify=False
    )
    if response.status_code == 200:
        log_print("API key is \033[1;31;40mvulnerable\033[0m for Firebase Cloud Messaging (FCM)!")
        log_print("PoC curl:", curl_cmd)
        results.append({'api_name': 'Firebase Cloud Messaging (FCM)', 'status': 'Vulnerable', 'poc': curl_cmd})
    else:
        log_print("API key is not vulnerable for FCM API.")
        results.append({'api_name': 'Firebase Cloud Messaging (FCM)', 'status': 'Not Vulnerable', 'poc': curl_cmd})

    # === Generate HTML Report ===
    html_filename = os.path.join("logs", f"gmaps_scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    scan_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Google Maps API Key Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        h1 {{ text-align: center; color: #333; }}
        .developer {{ text-align: center; font-size: 1.1em; margin: 10px 0; color: #555; }}
        .info {{ background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: white; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        th, td {{ border: 1px solid #ccc; padding: 12px; text-align: left; }}
        th {{ background: #333; color: white; }}
        .vulnerable {{ background-color: #ffcccc; color: red; font-weight: bold; }}
        .not-vulnerable {{ background-color: #ccffcc; color: green; font-weight: bold; }}
        a {{ color: blue; word-break: break-all; text-decoration: underline; }}
        pre {{ background: #f0f0f0; padding: 10px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>Google Maps API Key Scan Report</h1>
    <div class="developer">
        Developed by: Abhishek Hargan<br>
        LinkedIn: <a href="https://www.linkedin.com/in/abhishekhargan" target="_blank">https://www.linkedin.com/in/abhishekhargan</a>
    </div>
    <div class="info">
        <p><strong>API Key Tested:</strong> {apikey}</p>
        <p><strong>Scan Time:</strong> {scan_time}</p>
    </div>

    <table>
        <tr>
            <th>Sr No</th>
            <th>API Name</th>
            <th>Status</th>
            <th>PoC / Check URL or Command</th>
        </tr>"""

    for i, result in enumerate(results, 1):
        status_class = "vulnerable" if result['status'] == 'Vulnerable' else "not-vulnerable"
        if result['poc'].startswith('http'):
            poc_display = f'<a href="{result["poc"]}" target="_blank">{result["poc"]}</a>'
        else:
            poc_display = f'<pre>{result["poc"]}</pre>'
        html_content += f"""
        <tr>
            <td>{i}</td>
            <td>{result['api_name']}</td>
            <td class="{status_class}">{result['status']}</td>
            <td>{poc_display}</td>
        </tr>"""

    html_content += f"""
    </table>
    <div class="info" style="text-align:center;">
        <p>Report generated on {scan_time}</p>
        <p>Pricing reference: <a href="https://cloud.google.com/maps-platform/pricing" target="_blank">Google Maps Platform Pricing</a></p>
    </div>
</body>
</html>"""

    with open(html_filename, "w", encoding="utf-8") as f:
        f.write(html_content)

    log_print(f"HTML report saved as: {html_filename}")

    # === Generate PDF from HTML using Playwright (Landscape) ===
    pdf_generated = False
    try:
        from playwright.sync_api import sync_playwright

        pdf_filename = os.path.join("logs", f"gmaps_scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(f"file://{os.path.abspath(html_filename)}")
            page.wait_for_load_state("networkidle")
            page.pdf(
                path=pdf_filename,
                format='A4',
                landscape=True,  # <<< Landscape orientation
                print_background=True,
                margin={"top": "30px", "bottom": "30px", "left": "40px", "right": "40px"}
            )
            browser.close()

        log_print(f"PDF report (Landscape, selectable text) saved as: {pdf_filename}")
        pdf_generated = True
    except ImportError:
        log_print("\nWarning: Playwright is not installed.")
        log_print("To enable PDF generation:")
        log_print("   pip install playwright")
        log_print("   playwright install chromium")
    except Exception as e:
        log_print(f"Error generating PDF: {e}")

    if not pdf_generated:
        log_print("PDF generation skipped. Only HTML report was created.")

    log_print("\n" + "="*60)
    log_print("Scan completed successfully!")
    log_print(f"Log file: {log_filename}")
    log_print(f"HTML report: {html_filename}")
    if pdf_generated:
        log_print(f"PDF report (Landscape): {pdf_filename}")
    log_print("All files saved in the 'logs' folder.")
    log_print("="*60)

    log_file.close()
    return True

def main() -> None:
    warnings.filterwarnings("ignore")

    log_print("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    log_print("┃ ╔══════════════════════════════════╗ ┃")
    log_print("┃ ║ **** Google API Checker ****     ║ ┃")
    log_print("┃ ║ * Developed by Abhishek Hargan * ║ ┃")
    log_print("┃ ╚══════════════════════════════════╝ ┃")
    log_print("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    log_print(" ")

    apikey = input("Please enter the Google Maps API key you want to test: ").strip()
    if not apikey:
        log_print("No API key provided. Aborting.")
        log_file.close()
        return

    scan_gmaps(apikey)

if __name__ == "__main__":
    main()