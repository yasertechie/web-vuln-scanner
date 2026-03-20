from flask import Flask, request, jsonify
from flask_cors import CORS

# Import modules
from crawler import crawl
from scanner.sql_scanner import test_sql_injection
from scanner.xss_scanner import test_xss
from scanner.port_scanner import scan_ports
from urllib.parse import urlparse

import json

app = Flask(__name__)
CORS(app)

# Home route
@app.route('/')
def home():
    return "Web Vulnerability Scanner is Running 🚀"


# Scan API
@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Step 1: Crawl links
    links = crawl(url)

    all_vulnerabilities = []

    # Step 2: Run vulnerability scanners
    if isinstance(links, list):
        for link in links:
            sql_vulns = test_sql_injection(link)
            xss_vulns = test_xss(link)

            all_vulnerabilities.extend(sql_vulns)
            all_vulnerabilities.extend(xss_vulns)

    # Step 3: Extract host
    parsed_url = urlparse(url)
    host = parsed_url.netloc.replace("www.", "")

    # Step 4: Scan ports
    open_ports = scan_ports(host)

    # Step 5: Prepare report data
    report_data = {
        "target": url,
        "total_links_scanned": len(links) if isinstance(links, list) else 0,
        "open_ports": open_ports,
        "vulnerabilities_found": len(all_vulnerabilities),
        "vulnerabilities": all_vulnerabilities
    }

    # Step 6: Save report to file
    try:
        with open("../reports/report.json", "w") as f:
            json.dump(report_data, f, indent=4)
    except:
        # fallback path (if error)
        with open("reports/report.json", "w") as f:
            json.dump(report_data, f, indent=4)

    # Step 7: Return clean response
    return jsonify({
        "status": "success",
        "target": url,
        "scan_summary": {
            "total_links_scanned": report_data["total_links_scanned"],
            "total_vulnerabilities": report_data["vulnerabilities_found"],
            "open_ports_found": len(open_ports)
        },
        "open_ports": open_ports,
        "vulnerabilities": all_vulnerabilities
    })


# Run server
if __name__ == '__main__':
    app.run(debug=True)