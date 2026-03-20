import requests

def test_xss(url):
    vulnerabilities = []

    payload = "<script>alert(1)</script>"
    test_url = url + payload

    try:
        response = requests.get(test_url, timeout=5)

        if payload in response.text:
            vulnerabilities.append({
                "url": test_url,
                "issue": "Possible XSS",
                "payload": payload
            })

    except Exception:
        pass

    return vulnerabilities