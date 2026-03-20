import requests

# Common SQL error patterns
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated"
]

def test_sql_injection(url):
    vulnerabilities = []

    payload = "'"

    test_url = url + payload

    try:
        response = requests.get(test_url, timeout=5)
        content = response.text.lower()

        for error in SQL_ERRORS:
            if error in content:
                vulnerabilities.append({
                    "url": test_url,
                    "issue": "Possible SQL Injection",
                    "payload": payload
                })
                break

    except Exception:
        pass

    return vulnerabilities