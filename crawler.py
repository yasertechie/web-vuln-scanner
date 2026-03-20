import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def crawl(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')

        links = set()

        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(url, href)
            links.add(full_url)

        return list(links)

    except Exception as e:
        return {"error": str(e)}