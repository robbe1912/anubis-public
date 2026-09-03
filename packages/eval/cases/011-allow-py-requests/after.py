import requests
def get(url):
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.json()
