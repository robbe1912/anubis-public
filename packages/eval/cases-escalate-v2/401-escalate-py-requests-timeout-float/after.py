def get(url):
    return requests.get(url, timeout=(0.5, 2.7))
