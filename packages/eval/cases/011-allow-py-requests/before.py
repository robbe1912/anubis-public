import urllib.request
def get(url):
    with urllib.request.urlopen(url) as r:
        return r.read()
