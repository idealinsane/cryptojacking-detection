import requests

def fetch_popular_official_images(limit=1):
    url = "https://hub.docker.com/v2/repositories/library/?page_size={}&ordering=-pull_count".format(limit)
    try:
        resp = requests.get(url)
        resp.raise_for_status()
        data = resp.json()
        print(data)
        keywords = [item["name"].lower() for item in data.get("results", [])]
        return keywords
    except Exception as e:
        print(f"[!] Failed to fetch popular images: {e}")
        return []

SEARCH_KEYWORDS = fetch_popular_official_images()
print(SEARCH_KEYWORDS)