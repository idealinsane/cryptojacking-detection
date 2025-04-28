import requests
import csv

def fetch_popular_official_images(limit=20):
    url = "https://hub.docker.com/v2/repositories/library/?page_size={}&ordering=-pull_count".format(limit)
    try:
        resp = requests.get(url)
        resp.raise_for_status()
        data = resp.json()
        keywords = [item["name"].lower() for item in data.get("results", [])]
        return keywords
    except Exception as e:
        print(f"[!] Failed to fetch popular images: {e}")
        return []

SEARCH_KEYWORDS = fetch_popular_official_images()
MAX_PAGES = 100
PAGE_SIZE = 100
OUTPUT_CSV = "targets.csv"

def search_user_images(keyword, max_pages=MAX_PAGES):
    results = set()

    for page in range(1, max_pages + 1):
        url = f"https://hub.docker.com/v2/search/repositories/?query={keyword}&page={page}&page_size={PAGE_SIZE}"
        resp = requests.get(url)
        if resp.status_code != 200:
            print(f"Error fetching page {page} for keyword '{keyword}': {resp.status_code}")
            break

        data = resp.json()
        if not data.get("results"):
            break

        for repo in data["results"]:
            repo_name = repo["repo_name"]
            is_official = repo.get("is_official", True)
            is_automated = repo.get("is_automated", True)

            # 조건: 사용자/keyword, 공식 아님, 자동 빌드 아님
            if repo_name.count("/") == 1 and repo_name.endswith(f"/{keyword}") and not is_official and not is_automated:
                results.add(repo_name)

        if not data.get("next"):
            break

    return results

def main():
    all_repos = set()

    for keyword in SEARCH_KEYWORDS:
        print(f"[+] Searching for keyword: {keyword}")
        repos = search_user_images(keyword)
        all_repos.update(repos)
        print(f"    Found {len(repos)} matching repos.")

    print(f"\n[✓] Total unique repos found: {len(all_repos)}")

    # CSV 저장
    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["image_name"])  # header
        for repo in sorted(all_repos):
            writer.writerow([repo])

    print(f"[✓] Saved results to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()