import requests
import csv
import os
import time
import concurrent.futures
import threading
from docker_official_image_scraper import get_popular_official_images

MAX_PAGES = 100
PAGE_SIZE = 100
OUTPUT_CSV = "../data/targets.csv"

# 공식 이미지 이름 추출 (500개)
SEARCH_KEYWORDS = get_popular_official_images(total_limit=500)

csv_lock = threading.Lock()

def save_partial_to_csv(repos, output_csv):
    output_dir = os.path.dirname(output_csv)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    with csv_lock:
        file_exists = os.path.isfile(output_csv)
        with open(output_csv, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["image_name"])
            for repo in sorted(repos):
                writer.writerow([repo])

def search_user_images(keyword, max_pages=MAX_PAGES):
    results = set()
    stop_outer = False
    for page in range(1, max_pages + 1):
        if stop_outer:
            break
        url = f"https://hub.docker.com/v2/search/repositories/?query={keyword}&page={page}&page_size={PAGE_SIZE}"
        for attempt in range(3):  # 최대 3회 재시도
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 404:
                    # print(f"[404] No more pages for keyword '{keyword}' at page {page}.")
                    stop_outer = True
                    break
                if resp.status_code == 429:
                    retry_after_raw = resp.headers.get("Retry-After", "30")
                    try:
                        retry_after = int(retry_after_raw)
                        now = int(time.time())
                        if retry_after > now:
                            wait_sec = retry_after - now
                            if wait_sec < 1:
                                wait_sec = 1
                            elif wait_sec > 600:
                                wait_sec = 60
                        else:
                            wait_sec = retry_after
                            if wait_sec < 1 or wait_sec > 600:
                                wait_sec = 60
                    except Exception:
                        wait_sec = 60
                    print(f"[429] Rate limit hit. Waiting {wait_sec} seconds for keyword '{keyword}' page {page}")
                    time.sleep(wait_sec)
                    continue  # 재시도
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
                    if repo_name.count("/") == 1 and repo_name.endswith(f"/{keyword}") and not is_official and not is_automated:
                        results.add(repo_name)
                if not data.get("next"):
                    break
                time.sleep(1)  # 요청 간 1초 지연
                break
            except Exception as e:
                print(f"[!] Connection error (attempt {attempt+1}) for keyword '{keyword}' page {page}: {e}")
                time.sleep(2)  # 실패 시 2초 대기 후 재시도
        else:
            print(f"[!] Failed to fetch page {page} for keyword '{keyword}' after 3 attempts.")
            break
    return results

def main():
    all_repos = set()

    def process_keyword(keyword):
        print(f"[+] Searching for keyword: {keyword}")
        repos = search_user_images(keyword)
        print(f"    Found {len(repos)} matching repos.")
        if repos:
            save_partial_to_csv(repos, OUTPUT_CSV)
        return repos

    # 병렬 처리: 워커 수 8개로 제한 (rate limit 완화)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(process_keyword, SEARCH_KEYWORDS))

    for repos in results:
        all_repos.update(repos)

    print(f"\n[✓] Total unique repos found: {len(all_repos)}")

    # 마지막에 중복 제거 후 전체 저장(정합성 보장)
    output_dir = os.path.dirname(OUTPUT_CSV)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["image_name"])
        for repo in sorted(all_repos):
            writer.writerow([repo])

    print(f"[✓] Saved results to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()