import requests

def get_popular_official_images(total_limit=500):
    """
    Docker Hub에서 pull 수 기준 상위 공식 이미지를 여러 페이지에 걸쳐 추출합니다.

    Args:
        total_limit (int): 추출할 이미지 개수 (최대값 제한 없음)

    Returns:
        list[str]: 인기 공식 이미지 이름 리스트 (예: ['ubuntu', 'nginx', ...])
    """
    url = "https://hub.docker.com/v2/repositories/library/"
    page_size = 100  # API 최대값
    images = []
    page = 1

    while len(images) < total_limit:
        params = {
            "page_size": page_size,
            "ordering": "-pull_count",
            "page": page,
        }
        try:
            resp = requests.get(url, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            batch = [item["name"].lower() for item in data.get("results", [])]
            if not batch:
                break
            images.extend(batch)
            if not data.get("next"):
                break
            page += 1
        except Exception as e:
            print(f"[!] Failed to fetch popular images (page {page}): {e}")
            break

    return images[:total_limit]

if __name__ == "__main__":
    images = get_popular_official_images(total_limit=500)
    print(images)