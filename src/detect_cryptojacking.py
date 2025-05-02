import os
import pandas as pd
import subprocess
import yara
import shutil
from concurrent.futures import ProcessPoolExecutor, as_completed
import requests

# 경로 설정
CSV_PATH = "../data/targets.csv"
YARA_RULE_PATH = "../rules/mining_rules.yar"
EXTRACT_DIR = "../data/extracted_images"
OUTPUT_PATH = "../data/targets_detected.csv"

# Docker Hub에서 가장 최근 태그 조회 함수
def get_latest_tag(image_name):
    if '/' not in image_name:
        namespace = 'library'
        repo = image_name
    else:
        namespace, repo = image_name.split('/', 1)
    url = f"https://hub.docker.com/v2/repositories/{namespace}/{repo}/tags?page_size=100"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return None
        data = resp.json()
        results = data.get('results', [])
        if not results:
            return None
        results.sort(key=lambda x: x['last_updated'], reverse=True)
        return results[0]['name']
    except Exception as e:
        print(f"[DockerHub API error] {image_name}: {e}")
        return None

# CSV 읽기
df = pd.read_csv(CSV_PATH)

# cdhowie/rocket.chat부터 분석 시작
start_idx = df[df['image_name'] == 'cecd/postgres'].index[0]
image_list = df['image_name'].tolist()[start_idx:]

results = []
MAX_WORKERS = 1  # 동시에 실행할 병렬 프로세스 개수 제한 (시스템 상황에 맞게 조정)

# 각 이미지별 전체 분석 함수
def analyze_image(image):
    print(f"\n[분석 중] {image}")
    image_result = {
        "image": image,
        "yara_detected": None,
        "detected_rules": "",
        "is_cryptojacking": None
    }
    # 이미지명/태그 분리
    if ':' in image:
        base_image, tag = image.rsplit(':', 1)
    else:
        base_image, tag = image, 'latest'
    image_with_tag = f"{base_image}:{tag}"

    # 1. 도커 이미지 pull (최초 latest 또는 지정 태그)
    pull_cmd = ["docker", "pull", image_with_tag]
    pull_result = subprocess.run(pull_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("docker pull stderr:", pull_result.stderr.decode())

    # latest 태그로 실패 시, Docker Hub에서 최신 태그 자동 보정
    if pull_result.returncode != 0 and tag == 'latest':
        latest_tag = get_latest_tag(base_image)
        if latest_tag and latest_tag != 'latest':
            print(f"[INFO] {image}의 latest 태그가 없어, 최신 태그({latest_tag})로 재시도합니다.")
            image_with_tag = f"{base_image}:{latest_tag}"
            pull_cmd = ["docker", "pull", image_with_tag]
            pull_result = subprocess.run(pull_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print("docker pull stderr (retry):", pull_result.stderr.decode())
        else:
            print(f"[ERROR] {image}에 사용할 수 있는 태그가 없습니다.")
            return image_result

    if pull_result.returncode != 0:
        print(f"[ERROR] docker pull 실패: {image_with_tag}")
        return image_result  # 이후 단계 skip

    # 2. 이미지 저장 및 추출
    image_tar = f"{base_image.replace('/', '_').replace(':', '_')}_{tag}.tar"
    save_cmd = ["docker", "save", "-o", image_tar, image_with_tag]
    save_result = subprocess.run(save_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("docker save stderr:", save_result.stderr.decode())
    if save_result.returncode != 0:
        print(f"[ERROR] docker save 실패: {image_with_tag}")
        return image_result

    extract_path = os.path.join(EXTRACT_DIR, base_image.replace('/', '_').replace(':', '_') + f"_{tag}")
    os.makedirs(extract_path, exist_ok=True)
    tar_cmd = ["tar", "-xf", image_tar, "-C", extract_path]
    tar_result = subprocess.run(tar_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("tar stderr:", tar_result.stderr.decode())
    if tar_result.returncode != 0:
        print(f"[ERROR] tar 추출 실패: {image_tar}")
        try:
            os.remove(image_tar)
        except Exception:
            pass
        return image_result

    # 3. YARA 병렬 검사 (파일별)
    def yara_scan_file(filepath):
        try:
            print(f"[YARA] Scanning: {filepath}")
            rules = yara.compile(filepath=YARA_RULE_PATH)
            matches = rules.match(filepath)
            if matches:
                print(f"[YARA] Match: {filepath} -> {[match.rule for match in matches]}")
                return [match.rule for match in matches]
            else:
                print(f"[YARA] No match: {filepath}")
        except Exception as e:
            print(f"[YARA][ERROR] {filepath}: {e}")
        return []

    # 파일 리스트 수집
    file_list = []
    for root, dirs, files in os.walk(extract_path):
        for file in files:
            file_list.append(os.path.join(root, file))

    detected_rules = set()
    for f in file_list:
        rules_found = yara_scan_file(f)
        detected_rules.update(rules_found)

    detected_rules_str = ",".join(sorted(detected_rules)) if detected_rules else ""
    image_result["yara_detected"] = bool(detected_rules)
    image_result["detected_rules"] = detected_rules_str
    image_result["is_cryptojacking"] = bool(detected_rules)

    # 임시 파일 정리 및 도커 이미지 삭제
    try:
        os.remove(image_tar)
    except Exception as e:
        print(f"[WARNING] 이미지 tar 파일 삭제 실패: {image_tar} ({e})")
    try:
        shutil.rmtree(extract_path)
    except Exception as e:
        print(f"[WARNING] 추출 디렉토리 삭제 실패: {extract_path} ({e})")
    try:
        # 이미지가 존재하는지 확인
        inspect_cmd = ["docker", "inspect", image_with_tag]
        inspect_result = subprocess.run(inspect_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if inspect_result.returncode != 0:
            print(f"[WARNING] 이미지가 존재하지 않아 삭제를 건너뜁니다: {image_with_tag}")
            return image_result
            
        # 이미지 삭제 시도
        rmi_cmd = ["docker", "rmi", "-f", image_with_tag]
        rmi_result = subprocess.run(rmi_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if rmi_result.returncode != 0 and "Untagged" in rmi_result.stderr.decode():
            # 태그가 해제된 경우, untagged 이미지 삭제
            prune_cmd = ["docker", "image", "prune", "-f"]
            subprocess.run(prune_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        print(f"[WARNING] 도커 이미지 삭제 실패: {image_with_tag} ({e})")
    return image_result

def save_partial_result_row(result):
    # 각 결과를 한 줄씩 개별적으로 임시 파일에 append (CSV 헤더가 없으면 추가)
    try:
        output_dir = os.path.dirname(OUTPUT_PATH)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        file_exists = os.path.exists(OUTPUT_PATH)
        df_row = pd.DataFrame([result])
        mode = 'a' if file_exists else 'w'
        header = not file_exists
        df_row.to_csv(OUTPUT_PATH, mode=mode, header=header, index=False)
    except Exception as e:
        print(f"[ERROR] 결과 저장 실패: {OUTPUT_PATH} ({e})")

# 배치 처리 (4개 이미지씩 처리)
batch_size = 4
for i in range(0, len(image_list), batch_size):
    batch_images = image_list[i:i + batch_size]
    print(f"\n[배치 {i//batch_size + 1}/{len(image_list)//batch_size + 1} 시작]")
    
    # 현재 배치의 이미지 분석
    with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(analyze_image, image): image for image in batch_images}
        for future in as_completed(futures):
            result = future.result()
            save_partial_result_row(result)  # 각 결과를 개별적으로 바로 저장
            print(f"[INFO] {result['image']} 탐지 완료.")
    
    # 배치 처리 완료 후 모든 Docker 이미지 삭제
    print("\n[Docker 이미지 정리 시작]")
    
    # 모든 Docker 이미지 ID 가져오기
    images_cmd = ["docker", "images", "-q"]
    images_result = subprocess.run(images_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    if images_result.returncode != 0:
        print(f"[ERROR] 이미지 목록 조회 실패: {images_result.stderr}")
        print("[WARNING] 이미지 정리 중지")
    else:
        # 이미지 ID 리스트
        image_ids = images_result.stdout.strip().split()
        if not image_ids:
            print("[INFO] 삭제할 이미지가 없습니다.")
        else:
            # 이미지 삭제 명령어 실행
            rmi_cmd = ["docker", "rmi", "-f"] + image_ids
            rmi_result = subprocess.run(rmi_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if rmi_result.returncode == 0:
                print("[INFO] 모든 Docker 이미지 삭제 완료")
            else:
                print(f"[WARNING] 이미지 삭제 중 오류 발생: {rmi_result.stderr}")
    
    print("[Docker 이미지 정리 완료]")

print("\n전체 탐지 완료! 결과는 ../data/targets_detected.csv에 저장되었습니다.")
