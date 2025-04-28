import os
import pandas as pd
import subprocess
import yara
import shutil
from concurrent.futures import ProcessPoolExecutor, as_completed

# 경로 설정
CSV_PATH = "../data/targets.csv"
YARA_RULE_PATH = "../rules/mining_rules.yar"
EXTRACT_DIR = "../data/extracted_images"

# CSV 읽기
df = pd.read_csv(CSV_PATH)
results = []

# 각 이미지별 전체 분석 함수
def analyze_image(image):
    print(f"\n[분석 중] {image}")
    image_result = {
        "image": image,
        "yara_detected": False,
        "detected_rules": "",
        "is_cryptojacking": False
    }
    # 1. 도커 이미지 pull
    pull_cmd = ["docker", "pull", image]
    subprocess.run(pull_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # 2. 이미지 저장 및 추출
    image_tar = f"{image.replace('/', '_').replace(':', '_')}.tar"
    save_cmd = ["docker", "save", "-o", image_tar, image]
    subprocess.run(save_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    extract_path = os.path.join(EXTRACT_DIR, image.replace('/', '_').replace(':', '_'))
    os.makedirs(extract_path, exist_ok=True)
    tar_cmd = ["tar", "-xf", image_tar, "-C", extract_path]
    subprocess.run(tar_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # 3. YARA 병렬 검사 (파일별)
    def yara_scan_file(filepath):
        try:
            rules = yara.compile(filepath=YARA_RULE_PATH)
            matches = rules.match(filepath)
            if matches:
                return [match.rule for match in matches]
        except Exception:
            pass
        return []

    # 파일 리스트 수집
    file_list = []
    for root, dirs, files in os.walk(extract_path):
        for file in files:
            file_list.append(os.path.join(root, file))

    detected_rules = set()
    with ProcessPoolExecutor() as executor:
        future_to_file = {executor.submit(yara_scan_file, f): f for f in file_list}
        for future in as_completed(future_to_file):
            rules_found = future.result()
            detected_rules.update(rules_found)

    detected_rules_str = ",".join(sorted(detected_rules)) if detected_rules else ""
    image_result["yara_detected"] = bool(detected_rules)
    image_result["detected_rules"] = detected_rules_str
    image_result["is_cryptojacking"] = bool(detected_rules)

    # 임시 파일 정리
    try:
        os.remove(image_tar)
        shutil.rmtree(extract_path)
    except Exception:
        pass
    return image_result

# 이미지별 병렬 처리
image_list = df['image_name'].tolist()
with ProcessPoolExecutor() as executor:
    futures = [executor.submit(analyze_image, image) for image in image_list]
    for future in as_completed(futures):
        result = future.result()
        results.append(result)

# 결과 CSV로 저장
result_df = pd.DataFrame(results)
merged = df.merge(result_df, left_on="image_name", right_on="image")
merged.to_csv("../data/targets_detected.csv", index=False)

print("\n탐지 완료! 결과는 ../data/targets_detected.csv에 저장되었습니다.")
