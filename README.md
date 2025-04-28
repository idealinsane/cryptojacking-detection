# 크립토재킹 도커 이미지 탐지 프로젝트

이 프로젝트는 크립토재킹(cryptojacking) 도커 이미지를 수집하고, 정적 탐지 기법을 통해 악성 이미지를 분류하는 과정을 다룹니다. 추후에는 다양한 정적 분석 방법을 적용하여 탐지 정확도를 높일 예정입니다.

## 디렉토리 구조

```
CryptojackingDetection/
├── README.md
├── pyproject.toml
├── requirements.txt
├── src/
│   ├── docker_official_image_scraper.py
│   ├── docker_scraper.py
│   └── validate_wallets.py
├── rules/
│   ├── mining_rules.yar
│   └── wallet_rules.yar
├── data/
│   ├── beneign.txt
│   ├── detected.txt
│   ├── wallet_example.txt
│   └── wallets_verified.csv
├── xmrig-6.22.2/
│   ├── SHA256SUMS
│   ├── cert.pem
│   ├── cert_key.pem
│   ├── config.json
│   ├── xmrig
│   └── xmrig_upx_packed
```

## 전체 프로세스

1. **도커 공식 이미지 이름 추출**

   - `src/docker_official_image_scraper.py`를 사용하여, typosquatting(오타를 이용한 공격)의 후보가 될 만한 도커 공식 이미지 이름을 추출합니다. (예: `ubuntu`)

2. **Typosquatting 의심 이미지 추출**

   - `src/docker_scraper.py`를 통해, 위에서 추출한 공식 이미지 이름을 기반으로 typosquatting이 의심되는 이미지를 수집합니다. (예: `malicious/ubuntu`)

3. **도커 이미지 다운로드 및 YARA 탐지**

   - 수집된 이미지를 다운로드한 후, YARA 도구(`rules/`)를 사용하여 크립토재킹 관련 악성 행위를 탐지합니다.

4. **지갑 주소 유효성 검증**

   - YARA 탐지 결과, 지갑 주소(cryptocurrency wallet address)로 탐지된 이미지는 `src/validate_wallets.py`에서 해당 주소의 유효성을 추가로 검증합니다.

5. **악성/양성 이미지 분류 및 수집**
   - 최종적으로 악성 이미지와 정상 이미지를 분류하여 `data/`에 저장 및 관리합니다.

## 설치 및 실행 방법

### Poetry를 이용한 의존성 관리 (권장)

1. Poetry 설치 (최초 1회만)
   ```bash
   pip install poetry
   ```
2. 의존성 설치 및 가상환경 생성
   ```bash
   poetry install --no-root
   ```
3. 가상환경 경로 확인
   ```bash
   poetry env info --path
   ```
   3.1. 가상환경 활성화
   ```bash
   source /Users/ideal/Library/Caches/pypoetry/virtualenvs/cryptojacking-detection-gFpZeC9O-py3.12/bin/activate
   ```
4. 각 단계별 스크립트 실행:
   - 공식 이미지 추출: `python src/docker_official_image_scraper.py`
   - Typosquatting 이미지 탐지: `python src/docker_scraper.py`
   - 지갑 유효성 검증: `python src/validate_wallets.py`

### requirements.txt를 이용한 설치 (대안)

1. Python 3.8 이상이 설치되어 있어야 합니다.
2. 필요한 패키지 설치:
   ```bash
   pip install -r requirements.txt
   ```

## 향후 계획

- 다양한 정적 탐지 기법(YARA rule 확장, 바이너리 분석 등) 적용
- 자동화된 악성 코드 샘플 수집 및 리포트 생성

## 참고 사항

- 본 프로젝트는 연구 및 보안 목적으로만 사용해야 하며, 악의적인 용도로의 사용을 금지합니다.
