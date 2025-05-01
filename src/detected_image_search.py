import pandas as pd

# CSV 파일 읽기
df = pd.read_csv('data/targets_detected.csv')

# is_cryptojacking이 True인 행만 추출
filtered_df = df[df['is_cryptojacking'] == True]

# 결과를 새로운 CSV로 저장 (필요시)
filtered_df.to_csv('data/cryptojacking_true.csv', index=False)