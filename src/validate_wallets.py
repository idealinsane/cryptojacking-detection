import re
import csv
import base58
from monero.address import address as xmr_address
from eth_utils import keccak
from bitcoin.wallet import CBitcoinAddress

### 1. BTC 주소 검증 (Base58Check + prefix)
def is_valid_btc_address(addr):
    try:
        if addr.startswith("bc1p"):
            return "UNKNOWN"  # Taproot 주소는 검증 보류
        CBitcoinAddress(addr)
        return "VALID"
    except Exception:
        return "INVALID"

def is_valid_eth_checksum(address):
    if not re.match(r"^0x[a-fA-F0-9]{40}$", address):
        return False
    addr = address[2:]
    hash_bytes = keccak(text=addr.lower()).hex()

    for i, c in enumerate(addr):
        if c.isalpha():
            if (int(hash_bytes[i], 16) > 7 and c.upper() != c) or \
               (int(hash_bytes[i], 16) <= 7 and c.lower() != c):
                return False
    return True

### 3. XMR 주소 검증 (패턴 + Base58 디코딩 길이)
def is_valid_xmr_address(addr):
    try:
        _ = xmr_address(addr)
        return True
    except Exception as e:
        print(f"[XMR CHECK FAIL] {addr}: {e}")
        return False

### 패턴 정규식
btc_pattern = re.compile(
    r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{39,59}"  # P2PKH, P2SH, SegWit, Taproot
)
eth_pattern = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
xmr_pattern = re.compile(r"\b(?:4|8)[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b|\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{104}\b")

### 결과 파일로 출력
with open("detected.txt", "r") as infile, open("wallets_verified.csv", "w", newline="") as outfile:
    writer = csv.writer(outfile)
    writer.writerow(["Coin", "Status", "Address", "Line"])

    for line in infile:
        for match in btc_pattern.findall(line):
            status = is_valid_btc_address(match)
            writer.writerow(["BTC", status, match, line.strip()])
        
        for match in eth_pattern.findall(line):
            result = "VALID" if is_valid_eth_checksum(match) else "INVALID"
            writer.writerow(["ETH", result, match, line.strip()])
        
        for match in xmr_pattern.findall(line):
            result = "VALID" if is_valid_xmr_address(match) else "INVALID"
            writer.writerow(["XMR", result, match, line.strip()])
