"""
軟體 A - PoC
向 LS 請求 DEK → 解密取得 DEK → ChaCha 加密文件 → 輸出 H_dek & C_doc，並清除 DEK
"""
import os
import sys
import base64
import hashlib
import requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

LS_URL = os.environ.get("LS_URL", "http://127.0.0.1:5000")
CLIENT_ID = "A"
DEMO = os.environ.get("DEMO", "0") == "1"


def _bytes_to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64_to_bytes(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _get_passphrase():
    """可選 passphrase（環境變數 KEY_PASSPHRASE），用於私鑰加密儲存"""
    p = os.environ.get("KEY_PASSPHRASE", "")
    return p.encode("utf-8") if p else None


def load_or_create_keypair(key_path: str):
    """載入或產生 A 的 RSA 金鑰對。若有 KEY_PASSPHRASE 則以 passphrase 加密儲存"""
    passphrase = _get_passphrase()
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            data = f.read()
        try:
            priv = serialization.load_pem_private_key(data, password=passphrase, backend=default_backend())
        except Exception:
            priv = serialization.load_pem_private_key(data, password=None, backend=default_backend())
        pub = priv.public_key()
    else:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        pub = priv.public_key()
        enc = (
            serialization.BestAvailableEncryption(passphrase)
            if passphrase
            else serialization.NoEncryption()
        )
        with open(key_path, "wb") as f:
            f.write(priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=enc,
            ))
    return priv, pub


def register(priv, pub):
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    r = requests.post(f"{LS_URL}/register", json={
        "client_id": CLIENT_ID,
        "public_key_pem": pem,
    }, timeout=5)
    r.raise_for_status()


def request_dek(priv):
    r = requests.post(f"{LS_URL}/request_dek", json={"client_id": CLIENT_ID}, timeout=5)
    r.raise_for_status()
    data = r.json()
    c_adek = _b64_to_bytes(data["c_adek"])
    h_dek = _b64_to_bytes(data["h_dek"])
    dek = priv.decrypt(
        c_adek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return dek, h_dek


def encrypt_document(plaintext: bytes, dek: bytes) -> bytes:
    """ChaCha20-Poly1305：nonce 12 bytes，隨機產生，放在密文前"""
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(dek)
    ct = chacha.encrypt(nonce, plaintext, None)
    return nonce + ct


def secure_clear(buf: bytearray):
    """
    盡可能從記憶體清除敏感資料（best-effort）。
    限制：decrypt() 回傳 immutable bytes，原始本體無法覆寫；此處清除的是
    bytearray 拷貝。實務高敏感環境可考慮 C 擴展或專用記憶體區。
    """
    for i in range(len(buf)):
        buf[i] = 0


def run(input_path: str, output_prefix: str, key_path: str = "keys/a_private.pem"):
    os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)

    if DEMO:
        print("  ① 載入/產生 A 的 RSA 金鑰對，向 LS 註冊公鑰")
    priv, pub = load_or_create_keypair(key_path)
    register(priv, pub)
    if DEMO:
        print("     [OK] 註冊成功")

    if DEMO:
        print("  ② 向 LS 請求新的 DEK")
    dek, h_dek = request_dek(priv)
    if DEMO:
        print(f"     [OK] 收到 C_adek（RSA 密文），H_dek = SHA256(DEK)")
        print(f"     → H_dek 預覽: {h_dek[:8].hex()}...{h_dek[-4:].hex()}")

    try:
        with open(input_path, "rb") as f:
            plaintext = f.read()
        if DEMO:
            print(f"  ③ 以 DEK 執行 ChaCha20-Poly1305 加密")
            print(f"     → 明文 {len(plaintext)} bytes → 密文 + nonce(12)")
        c_doc = encrypt_document(plaintext, dek)
        del plaintext  # 盡早釋放敏感資料參考
        h_dek_computed = hashlib.sha256(dek).digest()
        assert h_dek_computed == h_dek, "H_dek 與 LS 回傳不一致"
        if DEMO:
            print(f"     [OK] C_doc 長度: {len(c_doc)} bytes")
    finally:
        dek_arr = bytearray(dek)
        secure_clear(dek_arr)
        dek = None
        if DEMO:
            print("  ④ 從記憶體清除 DEK")

    with open(f"{output_prefix}.h_dek", "wb") as f:
        f.write(h_dek)
    with open(f"{output_prefix}.c_doc", "wb") as f:
        f.write(c_doc)
    if DEMO:
        print(f"  ⑤ 輸出 H_dek & C_doc → {output_prefix}.h_dek / .c_doc")
    print(f"  [A] 加密完成")
    return h_dek, c_doc


if __name__ == "__main__":
    input_file = sys.argv[1] if len(sys.argv) > 1 else "demo_input.txt"
    output_prefix = sys.argv[2] if len(sys.argv) > 2 else "encrypted_output"
    if not os.path.exists(input_file):
        with open(input_file, "w", encoding="utf-8") as f:
            f.write("這是 PoC 示範文件。機密內容：DEK 由 LS 派發，A 加密、B 解密。\n")
        print(f"[A] 已建立示範輸入檔 {input_file}")
    run(input_file, output_prefix)
