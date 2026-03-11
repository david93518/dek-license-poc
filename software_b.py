"""
軟體 B - PoC
向 LS 以 H_dek 請求 DEK（C_Bdek）→ 解密取得 DEK → 解密 C_doc → 清除 DEK 後繼續
"""
import os
import sys
import base64
import hashlib
import requests
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

LS_URL = os.environ.get("LS_URL", "http://127.0.0.1:5000")
CLIENT_ID = "B"
DEMO = os.environ.get("DEMO", "0") == "1"


def _bytes_to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64_to_bytes(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def load_or_create_keypair(key_path: str):
    """載入或產生 B 的 RSA 金鑰對"""
    from cryptography.hazmat.primitives.asymmetric import rsa
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        pub = priv.public_key()
    else:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        pub = priv.public_key()
        with open(key_path, "wb") as f:
            f.write(priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),  # PoC：實務應改用 passphrase 或 KMS/HSM
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


def get_dek_for_decrypt(priv, h_dek: bytes):
    r = requests.post(f"{LS_URL}/get_dek_for_decrypt", json={
        "client_id": CLIENT_ID,
        "h_dek": _bytes_to_b64(h_dek),
    }, timeout=5)
    r.raise_for_status()
    data = r.json()
    c_bdek = _b64_to_bytes(data["c_bdek"])
    dek = priv.decrypt(
        c_bdek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return dek


def decrypt_document(c_doc: bytes, dek: bytes) -> bytes:
    """C_doc = nonce(12) || ChaCha20-Poly1305 密文"""
    nonce = c_doc[:12]
    ct = c_doc[12:]
    chacha = ChaCha20Poly1305(dek)
    return chacha.decrypt(nonce, ct, None)


def secure_clear(buf: bytearray):
    """
    Best-effort 清除：清除的是 bytearray 拷貝，原始 bytes 本體在 Python 下無法強制覆寫。
    """
    for i in range(len(buf)):
        buf[i] = 0


def run(h_dek_path: str, c_doc_path: str, output_path: str, key_path: str = "keys/b_private.pem"):
    os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)

    if DEMO:
        print("  ① 載入/產生 B 的 RSA 金鑰對，向 LS 註冊公鑰")
    priv, pub = load_or_create_keypair(key_path)
    register(priv, pub)
    if DEMO:
        print("     [OK] 註冊成功")

    with open(h_dek_path, "rb") as f:
        h_dek = f.read()
    with open(c_doc_path, "rb") as f:
        c_doc = f.read()
    if DEMO:
        print(f"  ② 讀取 H_dek ({len(h_dek)} bytes) 與 C_doc ({len(c_doc)} bytes)")
        print(f"     → H_dek: {h_dek[:8].hex()}...{h_dek[-4:].hex()}")
        print("  ③ 向 LS 發送 H_dek，請求 DEK（以 B 公鑰加密的 C_bdek）")

    dek = get_dek_for_decrypt(priv, h_dek)
    if DEMO:
        print("     [OK] 收到 C_bdek，以 B 私鑰解密取得 DEK")

    try:
        plaintext = decrypt_document(c_doc, dek)
        if DEMO:
            print(f"  ④ ChaCha20-Poly1305 解密 C_doc → 明文 {len(plaintext)} bytes")
        with open(output_path, "wb") as f:
            f.write(plaintext)
    finally:
        dek_arr = bytearray(dek)
        secure_clear(dek_arr)
        dek = None
        if DEMO:
            print("  ⑤ 從記憶體清除 DEK，繼續其他處理")

    print(f"  [B] 解密完成 → {output_path}")
    if DEMO:
        print("\n  *** PoC 成功：三容器 DEK 派發 → A 加密 → B 解密 流程驗證通過 ***")
    return plaintext


if __name__ == "__main__":
    prefix = sys.argv[1] if len(sys.argv) > 1 else "encrypted_output"
    output = sys.argv[2] if len(sys.argv) > 2 else "decrypted_output.txt"
    h_dek_path = f"{prefix}.h_dek"
    c_doc_path = f"{prefix}.c_doc"
    if not os.path.exists(h_dek_path) or not os.path.exists(c_doc_path):
        print(f"請先執行軟體 A 產生 {h_dek_path} 與 {c_doc_path}")
        sys.exit(1)
    run(h_dek_path, c_doc_path, output)
