"""
License Server (LS) - PoC
負責：生成 DEK、以客戶端公鑰封裝 DEK、依 H_dek 查詢並以 B 公鑰封裝 DEK
支援：DEK TTL、過期清理、操作審計
"""
import os
import sys
import base64
import hashlib
import time
from flask import Flask, request, jsonify

DEMO = os.environ.get("DEMO", "0") == "1"
DEK_TTL_SECONDS = int(os.environ.get("DEK_TTL_SECONDS", "3600"))  # 預設 1 小時


def _log(msg: str):
    if DEMO:
        print(f"      [LS] {msg}", file=sys.stderr, flush=True)


from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# 已註冊客戶端：client_id -> (public_key_object, public_key_pem)
clients = {}
# DEK 儲存：h_dek (bytes) -> {"dek": bytes, "created_at": float}
dek_store = {}
# 操作審計：不可竄改（PoC 為記憶體 list，實務可改為 append-only 檔或外部系統）
audit_log = []


def _bytes_to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64_to_bytes(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _b64_to_h_dek_strict(s: str):
    """嚴格解碼 h_dek：validate=True，長度必須 32 bytes"""
    if not s or not isinstance(s, str):
        return None
    try:
        raw = base64.b64decode(s.encode("ascii"), validate=True)
        return raw if len(raw) == 32 else None
    except Exception:
        return None


def _audit(action: str, client_id: str, h_dek_preview: str | None = None):
    """審計：記錄操作（誰、何時、什麼）"""
    entry = {
        "ts": time.time(),
        "action": action,
        "client_id": client_id,
        "h_dek": h_dek_preview,
    }
    audit_log.append(entry)


def _cleanup_expired_deks() -> int:
    """清除過期 DEK，回傳刪除數量"""
    now = time.time()
    expired = [k for k, v in dek_store.items() if now - v["created_at"] > DEK_TTL_SECONDS]
    for k in expired:
        del dek_store[k]
    return len(expired)


def _get_json():
    """取得並驗證 JSON body，避免 get_json() 為 None 導致 .get() 炸 500"""
    data = request.get_json(force=False, silent=True)
    if data is None or not isinstance(data, dict):
        return None
    return data


@app.route("/register", methods=["POST"])
def register():
    """客戶端註冊公鑰（PoC 身分綁定）"""
    data = _get_json()
    if data is None:
        return jsonify({"error": "invalid or missing JSON body"}), 400
    client_id = data.get("client_id")
    public_key_pem = data.get("public_key_pem")
    if not client_id or not public_key_pem:
        return jsonify({"error": "missing client_id or public_key_pem"}), 400
    try:
        pub = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8"), backend=default_backend()
        )
        clients[client_id] = {"key": pub, "pem": public_key_pem}
        _audit("register", client_id)
        _log(f"客戶端 {client_id} 註冊公鑰完成")
        return jsonify({"status": "ok", "client_id": client_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/request_dek", methods=["POST"])
def request_dek():
    """
    軟體 A 請求一組新 DEK。
    LS 生成 DEK、計算 H_dek、以 A 公鑰加密 DEK，並儲存 DEK 供之後 B 使用。
    """
    try:
        data = _get_json()
        if data is None:
            return jsonify({"error": "invalid or missing JSON body"}), 400
        client_id = data.get("client_id")
        if not client_id or client_id not in clients:
            return jsonify({"error": "unknown client_id"}), 403
        _log(f"收到 {client_id} 的 DEK 請求")
        _cleanup_expired_deks()  # 定期清理過期 DEK
        # 生成 32 bytes DEK（ChaCha20 用）
        dek = os.urandom(32)
        h_dek = hashlib.sha256(dek).digest()
        dek_store[h_dek] = {"dek": dek, "created_at": time.time()}
        _audit("request_dek", client_id, h_dek[:8].hex() + "..." + h_dek[-4:].hex())
        _log(f"產生 DEK、計算 H_dek、以 {client_id} 公鑰加密 → C_adek")
        pub = clients[client_id]["key"]
        # 使用 RSA 公鑰加密 DEK（PoC 用 RSA，實務可改為 hybrid）
        c_adek = pub.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return jsonify({
            "c_adek": _bytes_to_b64(c_adek),
            "h_dek": _bytes_to_b64(h_dek),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/get_dek_for_decrypt", methods=["POST"])
def get_dek_for_decrypt():
    """
    軟體 B 以 H_dek 請求取得 DEK（以 B 公鑰加密）。
    LS 驗證 B 身分並確認 H_dek 對應的 DEK 存在。取用後 DEK 立即刪除（one-time-use）。
    """
    data = _get_json()
    if data is None:
        return jsonify({"error": "invalid or missing JSON body"}), 400
    client_id = data.get("client_id")
    h_dek_b64 = data.get("h_dek")
    if not client_id or client_id not in clients:
        return jsonify({"error": "unknown client_id"}), 403
    if not h_dek_b64:
        return jsonify({"error": "missing h_dek"}), 400
    h_dek = _b64_to_h_dek_strict(h_dek_b64)
    if h_dek is None:
        return jsonify({"error": "invalid h_dek: must be base64 of 32 bytes"}), 400
    entry = dek_store.get(h_dek)
    if entry is None:
        return jsonify({"error": "h_dek not found or expired"}), 404
    now = time.time()
    if now - entry["created_at"] > DEK_TTL_SECONDS:
        del dek_store[h_dek]
        return jsonify({"error": "h_dek expired (TTL)"}), 410  # Gone
    _log(f"收到 {client_id} 的 DEK 索取請求，H_dek 驗證通過")
    dek = dek_store.pop(h_dek)["dek"]  # one-time-use：取用後立即刪除
    _audit("get_dek_for_decrypt", client_id, h_dek[:8].hex() + "..." + h_dek[-4:].hex())
    pub = clients[client_id]["key"]
    _log(f"以 {client_id} 公鑰加密 DEK → C_bdek")
    c_bdek = pub.encrypt(
        dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return jsonify({"c_bdek": _bytes_to_b64(c_bdek)})


@app.route("/audit", methods=["GET"])
def get_audit():
    """查詢審計紀錄（PoC 用，實務應改為寫入不可竄改儲存）"""
    return jsonify({"audit_log": audit_log, "count": len(audit_log)})


def main():
    import logging
    log = logging.getLogger("werkzeug")
    if DEMO:
        log.setLevel(logging.ERROR)  # 隱藏 Flask 預設請求日誌，避免干擾 Demo
    app.run(host="0.0.0.0", port=5000, debug=False)


if __name__ == "__main__":
    main()
