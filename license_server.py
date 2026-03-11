"""
License Server (LS) - PoC
負責：生成 DEK、以客戶端公鑰封裝 DEK、依 H_dek 查詢並以 B 公鑰封裝 DEK
支援：身分驗證（公鑰指紋綁定、角色授權、RSA 驗證）、DEK TTL、過期清理、
      操作審計（append-only 檔）、API schema 驗證、rate limit
"""
import os
import sys
import json
import base64
import hashlib
import time
from collections import defaultdict
from flask import Flask, request, jsonify

DEMO = os.environ.get("DEMO", "0") == "1"
DEK_TTL_SECONDS = int(os.environ.get("DEK_TTL_SECONDS", "3600"))
AUDIT_FILE = os.environ.get("AUDIT_FILE", "")  # 若設定則寫入 append-only 檔
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "60"))  # 每 client 每分鐘上限
ALLOWED_CLIENTS = frozenset(["A", "B"])  # 僅允許 A、B 註冊


def _log(msg: str):
    if DEMO:
        print(f"      [LS] {msg}", file=sys.stderr, flush=True)


from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

clients = {}  # client_id -> {key, pem, fingerprint}
dek_store = {}
audit_log = []  # 記憶體副本，供 /audit 查詢
# rate limit: client_id -> [(timestamp, action), ...]
_rate_entries = defaultdict(list)


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


def _audit(action: str, client_id: str, h_dek_preview=None):
    """審計：記錄操作，寫入記憶體並可選 append-only 檔（不可竄改）"""
    entry = {
        "ts": time.time(),
        "action": action,
        "client_id": client_id,
        "h_dek": h_dek_preview,
    }
    audit_log.append(entry)
    if AUDIT_FILE:
        try:
            with open(AUDIT_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass


def _check_rate_limit(client_id: str, action: str) -> tuple[bool, str]:
    """簡易 rate limit：每 client 每分鐘 N 次，回傳 (ok, error_msg)"""
    now = time.time()
    cutoff = now - 60
    key = client_id
    _rate_entries[key] = [(t, a) for t, a in _rate_entries[key] if t > cutoff]
    if len(_rate_entries[key]) >= RATE_LIMIT_PER_MIN:
        return False, "rate limit exceeded"
    _rate_entries[key].append((now, action))
    return True, ""


def _pubkey_fingerprint(pub) -> str:
    """公鑰指紋：SHA256 的 hex"""
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _validate_public_key_rsa(pub) -> tuple[bool, str]:
    """驗證公鑰為 RSA 且長度 >= 2048，回傳 (ok, error_msg)"""
    if not isinstance(pub, rsa.RSAPublicKey):
        return False, "public key must be RSA"
    key_size = pub.key_size
    if key_size < 2048:
        return False, f"RSA key size must be >= 2048, got {key_size}"
    return True, ""


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


def _schema_register(data):
    """schema：register 必填 client_id, public_key_pem 且為字串"""
    cid = data.get("client_id")
    pem = data.get("public_key_pem")
    if not isinstance(cid, str) or not cid.strip():
        return "client_id must be non-empty string", 400
    if not isinstance(pem, str) or not pem.strip():
        return "public_key_pem must be non-empty string", 400
    if cid not in ALLOWED_CLIENTS:
        return f"client_id must be one of {sorted(ALLOWED_CLIENTS)}", 403
    return None, 0


@app.route("/register", methods=["POST"])
def register():
    """客戶端註冊公鑰。身分驗證：僅 A/B、公鑰指紋綁定、RSA >= 2048"""
    data = _get_json()
    if data is None:
        return jsonify({"error": "invalid or missing JSON body"}), 400
    err, code = _schema_register(data)
    if err:
        return jsonify({"error": err}), code
    client_id = data["client_id"].strip()
    public_key_pem = data["public_key_pem"].strip()
    ok, _ = _check_rate_limit(client_id, "register")
    if not ok:
        return jsonify({"error": "rate limit exceeded"}), 429
    try:
        pub = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8"), backend=default_backend()
        )
    except Exception as e:
        return jsonify({"error": f"invalid public key: {e}"}), 400
    ok, msg = _validate_public_key_rsa(pub)
    if not ok:
        return jsonify({"error": msg}), 400
    fp = _pubkey_fingerprint(pub)
    if client_id in clients:
        if clients[client_id]["fingerprint"] != fp:
            return jsonify({"error": "client_id already registered with different key (409)"}), 409
    clients[client_id] = {"key": pub, "pem": public_key_pem, "fingerprint": fp}
    _audit("register", client_id)
    _log(f"客戶端 {client_id} 註冊公鑰完成")
    return jsonify({"status": "ok", "client_id": client_id})


ALLOWED_REQUEST_DEK = "A"  # 僅 A 可請求新 DEK
ALLOWED_GET_DEK = "B"      # 僅 B 可取用 DEK


@app.route("/request_dek", methods=["POST"])
def request_dek():
    """
    軟體 A 請求一組新 DEK。角色授權：僅 A 可呼叫。
    """
    try:
        data = _get_json()
        if data is None:
            return jsonify({"error": "invalid or missing JSON body"}), 400
        client_id = data.get("client_id") if isinstance(data.get("client_id"), str) else None
        if not client_id or client_id not in clients:
            return jsonify({"error": "unknown client_id"}), 403
        if client_id != ALLOWED_REQUEST_DEK:
            return jsonify({"error": "only client A may request new DEK"}), 403
        ok, msg = _check_rate_limit(client_id, "request_dek")
        if not ok:
            return jsonify({"error": msg}), 429
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
    軟體 B 以 H_dek 請求取得 DEK。角色授權：僅 B 可呼叫。
    """
    data = _get_json()
    if data is None:
        return jsonify({"error": "invalid or missing JSON body"}), 400
    client_id = data.get("client_id") if isinstance(data.get("client_id"), str) else None
    h_dek_b64 = data.get("h_dek") if isinstance(data.get("h_dek"), str) else None
    if not client_id or client_id not in clients:
        return jsonify({"error": "unknown client_id"}), 403
    if client_id != ALLOWED_GET_DEK:
        return jsonify({"error": "only client B may get DEK for decrypt"}), 403
    ok, msg = _check_rate_limit(client_id, "get_dek_for_decrypt")
    if not ok:
        return jsonify({"error": msg}), 429
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
