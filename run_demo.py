"""
單一容器內 PoC 示範：先啟動 LS，再依序執行 A（加密）→ B（解密）
"""
import os
import sys
import time
import subprocess

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
DEMO = os.environ.get("DEMO", "1") == "1"  # 預設開啟 Demo 模式


def run_ls():
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["DEMO"] = "1" if DEMO else "0"
    # Demo 模式：LS 輸出到終端；否則擷取以檢測啟動失敗
    kwargs = {"cwd": ROOT, "env": env, "text": True}
    if DEMO:
        kwargs["stdout"] = None
        kwargs["stderr"] = None
    else:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.STDOUT
    proc = subprocess.Popen([sys.executable, "license_server.py"], **kwargs)
    return proc


def sep(title="", _print=None):
    p = _print or (lambda m: __builtins__.print(m, flush=True))
    if DEMO:
        p("\n" + "─" * 50)
        if title:
            p(f"  {title}")
            p("─" * 50)


def main():
    if DEMO:
        os.environ["DEMO"] = "1"
    _p = lambda msg: __builtins__.print(msg, flush=True)
    _p("")
    _p("╔══════════════════════════════════════════════════════╗")
    _p("║   DEK PoC：LS + 軟體A(加密) + 軟體B(解密) 流程示範   ║")
    _p("╚══════════════════════════════════════════════════════╝")
    sep("階段 0：啟動 License Server", _print=_p)
    _p("  [LS] 監聽 port 5000...")
    ls_proc = run_ls()
    time.sleep(1.5)
    if ls_proc.poll() is not None:
        if not DEMO:
            out, _ = ls_proc.communicate()
            _p("  [X] LS 啟動失敗: " + (out or "無輸出"))
        else:
            _p("  [X] LS 啟動失敗")
        sys.exit(1)
    _p("  [OK] LS 已就緒")
    try:
        demo_input = "demo_input.txt"
        if not os.path.exists(demo_input):
            with open(demo_input, "w", encoding="utf-8") as f:
                f.write("這是 PoC 示範文件。\n機密內容：DEK 由 LS 派發，A 加密、B 解密。\n")
            if DEMO:
                _p(f"  [預備] 建立示範輸入檔 {demo_input}")

        sep("階段 1：軟體 A 執行加密", _print=_p)
        subprocess.run([sys.executable, "software_a.py", demo_input, "encrypted_output"], check=True, cwd=ROOT)

        sep("階段 2：軟體 B 執行解密", _print=_p)
        subprocess.run([sys.executable, "software_b.py", "encrypted_output", "decrypted_output.txt"], check=True, cwd=ROOT)

        sep("階段 3：驗證結果", _print=_p)
        with open(demo_input, "rb") as f:
            orig = f.read()
        with open("decrypted_output.txt", "rb") as f:
            dec = f.read()
        if orig == dec:
            _p("  [OK] 原始檔與解密檔 位元組完全一致")
            if DEMO:
                _p("\n  【解密還原的內容】")
                _p("  " + "-" * 44)
                for line in dec.decode("utf-8", errors="replace").strip().split("\n"):
                    _p(f"  │ {line}")
                _p("  " + "-" * 44)
            _p("\n  *** PoC 成功：DEK 派發 → A 加密 → B 解密 流程驗證通過")
        else:
            _p("  [X] 內容不一致，請檢查。")
            sys.exit(1)
    finally:
        ls_proc.terminate()
        ls_proc.wait(timeout=3)
    _p("\n" + "═" * 52 + "\n")


if __name__ == "__main__":
    main()
