#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""export_auth_from_ide.py — 从 CodeBuddy 桌面端 IDE SecretStorage 导出登录态为 .info 文件。

背景（2026-11 桌面端 1.106.1 起）：
  桌面端把完整登录态存进 VS Code 式 SecretStorage（%APPDATA%\\CodeBuddy CN\\User\\
  globalStorage\\state.vscdb），不再往 %LOCALAPPDATA%\\CodeBuddyExtension\\Data\\Public\\auth\\
  写明文 .info 文件。CLI（2.x）登录时仍会写该文件。本脚本提供不依赖 CLI 的第三条恢复通道：
  直接解密 IDE SecretStorage 中的登录态，组装成转换器/CLI 可读的 .info 文件。

SecretStorage 布局（genie AuthenticationService.storeSessionByChunks，三块）：
  主 secret   = secret://{"extensionId":"tencent-cloud.coding-copilot",
                "key":"<storageKey>"}                     → 会话 JSON（refreshToken/accounts 置空）
  <storageKey>_refresh_token → refreshToken 纯串
  <storageKey>_accounts      → account 数组 JSON
  （storageKey 默认 "planning-genie.new.accessTokencn"，可被 product.json 的
    genieAuthentication.attributes.storageKey 覆盖——--storage-key 可显式指定。）

加密（Chromium safeStorage, Windows）：
  Local State "os_crypt.encrypted_key" → base64 → 去 "DPAPI" 前缀 → DPAPI 解出 32B AES 主钥；
  条目格式 "v10" + 12B nonce + 密文 + 16B tag（AES-256-GCM）。

用法：
  python -X utf8 export_auth_from_ide.py --dry-run     # 只打印结构与新鲜度，不写盘
  python -X utf8 export_auth_from_ide.py               # 导出到默认 .info 路径
  python -X utf8 export_auth_from_ide.py --out x.info --force

安全提醒：本脚本会接触真实凭据；输出文件含明文 token，勿提交、勿外传。
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import ctypes.wintypes as wt
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

DEFAULT_STORAGE_KEY = "planning-genie.new.accessTokencn"
DEFAULT_EXTENSION_ID = "tencent-cloud.coding-copilot"
DEFAULT_IDE_APP_DIRS = ("CodeBuddy CN", "WorkBuddy")
APPDATA = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
LOCALAPPDATA = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))


# ---------------------------------------------------------------------------
# DPAPI / AES-GCM
# ---------------------------------------------------------------------------

class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_unprotect(data: bytes) -> bytes:
    pb = ctypes.cast(ctypes.create_string_buffer(bytes(data), len(data)),
                     ctypes.POINTER(ctypes.c_char))
    blob_in = DATA_BLOB(len(data), pb)
    blob_out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
        raise OSError("CryptUnprotectData 失败 err=%d" % ctypes.GetLastError())
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(
            ctypes.c_void_p(ctypes.cast(blob_out.pbData, ctypes.c_void_p).value))


def load_os_crypt_key(local_state_path: Path) -> bytes:
    """读 Local State 的 os_crypt.encrypted_key，DPAPI 解出 32 字节 AES-256 主钥。"""
    ls = json.loads(local_state_path.read_text(encoding="utf-8"))
    enc_key = base64.b64decode(ls["os_crypt"]["encrypted_key"])
    if enc_key[:5] != b"DPAPI":
        raise RuntimeError(
            f"Local State 里 os_crypt.encrypted_key 前缀是 {enc_key[:5]!r}（期望 DPAPI）。"
            "可能是 App-Bound Encryption（v20），外部进程无法复刻。")
    key = dpapi_unprotect(enc_key[5:])
    if len(key) != 32:
        raise RuntimeError(f"DPAPI 解出的 AES 主钥长度 {len(key)} != 32")
    return key


def aesgcm_decrypt(blob: bytes, key: bytes) -> bytes:
    """Chromium v10: 'v10'(3) + nonce(12) + ciphertext + tag(16)，AES-256-GCM。"""
    if blob[:3] != b"v10":
        raise RuntimeError(f"secret blob 前缀 {blob[:3]!r} 不是 v10")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    return AESGCM(key).decrypt(blob[3:15], blob[15:], None)


# ---------------------------------------------------------------------------
# SecretStorage 读取
# ---------------------------------------------------------------------------

def find_state_vscdb() -> Path:
    for name in DEFAULT_IDE_APP_DIRS:
        p = APPDATA / name / "User" / "globalStorage" / "state.vscdb"
        if p.is_file():
            return p
    raise FileNotFoundError(
        f"未找到 state.vscdb（尝试过 {APPDATA}\\{' 或 '.join(DEFAULT_IDE_APP_DIRS)}\\User\\globalStorage\\）。"
        "用 --vscdb 显式指定。")


def secret_row(con: sqlite3.Connection, ext_id: str, key: str) -> bytes | None:
    """ItemTable 里的条目形如 'secret://{"extensionId":...,"key":...}'，值为 JSON Buffer 串。"""
    row = con.execute("SELECT value FROM ItemTable WHERE key=?", (
        'secret://' + json.dumps({"extensionId": ext_id, "key": key},
                                  ensure_ascii=False, separators=(",", ":")),)).fetchone()
    if row is None or row[0] is None:
        return None
    v = row[0]
    if isinstance(v, (bytes, bytearray)):
        v = v.decode("utf-8", "replace")
    obj = json.loads(v)
    data = bytes(obj["data"]) if isinstance(obj, dict) and "data" in obj else bytes(obj)
    return data or None


# ---------------------------------------------------------------------------
# 组装 .info
# ---------------------------------------------------------------------------

def assemble_secret(con, storage_key: str, ext_id: str, aes_key: bytes) -> dict:
    main_raw = secret_row(con, ext_id, storage_key)
    if main_raw is None:
        raise RuntimeError(f"主 secret 不存在：{ext_id} / {storage_key}")
    main = json.loads(aesgcm_decrypt(main_raw, aes_key).decode("utf-8"))

    auth = main.get("auth") or {}
    refresh = auth.get("refreshToken")
    accounts = main.get("accounts") or []

    if not refresh or not accounts:
        chunk_ref = secret_row(con, ext_id, storage_key + "_refresh_token")
        if chunk_ref is not None:
            refresh = refresh or aesgcm_decrypt(chunk_ref, aes_key).decode("utf-8")
            auth["refreshToken"] = refresh
            main["auth"] = auth
        chunk_acc = secret_row(con, ext_id, storage_key + "_accounts")
        if chunk_acc is not None and not accounts:
            accounts = json.loads(aesgcm_decrypt(chunk_acc, aes_key).decode("utf-8"))
            main["accounts"] = accounts

    if not refresh:
        raise RuntimeError("refreshToken 为空（主 secret 与 _refresh_token 分块都拿不到）——"
                           "登录态可能已被清空，去桌面端重新登录后再试。")

    # 归一到 CLI .info 的形状：{account, auth, accounts}
    account = main.get("account") or {}
    out = {"account": account, "auth": auth, "accounts": accounts or [account]}
    return out


def default_out_path() -> Path:
    return (LOCALAPPDATA / "CodeBuddyExtension" / "Data" / "Public" / "auth"
            / "Tencent-Cloud.coding-copilot.info")


# ---------------------------------------------------------------------------
# 校验（不泄露 token 本体）
# ---------------------------------------------------------------------------

def summarize(cred: dict) -> str:
    auth = cred.get("auth") or {}
    acct = cred.get("account") or {}
    exp = int(auth.get("expiresAt") or 0)
    ok_jwt = "?"
    try:
        part = auth["accessToken"].split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        exp2 = int(payload.get("exp") or 0)
        ok_jwt = "一致" if abs(exp2 * 1000 - exp) < 120_000 else f"JWT exp={time.strftime('%m-%d %H:%M', time.localtime(exp2))}"
    except Exception as e:
        ok_jwt = f"解析失败({e})"
    lines = [
        f"uid             : {acct.get('uid')}",
        f"昵称            : {acct.get('nickname')}",
        f"企业            : {acct.get('enterpriseId')} / {acct.get('enterpriseName','')}",
        f"expiresAt       : {time.strftime('%Y-%m-%d %H:%M', time.localtime(exp/1000)) if exp else '无'}",
        f"JWT 校验        : {ok_jwt}",
        f"accessToken 长度: {len(auth.get('accessToken') or '')}",
        f"refreshToken 长度: {len(auth.get('refreshToken') or '')}",
        f"domain          : {auth.get('domain')}",
        f"剩余有效期      : {(exp/1000 - time.time())/86400:.1f} 天",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="从 CodeBuddy 桌面端 IDE SecretStorage 导出登录态")
    ap.add_argument("--vscdb", default=None, help="state.vscdb 路径（默认自动定位）")
    ap.add_argument("--local-state", default=None, help="Local State 路径（默认与 vscdb 同 App 根）")
    ap.add_argument("--out", default=None, help=f"目标 .info 路径（默认 {default_out_path()}）")
    ap.add_argument("--storage-key", default=DEFAULT_STORAGE_KEY,
                    help=f"secret 主键（默认 {DEFAULT_STORAGE_KEY}）")
    ap.add_argument("--extension-id", default=DEFAULT_EXTENSION_ID,
                    help=f"扩展 id（默认 {DEFAULT_EXTENSION_ID}）")
    ap.add_argument("--dry-run", action="store_true", help="只打印，不写盘")
    ap.add_argument("--force", action="store_true", help="目标文件已存在时覆盖")
    args = ap.parse_args()

    if sys.platform != "win32":
        print("[!] 当前实现只支持 Windows（DPAPI）。macOS 需走 Keychain，后续再补。")
        return 2

    vscdb = Path(args.vscdb) if args.vscdb else find_state_vscdb()
    if not vscdb.is_file():
        print(f"[!] 文件不存在：{vscdb}")
        return 2
    local_state = (Path(args.local_state) if args.local_state
                   else vscdb.parent.parent.parent / "Local State")
    print(f"[i] vscdb      : {vscdb}")
    print(f"[i] Local State: {local_state}")

    aes_key = load_os_crypt_key(local_state)
    with sqlite3.connect(str(vscdb)) as con:
        cred = assemble_secret(con, args.storage_key, args.extension_id, aes_key)

    print()
    print(summarize(cred))
    print()

    out = Path(args.out) if args.out else default_out_path()
    if args.dry_run:
        print(f"[dry-run] 目标 {out}，未写盘。加 --dry-run 去掉即正式导出。")
        return 0
    if out.exists() and not args.force:
        print(f"[!] 目标已存在：{out}\n    确认要覆盖请加 --force（注意：会顶掉现有登录文件）。")
        return 3
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(cred, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, out)
    print(f"[✓] 已写出：{out}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[x] {e}", file=sys.stderr)
        sys.exit(1)
