import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from dotenv import load_dotenv

import paramiko
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


load_dotenv()
BASE_URL = os.getenv('BASE_URL')
SFTP_HOST = os.getenv('SFTP_HOST')
SFTP_PORT = int(os.getenv('SFTP_PORT'))
SFTP_USER = os.getenv('SFTP_USER')
SFTP_PASSWORD = os.getenv('SFTP_PASSWORD')
REMOTE_DIR = os.getenv('REMOTE_DIR')
SFTP_KEYFILE = str(Path.home() / ".ssh" / "id_rsa")

MAX_FRAGMENT_LEN = 260
FRAGMENTS_PER_TOKEN = 1

# Локальные файлы
OUT_DIR = Path("out")
INDEX_PATH = Path("log_index.jsonl")


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def token32() -> str:
    # 24 bytes -> 32 base64url chars (без '=')
    t = base64.urlsafe_b64encode(os.urandom(24)).decode("ascii").rstrip("=")
    return t if len(t) == 32 else token32()


def gen_id8() -> str:
    # 5 bytes -> base32 ~8 символов без '=' (низкий шанс коллизий)
    raw = os.urandom(5)
    s = base64.b32encode(raw).decode("ascii").rstrip("=").lower()
    return s[:8]


def split_text(text: str, _max_len: int) -> List[str]:
    text = text.replace("\r", "").strip()
    if not text:
        return []
    # фрагменты = только абзацы, разделённые пустой строкой
    return [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]


def encrypt_fragment(token: str, plaintext: str) -> dict:
    key = sha256(token.encode("utf-8"))  # 32 bytes
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)  # ciphertext||tag
    return {"nonce_b64": b64(iv), "ct_b64": b64(ct)}


def ensure_remote_dir(sftp: paramiko.SFTPClient, remote_dir: str) -> None:
    parts = [p for p in remote_dir.strip("/").split("/") if p]
    cur = ""
    for p in parts:
        cur += "/" + p
        try:
            sftp.stat(cur)
        except FileNotFoundError:
            sftp.mkdir(cur)


def load_used_ids() -> set:
    used = set()
    if not INDEX_PATH.exists():
        return used
    with INDEX_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if "id" in obj:
                    used.add(str(obj["id"]))
            except Exception:
                pass
    return used


def connect_sftp():
    transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    if SFTP_KEYFILE and Path(SFTP_KEYFILE).exists():
        pkey = paramiko.RSAKey.from_private_key_file(SFTP_KEYFILE, password=SFTP_PASSWORD)
        transport.connect(username=SFTP_USER, pkey=pkey)
    else:
        if not SFTP_PASSWORD:
            raise RuntimeError("No keyfile and no password set.")
        transport.connect(username=SFTP_USER, password=SFTP_PASSWORD)
    sftp = paramiko.SFTPClient.from_transport(transport)
    return transport, sftp


def remote_exists(sftp: paramiko.SFTPClient, remote_path: str) -> bool:
    try:
        sftp.stat(remote_path)
        return True
    except FileNotFoundError:
        return False


def pick_unique_id(sftp: paramiko.SFTPClient) -> str:
    used_local = load_used_ids()
    for _ in range(2000):
        cid = gen_id8()
        if cid in used_local:
            continue
        rpath = REMOTE_DIR.rstrip("/") + f"/{cid}.json"
        if remote_exists(sftp, rpath):
            continue
        return cid
    raise RuntimeError("Failed to generate unique id (too many collisions).")


def write_index(entry: dict) -> None:
    with INDEX_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def main():
    if len(sys.argv) != 2:
        print("Usage: python publish_log.py <log.txt>")
        sys.exit(1)

    infile = Path(sys.argv[1])
    if not infile.exists():
        print(f"File not found: {infile}")
        sys.exit(1)

    text = infile.read_text(encoding="utf-8")
    frags = split_text(text, MAX_FRAGMENT_LEN)
    if not frags:
        print("Empty log after stripping.")
        sys.exit(1)

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    transport, sftp = connect_sftp()
    try:
        ensure_remote_dir(sftp, REMOTE_DIR)
        log_id = pick_unique_id(sftp)

        title = infile.stem
        created = datetime.now(timezone.utc).isoformat()

        salt = os.urandom(16)
        salt_b64 = b64(salt)

        tokens: List[str] = []
        fragments_out: List[dict] = []

        for i, frag_txt in enumerate(frags):
            group = i // FRAGMENTS_PER_TOKEN
            while len(tokens) <= group:
                tokens.append(token32())
            tok = tokens[group]

            need_hash_hex = sha256(salt + tok.encode("utf-8")).hex()
            enc = encrypt_fragment(tok, frag_txt)

            fragments_out.append({
                "i": i,
                "type": "text",
                "need_hash_hex": need_hash_hex,
                "nonce_b64": enc["nonce_b64"],
                "ct_b64": enc["ct_b64"],
            })

        log_json = {
            "id": log_id,
            "title": f"LOG // {title}",
            "created": created,
            "salt_b64": salt_b64,
            "fragments": fragments_out,
        }

        local_json = OUT_DIR / f"{log_id}.json"
        local_json.write_text(json.dumps(log_json, ensure_ascii=False, indent=2), encoding="utf-8")

        remote_json = REMOTE_DIR.rstrip("/") + f"/{log_id}.json"
        sftp.put(str(local_json), remote_json)

        links = [f"{BASE_URL.rstrip('/')}/t/#{log_id}&k={t}" for t in tokens]
        tokens_txt = "LOG " + log_id + "\n" + "\n".join(f"{i+1}. {u}" for i, u in enumerate(links)) + "\n"
        local_tokens = OUT_DIR / f"{log_id}_tokens.txt"
        local_tokens.write_text(tokens_txt, encoding="utf-8")

        write_index({
            "ts": datetime.now(timezone.utc).isoformat(),
            "id": log_id,
            "title": title,
            "source_file": str(infile.resolve()),
            "fragments": len(fragments_out),
            "tokens": len(tokens),
            "remote": remote_json
        })

        print(f"LOG ID: {log_id}")
        print(f"Viewer: {BASE_URL.rstrip('/')}/t/#{log_id}")
        print("Links:")
        for u in links:
            print(u)
        print(f"\nSaved locally: {local_json} , {local_tokens} , index: {INDEX_PATH}")

    finally:
        sftp.close()
        transport.close()


if __name__ == "__main__":
    main()
