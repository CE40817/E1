#!/usr/bin/env python3
import socket
import threading
import time
import os
import secrets
import hashlib
import base64

HOST = "0.0.0.0"
PORT = int(os.getenv("PORT", "2135"))

POW_ZEROS = 4
EARLY_TTL = 2
SALT = b"\x13\x37\xC0\xFF\xEE\x42\x21\x09"

STATE = {
    "ticket_db": {},
    "voucher_used": set(),
    "ledger": {"accounts": {"main": 0, "vault": 0}},
    "flag": None,
    "target": int(os.getenv("TARGET_BALANCE", "300")),
    "v_code": [95, 78, 93, 75, 76, 72, 79, 49, 48, 48],
}

def load_flag():
    try:
        with open("/app/flag.txt", "r") as f:
            STATE["flag"] = f.read().strip()
    except Exception:
        STATE["flag"] = "ASIS{flag_missing_in_container}"

def fmt(resp: str) -> bytes:
    return (resp + "\n").encode()

def get_balance() -> int:
    return STATE["ledger"]["accounts"]["main"] + STATE["ledger"]["accounts"]["vault"]

def update_balance(amount: int) -> None:
    STATE["ledger"]["accounts"]["main"] += amount

def h256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def b32(s: bytes) -> str:
    return base64.b32encode(s).decode().rstrip("=")

def op_names(ticket: str):
    digest = hashlib.sha1(ticket.encode()).digest()
    tag = b32(digest)
    pay = "P" + tag[:2]
    red = "R" + tag[2:4]
    return pay, red

def per_ticket_voucher(ticket: str) -> str:
    seed = bytes(STATE["v_code"])
    mask = h256(ticket.encode())
    mixed = bytes(a ^ b for a, b in zip(seed, mask))
    b64 = base64.b64encode(mixed).decode()
    trans = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw0123456789-_"
    )
    return b64.translate(trans)

def verify_pow(ticket: str, nonce: str) -> bool:
    try:
        d = hashlib.sha256((ticket + nonce).encode()).hexdigest()
        return d.endswith("0" * POW_ZEROS)
    except Exception:
        return False

def commit_sig(ticket: str, total: int) -> str:
    return hashlib.sha256(ticket.encode() + str(total).encode() + SALT).hexdigest()[:16]

def parse_kv(s: str) -> dict:
    out = {}
    for p in s.split("&"):
        if "=" in p:
            k, v = p.split("=", 1)
            out[k] = v
    return out

def recv_line(conn, timeout=10.0) -> str:
    conn.settimeout(timeout)
    data = b""
    while True:
        ch = conn.recv(1)
        if not ch:
            break
        data += ch
        if ch == b"\n":
            break
    return data.decode(errors="ignore").strip()

def handle_client(conn, addr):
    conn.settimeout(10.0)
    try:
        first = recv_line(conn)
        if not first:
            conn.close()
            return

        if first.upper() == "HELLO":
            ticket = secrets.token_hex(16)
            STATE["ticket_db"][ticket] = {"issued_at": time.time()}
            conn.sendall(fmt(f"TICKET:{ticket}"))
            conn.sendall(fmt("EARLY_DATA:1"))
            conn.sendall(fmt("OK"))
            conn.close()
            return

        if first.startswith("CLIENT_HELLO:"):
            ticket = first.split(":", 1)[1].strip()
            meta = STATE["ticket_db"].get(ticket)
            if not meta:
                conn.sendall(fmt("ERR:BAD_TICKET"))
                conn.close()
                return

            if time.time() - meta["issued_at"] > EARLY_TTL:
                conn.sendall(fmt("ERR:TICKET_EXPIRED_FOR_0RTT"))
                conn.close()
                return

            pay_cmd, redeem_cmd = op_names(ticket)
            voucher_code = per_ticket_voucher(ticket)
            early_total = 0
            pow_ok = False

            while True:
                l = recv_line(conn)
                if not l:
                    break
                if l == "EARLY:":
                    continue
                if l == ".":
                    break

                if not pow_ok:
                    if l.startswith("POW "):
                        kv = parse_kv(l[4:])
                        if verify_pow(ticket, kv.get("nonce", "")):
                            pow_ok = True
                            conn.sendall(fmt("OK:POW"))
                            continue
                    conn.sendall(fmt("ERR:POW_REQUIRED"))
                    conn.close()
                    return

                if l.startswith(f"{redeem_cmd} "):
                    kv = parse_kv(l[len(redeem_cmd) + 1:])
                    if kv.get("code", "") == voucher_code:
                        early_total += 100
                        conn.sendall(fmt("OK:REDEEMED"))
                    else:
                        conn.sendall(fmt("ERR:CODE"))

                elif l.startswith(f"{pay_cmd} "):
                    kv = parse_kv(l[len(pay_cmd) + 1:])
                    try:
                        amt = int(kv.get("amt", "0"))
                    except Exception:
                        amt = 0
                    if amt > 25:
                        conn.sendall(fmt("OK:PAID:IGNORED_BIG"))
                        continue
                    early_total += amt
                    conn.sendall(fmt(f"OK:PAID:{amt}"))

                else:
                    conn.sendall(fmt("ERR:UNKNOWN"))

            conn.sendall(fmt("HS_DONE"))
            conn.sendall(fmt(f"EARLY_TOTAL:{early_total}"))

            commit_line = recv_line(conn)
            if not commit_line.startswith("COMMIT "):
                conn.sendall(fmt("ERR:COMMIT_REQUIRED"))
                conn.sendall(fmt(f"BALANCE:{get_balance()}"))
                conn.close()
                return

            kv = parse_kv(commit_line[7:])
            if kv.get("sig", "") != commit_sig(ticket, early_total):
                conn.sendall(fmt("ERR:BAD_SIG"))
                conn.sendall(fmt(f"BALANCE:{get_balance()}"))
                conn.close()
                return

            update_balance(early_total)
            conn.sendall(fmt("OK:COMMITTED"))
            current_balance = get_balance()
            conn.sendall(fmt(f"BALANCE:{current_balance}"))
            if current_balance >= STATE["target"]:
                conn.sendall(fmt(f"FLAG:{STATE['flag']}"))
            conn.close()
            return

        if first.startswith("GET /flag"):
            current_balance = get_balance()
            if current_balance >= STATE["target"]:
                conn.sendall(fmt(f"FLAG:{STATE['flag']}"))
            else:
                conn.sendall(fmt("ERR:LOW_BALANCE"))
            conn.close()
            return

        if first.startswith("POST /redeem "):
            kv = parse_kv(first[len("POST /redeem "):])
            code = kv.get("code", "")
            static_code = "".join(chr(c ^ 0) for c in STATE["v_code"])
            if code == static_code and code not in STATE["voucher_used"]:
                STATE["voucher_used"].add(code)
                update_balance(100)
                conn.sendall(fmt("OK"))
            else:
                conn.sendall(fmt("ERR"))
            conn.close()
            return

        conn.sendall(fmt("ERR:BAD_START"))
        conn.close()

    except Exception:
        try:
            conn.sendall(fmt("ERR:INTERNAL_SERVER_ISSUE"))
        except Exception:
            pass
        conn.close()

def serve():
    load_flag()
    print(f"[server] listening on {HOST}:{PORT}, target balance {STATE['target']}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(128)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    serve()
