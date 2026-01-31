#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import shlex
import requests

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    RESET = "\033[0m"

    @staticmethod
    def green(text):
        return f"{Colors.GREEN}{text}{Colors.RESET}"

    @staticmethod
    def red(text):
        return f"{Colors.RED}{text}{Colors.RESET}"

IP_CHECK_URL = "https://ipinfo.io/json"

def check_proxy_location(proxy):
    """Checks the proxy's current location"""
    proxies = {
        "http": proxy,
        "https": proxy,
    }

    try:
        r = requests.get(
            IP_CHECK_URL,
            proxies=proxies,
            timeout=10
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def main():
    parser = argparse.ArgumentParser(description="Proxy launcher for vibe_dumper.py")
    parser.add_argument(
        "-u", "--username",
        dest="user",
        required=True,
        help="Proxy username"
    )

    parser.add_argument(
        "-p", "--password",
        dest="password",
        required=True,
        help="Proxy password"
    )

    parser.add_argument(
        "-i", "--ip",
        dest="ip",
        required=True,
        help="Proxy IP:PORT"
    )

    parser.add_argument(
        "-c", "--command",
        dest="command",
        required=True,
        help='Command string for vibe_dumper.py (quoted)'
    )

    args = parser.parse_args()

    proxy = f"http://{args.user}:{args.password}@{args.ip}"

    print("[*] Verifying proxy connection...")
    info = check_proxy_location(proxy)

    if "error" in info:
        print("[!] Proxy check FAILED")
        print(f"[!] Error: {info['error']}")
        print("[!] Aborting to avoid IP leak.")
        sys.exit(1)

    ip = info.get("ip", "unknown")
    city = info.get("city", "unknown")
    region = info.get("region", "unknown")
    country = info.get("country", "unknown")
    org = info.get("org", "unknown")

    print("\n[*] Current outbound identity (via proxy):")
    print(f"    IP       : {ip}")
    print(f"    Location : {city}, {region}, {country}")
    print(f"    ASN/Org  : {org}")

    choice = input("\n[?] Continue with vibe_dumper.py? [y/N]: ").strip().lower()
    if choice != "y":
        print(Colors.red("[*] Aborted by user."))
        sys.exit(0)

    env = os.environ.copy()
    env["HTTP_PROXY"] = proxy
    env["HTTPS_PROXY"] = proxy
    env["ALL_PROXY"] = proxy

    cmd = [
        sys.executable,
        "vibe-dumper.py",
        *shlex.split(args.command)
    ]

    print("\n" + Colors.green("[*] Starting vibe_dumper.py...") + "\n")
    subprocess.run(cmd, env=env)

if __name__ == "__main__":
    main()