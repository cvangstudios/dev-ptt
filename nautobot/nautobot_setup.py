"""
nautobot_setup.py
-----------------
Run this ONCE to generate a Nautobot API token and save it to nautobotApi.cfg.

After this runs successfully, all future scripts will read from nautobotApi.cfg
and will not need your username or password again.

Requirements:
    pip install requests

Usage:
    python nautobot_setup.py
"""

import requests
import getpass
import urllib3
import configparser
import os
from datetime import datetime

# -------------------------------------------------------
# Suppress SSL warnings for self-signed certs in the lab.
# Remove this line if your Nautobot has a valid SSL cert.
# -------------------------------------------------------
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_FILE = "nautobotApi.cfg"


def prompt_user():
    """Prompt for connection details. Password is hidden while typing."""
    print("\n" + "=" * 55)
    print("  Nautobot One-Time Setup — Token Generator")
    print("=" * 55)

    url      = input("\nNautobot URL (e.g. https://nautobot.lab.local): ").strip().rstrip("/")
    username = input("Username: ").strip()
    password = getpass.getpass("Password (hidden): ")

    return url, username, password


def generate_token(url, username, password):
    """
    POST to /api/users/tokens/ using Basic Auth.
    Returns the token string if successful.
    """
    print(f"\n[*] Connecting to {url} ...")

    try:
        response = requests.post(
            f"{url}/api/users/tokens/",
            auth=(username, password),
            headers={
                "Accept":       "application/json",
                "Content-Type": "application/json",
            },
            json={"description": f"nautobot_setup.py — {datetime.now().strftime('%Y-%m-%d')}"},
            verify=False,   # Set to True if you have a valid SSL cert
            timeout=10,
        )

    except requests.exceptions.ConnectionError:
        print(f"\n[-] ERROR: Cannot reach {url}")
        print("    Check the URL and that Nautobot is running.")
        return None

    except requests.exceptions.Timeout:
        print(f"\n[-] ERROR: Connection to {url} timed out.")
        return None

    # -------------------------------------------------------
    # Handle response codes
    # -------------------------------------------------------
    if response.status_code in (200, 201):
        token = response.json().get("key")
        if token:
            print(f"[+] Token generated successfully.")
            return token
        else:
            print("[-] ERROR: Response was OK but no token key found.")
            print(f"    Raw response: {response.text}")
            return None

    elif response.status_code == 400:
        print(f"[-] ERROR: Bad request (HTTP 400).")
        print(f"    Response: {response.text}")
        return None

    elif response.status_code == 401:
        print("[-] ERROR: Invalid username or password (HTTP 401).")
        return None

    elif response.status_code == 403:
        print("[-] ERROR: Access denied (HTTP 403).")
        print("    Your account may not have permission to create tokens.")
        print("    Ask your Nautobot admin to grant token creation rights.")
        return None

    else:
        print(f"[-] ERROR: Unexpected response HTTP {response.status_code}")
        print(f"    Response: {response.text}")
        return None


def save_config(url, token):
    """Write URL and token to nautobotApi.cfg."""
    config = configparser.ConfigParser()
    config["nautobot"] = {
        "url":   url,
        "token": token,
    }

    with open(CONFIG_FILE, "w") as f:
        config.write(f)

    print(f"[+] Config saved to: {os.path.abspath(CONFIG_FILE)}")


def main():
    # Check if config already exists
    if os.path.exists(CONFIG_FILE):
        print(f"\n[!] WARNING: {CONFIG_FILE} already exists.")
        overwrite = input("    Overwrite it with a new token? (yes/no): ").strip().lower()
        if overwrite != "yes":
            print("[*] Exiting — existing config left unchanged.")
            return

    # Get credentials from user
    url, username, password = prompt_user()

    # Generate the token
    token = generate_token(url, username, password)

    if not token:
        print("\n[-] Setup failed. No config file written.")
        return

    # Save to config file
    save_config(url, token)

    print(f"\n{'=' * 55}")
    print("  Setup complete!")
    print(f"  Your scripts can now read from: {CONFIG_FILE}")
    print(f"  Token preview: {token[:6]}...{token[-4:]}")
    print(f"{'=' * 55}\n")


if __name__ == "__main__":
    main()
