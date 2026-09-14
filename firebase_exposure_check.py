"""
Firebase Realtime Database exposure STATUS checker for NETRA.
Confirms whether a misconfiguration exists, without extracting or storing
any of the database's actual contents.
"""
import sys
import requests
from datetime import datetime


def check_firebase_exposure(hostname: str):
    if not hostname.endswith("firebaseio.com"):
        print(f"Warning: '{hostname}' doesn't look like a Firebase RTDB hostname — proceeding anyway.")

    url = f"https://{hostname}/.json"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        resp = requests.get(url, params={"shallow": "true"}, timeout=10)
    except requests.RequestException as e:
        print(f"[{timestamp}] UNREACHABLE — {hostname}")
        print(f"  Could not connect: {e}")
        return

    print(f"[{timestamp}] Firebase exposure check: {hostname}")
    print(f"  HTTP status: {resp.status_code}")

    if resp.status_code == 200:
        try:
            data = resp.json()
            key_count = len(data) if isinstance(data, dict) else 0
            print(f"  RESULT: OPEN — database returned data (shallow mode: {key_count} top-level key(s) present)")
            print(f"  Top-level key COUNT only shown above — contents deliberately not printed or saved.")
            print(f"  ACTION: Document this finding (URL + timestamp + this output) and report through official channel. Do not query further.")
        except ValueError:
            print(f"  RESULT: OPEN — HTTP 200 returned but response wasn't valid JSON (still worth reporting)")
    elif resp.status_code in (401, 403):
        print(f"  RESULT: SECURED — access denied by security rules (this is the correct/expected state)")
    else:
        print(f"  RESULT: INCONCLUSIVE — unexpected status code {resp.status_code}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python firebase_exposure_check.py <hostname>")
        print("Example: python firebase_exposure_check.py rto-32-default-rtdb.firebaseio.com")
        sys.exit(1)

    check_firebase_exposure(sys.argv[1])
