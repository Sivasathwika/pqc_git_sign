#!/usr/bin/env python3
import requests, sys

def verify_commit(commit_id):
    try:
        resp = requests.get(f"http://localhost:5000/commit-details/{commit_id}")
        if resp.status_code != 200:
            print(f"❌ Commit {commit_id} not found")
            return False
        data = resp.json()
        if data.get("verified"):
            print(f"✅ Commit {commit_id} is VALID (verified)")
            return True
        else:
            print(f"❌ Commit {commit_id} is INVALID")
            if not data.get('content_matches'):
                print("   Reason: Commit content was tampered (hash mismatch)")
            elif not data.get('crypto_valid'):
                print("   Reason: Cryptographic signature is invalid")
            else:
                print("   Reason: Unknown verification failure")
            return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_commit.py <commit_id>")
        sys.exit(1)
    commit_id = sys.argv[1]
    sys.exit(0 if verify_commit(commit_id) else 1)
