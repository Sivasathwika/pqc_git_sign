#!/usr/bin/env python3
import sys
import subprocess
import hashlib
import base64
import oqs

PUBLIC_KEY_FILE = ".github/public_key.pem"

def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        return f.read()

def get_commit_signature(commit_hash):
    result = subprocess.run(
        ["git", "show", "--format=%GG", "-s", commit_hash],
        capture_output=True, text=True
    )
    sig_text = result.stdout.strip()
    if not sig_text or "-----BEGIN PGP SIGNATURE-----" not in sig_text:
        return None
    lines = sig_text.splitlines()
    sig_b64 = ""
    in_sig = False
    for line in lines:
        if "BEGIN PGP SIGNATURE" in line:
            in_sig = True
            continue
        if "END PGP SIGNATURE" in line:
            break
        if in_sig:
            sig_b64 += line.strip()
    try:
        return base64.b64decode(sig_b64)
    except:
        return None

def get_commit_content_hash(commit_hash):
    result = subprocess.run(
        ["git", "cat-file", "commit", commit_hash],
        capture_output=True, text=True
    )
    return hashlib.sha256(result.stdout.encode()).digest()

def main():
    if len(sys.argv) < 2:
        print("Usage: verify_commit_pqc.py <commit-hash>")
        sys.exit(1)
    commit = sys.argv[1]
    print(f"Verifying commit {commit}...")
    public_key = load_public_key()
    signature = get_commit_signature(commit)
    if signature is None:
        print("❌ No PQC signature found in commit")
        sys.exit(1)
    commit_hash = get_commit_content_hash(commit)
    with oqs.Signature("ML-DSA-65") as verifier:
        is_valid = verifier.verify(commit_hash, signature, public_key)
    if is_valid:
        print(f"✅ Commit {commit} signature is VALID")
        sys.exit(0)
    else:
        print(f"❌ Commit {commit} signature is INVALID")
        sys.exit(1)

if __name__ == "__main__":
    main()
