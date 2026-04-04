#!/usr/bin/env python3
import sys, subprocess, base64
import oqs

PUBLIC_KEY_FILE = ".github/public_key.pem"

def main():
    if len(sys.argv) < 2:
        sys.exit(1)
    commit = sys.argv[1]

    msg = subprocess.check_output(["git", "log", "-1", "--format=%B", commit], text=True)
    lines = msg.splitlines()
    original = []
    sig_b64 = None
    in_sig = False
    for line in lines:
        if "-----BEGIN PGP SIGNATURE-----" in line:
            in_sig = True
            continue
        if "-----END PGP SIGNATURE-----" in line:
            break
        if in_sig:
            sig_b64 = line.strip()
        else:
            original.append(line)

    original_msg = "\n".join(original).strip()
    if not sig_b64:
        print(f"❌ Commit {commit[:7]} has no PQC signature")
        sys.exit(1)

    try:
        signature = base64.b64decode(sig_b64)
    except Exception as e:
        print(f"❌ Commit {commit[:7]} invalid signature base64: {e}")
        sys.exit(1)

    with open(PUBLIC_KEY_FILE, "rb") as f:
        pub = f.read()
    with oqs.Signature("ML-DSA-65") as v:
        valid = v.verify(original_msg.encode(), signature, pub)

    if valid:
        print(f"✅ Commit {commit[:7]} signature VALID")
        sys.exit(0)
    else:
        print(f"❌ Commit {commit[:7]} signature INVALID")
        sys.exit(1)

if __name__ == "__main__":
    main()
