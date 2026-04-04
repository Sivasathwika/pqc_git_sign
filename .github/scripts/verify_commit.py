#!/usr/bin/env python3
import sys, subprocess, base64
import oqs

PUBLIC_KEY_FILE = ".github/public_key.pem"

def main():
    if len(sys.argv) < 2:
        sys.exit(1)
    commit = sys.argv[1]
    # Extract signature from commit message
    out = subprocess.run(["git", "show", "--format=%GG", "-s", commit], capture_output=True, text=True)
    sig_text = out.stdout.strip()
    if "-----BEGIN PGP SIGNATURE-----" not in sig_text:
        print(f"❌ Commit {commit[:7]} has no PQC signature")
        sys.exit(1)
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
    signature = base64.b64decode(sig_b64)
    # Get original commit message (without signature)
    msg = subprocess.check_output(["git", "log", "-1", "--format=%B", commit], text=True)
    orig_lines = []
    for line in msg.splitlines():
        if "-----BEGIN PGP SIGNATURE-----" in line:
            break
        orig_lines.append(line)
    original_msg = "\n".join(orig_lines).strip()
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
