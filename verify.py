import oqs
import sys
import hashlib

def verify_data(data, signature, public_key_file):
    with open(public_key_file, "rb") as f:
        public_key = f.read()
    with oqs.Signature("ML-DSA-65") as verifier:
        is_valid = verifier.verify(data, signature, public_key)
    return is_valid

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify.py <original_commit_hash_or_file>")
        sys.exit(1)

    input_data = sys.argv[1]
    try:
        with open(input_data, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        data = input_data.encode()

    commit_hash = hashlib.sha256(data).digest()

    try:
        with open("signature.sig", "rb") as f:
            signature = f.read()
    except FileNotFoundError:
        print("❌ signature.sig not found. Run sign.py first.")
        sys.exit(1)

    valid = verify_data(commit_hash, signature, "public_key.pem")
    if valid:
        print("✅ Signature is VALID")
        sys.exit(0)
    else:
        print("❌ Signature is INVALID")
        sys.exit(1)
