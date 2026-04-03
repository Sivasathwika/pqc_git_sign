import oqs
import sys
import hashlib

def sign_data(data, secret_key_file):
    with open(secret_key_file, "rb") as f:
        secret_key = f.read()
    with oqs.Signature("ML-DSA-65", secret_key) as sig:
        signature = sig.sign(data)
    return signature

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sign.py <commit_hash_or_file>")
        sys.exit(1)

    input_data = sys.argv[1]
    try:
        with open(input_data, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        data = input_data.encode()

    commit_hash = hashlib.sha256(data).digest()

    signature = sign_data(commit_hash, "private_key.pem")
    print("Signature (hex):", signature.hex())
    with open("signature.sig", "wb") as f:
        f.write(signature)
    print("Signature saved to signature.sig")
