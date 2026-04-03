import oqs
import sys
import hashlib

def sign_data(data, secret_key_file):
    with open(secret_key_file, "rb") as f:
        secret_key = f.read()
    sig = oqs.Signature("ML-DSA-65")
    signature = sig.sign(data, secret_key)
    sig.free()
    return signature

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sign.py <commit_hash_or_file>")
        sys.exit(1)
    
    input_data = sys.argv[1]
    # If input is a file, read it; else treat as raw string
    try:
        with open(input_data, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        data = input_data.encode()
    
    # Hash it to simulate commit hash
    commit_hash = hashlib.sha256(data).digest()
    
    signature = sign_data(commit_hash, "private_key.pem")
    print("Signature (hex):", signature.hex())
    with open("signature.sig", "wb") as f:
        f.write(signature)
    print("Signature saved to signature.sig")