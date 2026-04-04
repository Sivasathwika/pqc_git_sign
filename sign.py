import oqs
import sys
import hashlib

def sign_data(data, secret_key_file):
    with open(secret_key_file, "rb") as f:
        secret_key = f.read()
<<<<<<< HEAD
    with oqs.Signature("ML-DSA-65", secret_key) as sig:
        signature = sig.sign(data)
=======
    sig = oqs.Signature("ML-DSA-65")
    signature = sig.sign(data, secret_key)
    sig.free()
>>>>>>> a411c3e475eeeee2ee3279afa143dab5350fae0d
    return signature

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sign.py <commit_hash_or_file>")
        sys.exit(1)
<<<<<<< HEAD

    input_data = sys.argv[1]
=======
    
    input_data = sys.argv[1]
    # If input is a file, read it; else treat as raw string
>>>>>>> a411c3e475eeeee2ee3279afa143dab5350fae0d
    try:
        with open(input_data, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        data = input_data.encode()
<<<<<<< HEAD

    commit_hash = hashlib.sha256(data).digest()

=======
    
    # Hash it to simulate commit hash
    commit_hash = hashlib.sha256(data).digest()
    
>>>>>>> a411c3e475eeeee2ee3279afa143dab5350fae0d
    signature = sign_data(commit_hash, "private_key.pem")
    print("Signature (hex):", signature.hex())
    with open("signature.sig", "wb") as f:
        f.write(signature)
<<<<<<< HEAD
    print("Signature saved to signature.sig")
=======
    print("Signature saved to signature.sig")
>>>>>>> a411c3e475eeeee2ee3279afa143dab5350fae0d
