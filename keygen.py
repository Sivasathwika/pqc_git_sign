import oqs

def generate_keys():
    sig = oqs.Signature("ML-DSA-65")
    pub = sig.generate_keypair()
    priv = sig.export_secret_key()
    sig.free()
    
    with open("public_key.pem", "wb") as f:
        f.write(pub)
    with open("private_key.pem", "wb") as f:
        f.write(priv)
    
    print("✅ Keys generated: private_key.pem / public_key.pem")

if __name__ == "__main__":
    generate_keys()
