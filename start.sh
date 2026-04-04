#!/bin/bash
# Generate keys if they don't exist
if [ ! -f public_key.pem ] || [ ! -f private_key.pem ]; then
    echo "Generating PQC keys..."
    python3 keygen.py
fi
# Start the Flask app
exec python3 app.py
