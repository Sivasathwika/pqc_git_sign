# PQC-Signed Git Commits

Quantum-safe commit signing using Dilithium (ML-DSA-65).

## Problem
Today's Git commit signatures (RSA/ECDSA) will be broken by future quantum computers, allowing history to be forged.

## Solution
A CLI tool that signs commits with NIST-standardized post-quantum algorithm ML-DSA, and a GitHub Action that verifies signatures before merge.

## Tech Stack
- Python 3.10+
- liboqs (Open Quantum Safe)
- GitHub Actions

## Setup Instructions
1. Clone repo
2. Install dependencies: `pip install -r requirements.txt`
3. Install liboqs: `sudo apt install liboqs-dev` (Ubuntu)
4. Run demo: `python demo.py`

## Demo Video
[Link to YouTube/Drive]

## Future Scope
- Full Git integration (replace GPG)
- DNS TXT record for public key distribution
- On-chain storage for decentralized verification

## Point of Contact
Your Name – sivasathwika.nelluri@gmail.com
GitHub: @Sivasathwika
