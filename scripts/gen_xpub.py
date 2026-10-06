import hashlib
import sys
import base58

# 👇 PASTE YOUR HEX PUBLIC KEY FROM THE NODE LOGS HERE 👇
pubkey_hex = "031c1892039073daac5cff7af7df611b8c265838523cbd40a6709d6a5cf8f8577e"

pubkey_bytes = bytes.fromhex(pubkey_hex)
if len(pubkey_bytes) != 33:
    print("Error: Public key must be exactly 33 bytes (compressed SEC1 format).")
    sys.exit(1)

# 1. BIP32 Mainnet Public Key (xpub) version bytes
version = b'\x04\x88\xb2\x1e'

# 2. Hierarchy metadata (Master node)
depth = b'\x00'
parent_fingerprint = b'\x00\x00\x00\x00'
child_number = b'\x00\x00\x00\x00'

# 3. Chain Code: Since CGGMP21 doesn't generate one, we deterministically 
# derive a 32-byte chain code by hashing the public key. This is perfectly 
# valid for BIP32 public key derivation.
chain_code = hashlib.sha256(pubkey_bytes).digest()

# Assemble the 78-byte payload
payload = version + depth + parent_fingerprint + child_number + chain_code + pubkey_bytes

# Calculate Base58Check checksum (double SHA256)
checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

# Encode to Base58
xpub = base58.b58encode(payload + checksum).decode('utf-8')

print("\n✅ Successfully generated BIP32 xpub!")
print("Copy the string below and paste it into your .env file:\n")
print(f"MASTER_XPUB={xpub}\n")
