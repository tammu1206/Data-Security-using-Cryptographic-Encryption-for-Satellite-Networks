import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64

# === AES Utilities ===
def pad_message(msg):
    while len(msg) % 16 != 0:
        msg += " "
    return msg

def encrypt_aes(plaintext, aes_key):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    padded = pad_message(plaintext)
    encrypted = cipher.encrypt(padded.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_aes(encoded_ciphertext, aes_key):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    ciphertext = base64.b64decode(encoded_ciphertext)
    decrypted = cipher.decrypt(ciphertext).decode().strip()
    return decrypted

# === RSA Utilities ===
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()

def encrypt_rsa(public_key, message_bytes):
    encrypted = public_key.encrypt(
        message_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(encrypted).decode()

def decrypt_rsa(private_key, encoded_data):
    decoded = base64.b64decode(encoded_data)
    return private_key.decrypt(
        decoded,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# === Build CCSDS-style Packet ===
def build_ccsds_packet(encrypted_data, encrypted_key):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    return {
        "version": 1,
        "type": "TM",  # Telemetry
        "apid": "SAT-C",
        "sequence": 1,
        "timestamp": timestamp,
        "encrypted_key": encrypted_key,
        "data": encrypted_data,
        "end": "EOF"
    }

# === Sender ===
def sender(public_key):
    message = "CCSDS packet message from Satellite C"
    print("[Sender] Message:", message)

    aes_key = get_random_bytes(16)
    print("[Sender] AES Key:", base64.b64encode(aes_key).decode())

    encrypted_key = encrypt_rsa(public_key, aes_key)
    encrypted_data = encrypt_aes(message, aes_key)

    packet = build_ccsds_packet(encrypted_data, encrypted_key)
    return packet

# === Receiver ===
def receiver(packet, private_key):
    print("\n[Receiver] Received CCSDS Packet:")
    for k, v in packet.items():
        if k != "data" and k != "encrypted_key":
            print(f"  {k}: {v}")

    decrypted_aes_key = decrypt_rsa(private_key, packet["encrypted_key"])
    decrypted_message = decrypt_aes(packet["data"], decrypted_aes_key)

    print("[Receiver] Decrypted AES Key:", base64.b64encode(decrypted_aes_key).decode())
    print("[Receiver] Decrypted Message:", decrypted_message)

# === Main ===
def main():
    print("=== CCSDS Packet Simulation with Encrypted Payload ===")
    priv, pub = generate_rsa_keys()
    packet = sender(pub)
    receiver(packet, priv)

if __name__ == "__main__":
    main()
