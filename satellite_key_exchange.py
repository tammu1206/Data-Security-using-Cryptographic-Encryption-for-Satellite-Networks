
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64

# === AES Helper Functions ===

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

# === RSA Helper Functions ===

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_rsa(public_key, message_bytes):
    encrypted = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def decrypt_rsa(private_key, encoded_encrypted_data):
    encrypted_data = base64.b64decode(encoded_encrypted_data)
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

# === Sender Function ===
def sender(public_rsa_key):
    message = "Top secret data from Satellite C"
    print("[Sender] Message to send:", message)

    # 1. Create AES key
    aes_key = get_random_bytes(16)
    print("[Sender] Generated AES Key:", base64.b64encode(aes_key).decode())

    # 2. Encrypt AES key with receiver's public RSA key
    encrypted_key = encrypt_rsa(public_rsa_key, aes_key)
    print("[Sender] AES Key Encrypted with RSA:", encrypted_key)

    # 3. Encrypt message with AES key
    encrypted_message = encrypt_aes(message, aes_key)
    print("[Sender] Message Encrypted with AES:", encrypted_message)

    # Simulate packet sent
    return {
        "encrypted_key": encrypted_key,
        "encrypted_message": encrypted_message
    }

# === Receiver Function ===
def receiver(packet, private_rsa_key):
    print("\n[Receiver] Received Packet:", packet)

    # 1. Decrypt AES key using private RSA key
    decrypted_aes_key = decrypt_rsa(private_rsa_key, packet["encrypted_key"])
    print("[Receiver] Decrypted AES Key:", base64.b64encode(decrypted_aes_key).decode())

    # 2. Decrypt message using AES key
    decrypted_message = decrypt_aes(packet["encrypted_message"], decrypted_aes_key)
    print("[Receiver] Decrypted Message:", decrypted_message)

# === Main ===
def main():
    print("=== RSA Key Exchange + AES Encryption Simulation ===")

    # Receiver generates RSA key pair
    private_key, public_key = generate_rsa_keys()

    # Sender encrypts AES key and message
    packet = sender(public_key)

    # Receiver decrypts both
    receiver(packet, private_key)

# Run it
if __name__ == "__main__":
    main()
