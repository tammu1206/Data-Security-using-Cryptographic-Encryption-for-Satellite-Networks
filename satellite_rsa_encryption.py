from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

# Step 1: Generate RSA key pair
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Step 2: Encrypt using public key
def encrypt_with_rsa(public_key, message):
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

# Step 3: Decrypt using private key
def decrypt_with_rsa(private_key, encrypted_message):
    decoded = base64.b64decode(encrypted_message)
    decrypted = private_key.decrypt(
        decoded,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# Step 4: Sender encrypts message with Receiver's public key
def sender_rsa(public_key):
    message = "Hello from Satellite B!"
    print("[Sender] Original Message:", message)

    encrypted = encrypt_with_rsa(public_key, message)
    print("[Sender] Encrypted Message (RSA):", encrypted)

    packet = {
        "header": "SAT-B",
        "data": encrypted,
        "footer": "END"
    }

    return packet

# Step 5: Receiver decrypts with private key
def receiver_rsa(packet, private_key):
    print("\n[Receiver] Packet Received:", packet)
    encrypted = packet["data"]
    decrypted = decrypt_with_rsa(private_key, encrypted)
    print("[Receiver] Decrypted Message:", decrypted)

# Step 6: Main function
def main():
    print("=== RSA Encrypted Communication Simulation ===")
    
    private_key, public_key = generate_rsa_keys()

    packet = sender_rsa(public_key)
    receiver_rsa(packet, private_key)

# Run it
if __name__ == "__main__":
    main()
