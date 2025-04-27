from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Helper: Pad message to fit AES block size (16 bytes)
def pad_message(message):
    while len(message) % 16 != 0:
        message += ' '
    return message

# Step 1: Encrypt the message using AES
def encrypt_message_aes(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad_message(plaintext)
    ciphertext = cipher.encrypt(padded_text.encode())
    encoded_ciphertext = base64.b64encode(ciphertext).decode()  # make it readable
    return encoded_ciphertext

# Step 2: Decrypt the message
def decrypt_message_aes(encoded_ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = base64.b64decode(encoded_ciphertext)
    decrypted = cipher.decrypt(ciphertext).decode().strip()
    return decrypted

# Step 3: Simulate sender
def sender_aes():
    message = "Hello from Satellite A!"
    print("[Sender] Original Message:", message)

    key = get_random_bytes(16)  # AES key must be 16, 24, or 32 bytes
    print("[Sender] Secret Key (shared):", base64.b64encode(key).decode())

    encrypted_msg = encrypt_message_aes(message, key)
    print("[Sender] Encrypted Message:", encrypted_msg)

    packet = {
        "header": "SAT-A",
        "data": encrypted_msg,
        "footer": "END"
    }

    return packet, key

# Step 4: Simulate receiver
def receiver_aes(packet, key):
    print("\n[Receiver] Packet Received:", packet)

    encrypted_msg = packet["data"]
    decrypted_msg = decrypt_message_aes(encrypted_msg, key)
    print("[Receiver] Decrypted Message:", decrypted_msg)

# Step 5: Main function
def main():
    print("=== AES Encrypted Communication Simulation ===")
    packet, shared_key = sender_aes()
    receiver_aes(packet, shared_key)

# Run it!
if __name__ == "__main__":
    main()
