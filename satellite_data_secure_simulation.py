import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64
import matplotlib.pyplot as plt

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

# Draw message flow diagram
def draw_message_flow():
    steps = [
        "Message Created\n(Satellite C)",
        "Encrypt Message\n(AES)",
        "Encrypt AES Key\n(RSA)",
        "Send Packet\n(CCSDS Format)",
        "Decrypt AES Key\n(RSA)",
        "Decrypt Message\n(AES)"
    ]

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.set_xlim(0, len(steps) + 1)
    ax.set_ylim(0, 2)

    # Hide axes
    ax.axis('off')

    # Draw steps with arrows
    for i, step in enumerate(steps):
        x = i + 1
        ax.text(x, 1.5, step, ha='center', va='center', fontsize=11, bbox=dict(boxstyle="round", facecolor="#E0F7FA", edgecolor="gray"))
        if i < len(steps) - 1:
            ax.annotate("",
                        xy=(x + 0.5, 1.5), xycoords='data',
                        xytext=(x + 0.1, 1.5), textcoords='data',
                        arrowprops=dict(arrowstyle="->", lw=1.5, color="gray"))

    ax.set_title("🔐 Satellite Secure Communication Flow", fontsize=14, pad=20)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    draw_message_flow()

# Simulate each step and record timestamp
def simulate_steps_with_timing():
    steps = [
        "Message Created",
        "AES Encryption",
        "RSA Key Encryption",
        "Packet Sent",
        "RSA Key Decryption",
        "AES Decryption"
    ]

    timestamps = []

    for step in steps:
        print(f"🟢 Step: {step}")
        now = time.time()
        timestamps.append((step, now))
        time.sleep(0.5)  # simulate 0.5 seconds delay (you can change this)

    return timestamps

# Visualize the delays
def visualize_timeline(timestamps):
    step_names = [s[0] for s in timestamps]
    start_times = [s[1] - timestamps[0][1] for s in timestamps]  # offset from first
    durations = [0.4 for _ in step_names]  # fixed durations for demo

    fig, ax = plt.subplots(figsize=(10, 4))

    ax.barh(step_names, durations, left=start_times, height=0.5, color="#4FC3F7")
    for i, (start, duration) in enumerate(zip(start_times, durations)):
        ax.text(start + duration + 0.05, i, f"{start:.2f}s", va='center', fontsize=9)

    ax.set_xlabel("Time (s)")
    ax.set_title("⏱️ Message Flow Timeline with Delays")
    ax.grid(True, axis='x', linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.show()

# === Main ===
if __name__ == "__main__":
    timestamps = simulate_steps_with_timing()
    visualize_timeline(timestamps)
