import time
import matplotlib.pyplot as plt

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
