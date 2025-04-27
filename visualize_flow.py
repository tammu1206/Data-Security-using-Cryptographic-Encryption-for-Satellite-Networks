import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

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
