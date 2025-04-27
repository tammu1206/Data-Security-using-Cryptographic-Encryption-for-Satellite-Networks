# Step 1: Define the sender function
def sender():
    message = "Hello from Satellite A!"  # Plain text message
    print("[Sender] Original Message:", message)
    
    # Create a data packet (in this simple example, it's just a dictionary)
    packet = {
        "header": "SAT-A",  # This is like a label showing who sent it
        "data": message,
        "footer": "END"
    }

    print("[Sender] Packet Sent:", packet)
    return packet

# Step 2: Define the receiver function
def receiver(packet):
    print("\n[Receiver] Packet Received:", packet)

    # Extract the data
    received_message = packet["data"]
    print("[Receiver] Message Extracted:", received_message)

# Step 3: Main function to simulate the communication
def main():
    print("=== Simulating Basic Satellite Communication ===")
    packet = sender()         # Sender sends the packet
    receiver(packet)          # Receiver receives and processes it

# Run the program
if __name__ == "__main__":
    main()
