# CSEC-201 Project - Remote File Management Protocol (RFMP)
# Python Server
#
# The server waits for clients, does the setup phase (SS -> CC -> EC),
# then runs the commands the client sends (CM packets) and answers
# every command with SC (success) or EE (error).
# Each client gets its own thread so many clients can connect at once.

import socket
import threading
import struct

HOST = "0.0.0.0"   # listen on all network cards
PORT = 5000
# Error codes we use in EE packets (max 4 allowed)
ERR_BAD_PACKET = "100"   # wrong format / unknown packet / wrong order

# ---------------------------------------------------------------
# Sending and receiving packets
# TCP is a stream so we put a 4 byte length in front of every
# packet. This way the other side knows exactly how much to read.
# ---------------------------------------------------------------
def send_packet(sock, text):
    data = text.encode()
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:          # client closed the connection
            return None
        data += chunk
    return data

def recv_packet(sock):
    header = recv_exact(sock, 4)
    if header is None:
        return None
    length = struct.unpack("!I", header)[0]
    data = recv_exact(sock, length)
    if data is None:
        return None
    return data.decode()

def strip_brackets(packet):
    # "(CM,prompt,ls)" -> "CM,prompt,ls"
    packet = packet.strip()
    if packet.startswith("(") and packet.endswith(")"):
        packet = packet[1:-1]
    return packet

def send_error(sock, code, description):
    send_packet(sock, f"(EE,{code},{description})")

# ---------------------------------------------------------------
# Setup phase: SS -> CC   (secure mode will be added later)
# returns the session dictionary or None if something went wrong
# ---------------------------------------------------------------
def setup_phase(conn, addr):
    session = {
        "secure": False,
    }

    packet = recv_packet(conn)
    if packet is None:
        return None
    print(f"[{addr}] received: {packet}")
    fields = [f.strip() for f in strip_brackets(packet).split(",")]

    # Start packet must be (SS,RFMP,v1.0,0 or 1)
    if len(fields) != 4 or fields[0] != "SS" or fields[1] != "RFMP":
        send_error(conn, ERR_BAD_PACKET, "Expected start packet (SS,RFMP,version,0/1)")
        return None
    if fields[3] not in ("0", "1"):
        send_error(conn, ERR_BAD_PACKET, "Secure field must be 0 or 1")
        return None

    if fields[3] == "0":
        # no security, CC has only one field
        send_packet(conn, "(CC)")
        print(f"[{addr}] non-secure session started")
        return session

    # TODO: secure mode (RSA + encryption) not done yet
    send_error(conn, ERR_BAD_PACKET, "Secure mode is not supported yet")
    return None

# ---------------------------------------------------------------
# One thread runs this function for every client
# ---------------------------------------------------------------
def handle_client(conn, addr):
    print(f"[+] New client {addr}")
    try:
        session = setup_phase(conn, addr)
        if session is None:
            return

        # Operation phase
        while True:
            packet = recv_packet(conn)
            if packet is None:
                print(f"[{addr}] disconnected")
                break
            print(f"[{addr}] received: {packet[:80]}")
            body = strip_brackets(packet)

            if body == "END":
                # Closing phase
                send_packet(conn, "(SC,Goodbye)")
                print(f"[{addr}] closed the session")
                break

            send_error(conn, ERR_BAD_PACKET, "Unknown packet type")

    except (ConnectionResetError, BrokenPipeError):
        print(f"[{addr}] connection lost")
    finally:
        conn.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] RFMP server listening on port {PORT}")

    while True:
        conn, addr = server.accept()
        # new thread for each client (multithreaded server)
        t = threading.Thread(target=handle_client, args=(conn, addr))
        t.daemon = True
        t.start()
        print(f"[*] Active clients: {threading.active_count() - 1}")


if __name__ == "__main__":
    main()
