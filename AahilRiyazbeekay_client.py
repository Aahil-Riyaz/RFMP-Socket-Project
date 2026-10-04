# CSEC-201 Project - Remote File Management Protocol (RFMP)
# Python Client
#
# The client connects to the server, does the setup phase, and then
# shows a menu so the user can control the server remotely.

import socket
import struct
SERVER_IP = "127.0.0.1"
PORT = 5000

# ---------------------------------------------------------------
# Sending and receiving packets (4 byte length + packet text)
# ---------------------------------------------------------------
def send_packet(sock, text):
    data = text.encode()
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
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
    packet = packet.strip()
    if packet.startswith("(") and packet.endswith(")"):
        packet = packet[1:-1]
    return packet

# ---------------------------------------------------------------
# Reading server answers
# ---------------------------------------------------------------
def show_response(sock, session):
    # Reads packets until we get SC or EE.
    # DP packets (file contents / command output) are printed first.
    while True:
        packet = recv_packet(sock)
        if packet is None:
            print("Server closed the connection")
            return False
        body = strip_brackets(packet)

        if body.startswith("DP,"):
            text = body[3:]
            print("----- data from server -----")
            print(text)
            print("----------------------------")

        elif body.startswith("SC"):
            message = body[3:] if len(body) > 3 else ""
            print("[SUCCESS]", message)
            return True

        elif body.startswith("EE"):
            # (EE, Error Code, Description)
            fields = body.split(",", 2)
            code = fields[1] if len(fields) > 1 else "?"
            desc = fields[2] if len(fields) > 2 else ""
            print(f"[ERROR {code}] {desc}")
            return False

        else:
            print("Unknown packet from server:", packet)
            return False

# ---------------------------------------------------------------
# Setup phase
# ---------------------------------------------------------------
def setup_phase(sock):
    session = {"secure": False, "algorithm": None, "key": None}

    # only non-secure mode for now (secure = 0)
    send_packet(sock, "(SS,RFMP,v1.0,0)")
    reply = strip_brackets(recv_packet(sock))
    if reply != "CC":
        print("Server did not confirm:", reply)
        return None
    print("Connected (not secure)")
    return session

# ---------------------------------------------------------------
# Menu
# ---------------------------------------------------------------
def print_menu():
    print()
    print("========= RFMP MENU =========")
    print("9. Exit")

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((SERVER_IP, PORT))
    except ConnectionRefusedError:
        print("Can not connect to server. Is it running?")
        return

    session = setup_phase(sock)
    if session is None:
        sock.close()
        return
    
    while True:
        print_menu()
        choice = input("Choose option: ").strip()

        if choice == "9":
            # closing phase
            send_packet(sock, "(END)")
            show_response(sock, session)
            break
        else:
            print("Wrong option, try again")
            continue

        show_response(sock, session)

    sock.close()
    print("Disconnected.")

if __name__ == "__main__":
    main()
