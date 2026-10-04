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
import os
import subprocess

HOST = "0.0.0.0"   # listen on all network cards
PORT = 5000

# Error codes we use in EE packets (max 4 allowed)
ERR_BAD_PACKET = "100"   # wrong format / unknown packet / wrong order
ERR_NOT_FOUND = "200"    # file or folder does not exist
ERR_CMD_FAILED = "300"   # command could not be run

# The 5 extra system commands we allow (Linux/Mac name : Windows name)
EXTRA_COMMANDS = {
    "ls": "dir",
    "pwd": "cd",
    "whoami": "whoami",
    "hostname": "hostname",
    "cat": "type",
}

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
        "cwd": os.getcwd(),      # every client has its own folder path
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
# Prompt commands (CM,prompt,...)
# ---------------------------------------------------------------
def full_path(session, name):
    return os.path.join(session["cwd"], name)

def run_prompt(conn, session, command_text):
    parts = command_text.split()
    if len(parts) == 0:
        send_error(conn, ERR_BAD_PACKET, "Empty command")
        return
    cmd = parts[0].lower()
    args = parts[1:]

    try:
        if cmd == "mkdir":
            if len(args) != 1:
                send_error(conn, ERR_BAD_PACKET, "Usage: mkdir folderName")
                return
            os.mkdir(full_path(session, args[0]))
            send_packet(conn, f"(SC,Folder {args[0]} created)")

        elif cmd == "cd":
            if len(args) != 1:
                send_error(conn, ERR_BAD_PACKET, "Usage: cd path")
                return
            new_path = os.path.abspath(full_path(session, args[0]))
            if not os.path.isdir(new_path):
                send_error(conn, ERR_NOT_FOUND, f"Folder {args[0]} not found")
                return
            session["cwd"] = new_path   # only changes for this client
            send_packet(conn, f"(SC,Current folder is {new_path})")

        elif cmd in ("rmdir", "rd"):
            if len(args) != 1:
                send_error(conn, ERR_BAD_PACKET, "Usage: rmdir folderName")
                return
            os.rmdir(full_path(session, args[0]))   # folder must be empty
            send_packet(conn, f"(SC,Folder {args[0]} deleted)")

        elif cmd == "del":
            if len(args) != 1:
                send_error(conn, ERR_BAD_PACKET, "Usage: del fileName")
                return
            path = full_path(session, args[0])
            if not os.path.isfile(path):
                send_error(conn, ERR_NOT_FOUND, f"File {args[0]} not found")
                return
            os.remove(path)
            send_packet(conn, f"(SC,File {args[0]} deleted)")

        elif cmd == "ren":
            if len(args) != 2:
                send_error(conn, ERR_BAD_PACKET, "Usage: ren oldName newName")
                return
            os.rename(full_path(session, args[0]), full_path(session, args[1]))
            send_packet(conn, f"(SC,{args[0]} renamed to {args[1]})")

        elif cmd in EXTRA_COMMANDS:
            # the 5 extra commands are run with subprocess.run
            if os.name == "nt":           # Windows uses different names
                parts[0] = EXTRA_COMMANDS[cmd]
            result = subprocess.run(" ".join(parts), shell=True, cwd=session["cwd"],
                                    capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                send_error(conn, ERR_CMD_FAILED, result.stderr.strip() or "Command failed")
                return
            # output goes in a DP packet, then SC
            send_packet(conn, "(DP," + result.stdout + ")")
            send_packet(conn, f"(SC,{cmd} done)")

        else:
            # we only allow known commands so the client can not run
            # dangerous things like "rm -rf" on the server
            send_error(conn, ERR_CMD_FAILED, f"Command {cmd} is not allowed")

    except FileNotFoundError:
        send_error(conn, ERR_NOT_FOUND, "File or folder not found")
    except FileExistsError:
        send_error(conn, ERR_CMD_FAILED, "Already exists")
    except OSError as e:
        send_error(conn, ERR_CMD_FAILED, str(e).replace(",", " "))
    except subprocess.TimeoutExpired:
        send_error(conn, ERR_CMD_FAILED, "Command took too long")

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

            if body.startswith("CM,"):
                fields = body.split(",", 2)     # CM, command_type, arguments
                if len(fields) != 3:
                    send_error(conn, ERR_BAD_PACKET, "Format is (CM,type,arguments)")
                    continue
                cmd_type = fields[1].strip()
                argument = fields[2].strip()
                if cmd_type == "prompt":
                    run_prompt(conn, session, argument)
                else:
                    send_error(conn, ERR_BAD_PACKET, f"Unknown command type {cmd_type}")

            else:
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
