# CSEC-201 Project - RFMP (Remote File Management Protocol)
# Server side
# the server waits for clients and runs the commands they send
# every client gets its own thread so more than one can connect

import socket
import threading
import os
import subprocess
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

HOST = "0.0.0.0"
PORT = 5000

# our error codes for EE packets
# 100 = bad packet
# 200 = file or folder not found
# 300 = command failed / not allowed
# 400 = encryption error

# the 5 extra commands we picked and their names on windows
extra_commands = {"ls": "dir", "pwd": "cd", "whoami": "whoami", "hostname": "hostname", "cat": "type"}

# server makes its RSA keys one time when it starts
print("making RSA keys for the server...")
server_key = RSA.generate(2048)
# base64 so the key is one line with no commas inside the packet
server_public_key = base64.b64encode(server_key.publickey().export_key()).decode()

def receive_packet(conn):
    # TCP can split a big message into parts
    # so we keep reading until the message ends with )
    data = b""
    while True:
        part = conn.recv(4096)
        if not part:
            break
        data = data + part
        if data.endswith(b")"):
            break
    return data.decode()

def send_packet(conn, packet):
    conn.sendall(packet.encode())

def send_error(conn, code, msg):
    send_packet(conn, "(EE," + code + "," + msg + ")")

# ### Caesar cipher
def caesar_encrypt(text, shift):
    result = ""
    for ch in text:
        if ch.isupper():
            result = result + chr((ord(ch) - 65 + shift) % 26 + 65)
        elif ch.islower():
            result = result + chr((ord(ch) - 97 + shift) % 26 + 97)
        else:
            result = result + ch   # numbers and symbols stay the same
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# algorithm is None when the client did not ask for security
def encrypt(text, algorithm, key):
    if algorithm == "CAESAR":
        return caesar_encrypt(text, key)
    return text

def decrypt(text, algorithm, key):
    if algorithm == "CAESAR":
        return caesar_decrypt(text, key)
    return text

# runs the prompt commands, returns the folder the client is in
# (it only changes when the command is cd)
def run_command(conn, command, cwd):
    parts = command.split()
    if len(parts) == 0:
        send_error(conn, "100", "empty command")
        return cwd
    cmd = parts[0]

    try:
        if cmd == "mkdir":
            os.mkdir(os.path.join(cwd, parts[1]))
            send_packet(conn, "(SC,folder " + parts[1] + " created)")

        elif cmd == "cd":
            new_path = os.path.abspath(os.path.join(cwd, parts[1]))
            if os.path.isdir(new_path):
                cwd = new_path
                send_packet(conn, "(SC,now in " + cwd + ")")
            else:
                send_error(conn, "200", "folder not found")

        elif cmd == "rmdir" or cmd == "rd":
            os.rmdir(os.path.join(cwd, parts[1]))   # folder has to be empty
            send_packet(conn, "(SC,folder " + parts[1] + " deleted)")

        elif cmd == "del":
            path = os.path.join(cwd, parts[1])
            if os.path.isfile(path):
                os.remove(path)
                send_packet(conn, "(SC,file " + parts[1] + " deleted)")
            else:
                send_error(conn, "200", "file not found")

        elif cmd == "ren":
            os.rename(os.path.join(cwd, parts[1]), os.path.join(cwd, parts[2]))
            send_packet(conn, "(SC," + parts[1] + " renamed to " + parts[2] + ")")

        elif cmd in extra_commands:
            if os.name == "nt":   # windows uses different names
                parts[0] = extra_commands[cmd]
            result = subprocess.run(" ".join(parts), shell=True, cwd=cwd, capture_output=True, text=True)
            if result.returncode == 0:
                send_packet(conn, "(SC," + result.stdout + ")")
            else:
                send_error(conn, "300", "command failed")

        else:
            # we only allow our commands so nobody can run dangerous stuff on the server
            send_error(conn, "300", "command not allowed")

    except IndexError:
        send_error(conn, "100", "missing name after the command")
    except FileNotFoundError:
        send_error(conn, "200", "file or folder not found")
    except FileExistsError:
        send_error(conn, "300", "already exists")
    except OSError:
        send_error(conn, "300", "command failed")

    return cwd

# each client runs this function in its own thread
def handle_client(conn, addr):
    print("got a connection from", addr)
    cwd = os.getcwd()      # every client has its own folder
    write_file = None      # the file opened with openWrite
    algorithm = None       # stays None if not secure
    key = None

    try:
        # ### setup phase
        packet = receive_packet(conn)
        print(addr, "sent", packet)
        fields = packet[1:-1].split(",")
        # start packet should look like (SS,RFMP,v1.0,0) or (SS,RFMP,v1.0,1)
        if len(fields) != 4 or fields[0] != "SS" or fields[1] != "RFMP":
            send_error(conn, "100", "expected start packet")
            return

        if fields[3] == "0":
            send_packet(conn, "(CC)")
            print(addr, "not secure")
        elif fields[3] == "1":
            # send our public key, then the client sends the EC packet
            send_packet(conn, "(CC," + server_public_key + ")")
            packet = receive_packet(conn)
            # (EC,Algorithm,session_key,username:client_public_key)
            fields = packet[1:-1].split(",")
            if len(fields) != 4 or fields[0] != "EC":
                send_error(conn, "100", "expected encryption packet")
                return

            algorithm = fields[1].upper()
            if algorithm != "CAESAR":
                send_error(conn, "400", "only caesar works for now")
                return

            try:
                # unlock the session key with our private key
                rsa = PKCS1_OAEP.new(server_key)
                session_key = rsa.decrypt(base64.b64decode(fields[2]))
                username = fields[3].split(":")[0]
                client_public_key = fields[3].split(":")[1]
            except:
                send_error(conn, "400", "could not decrypt the session key")
                return

            key = int(session_key.decode())   # caesar shift number
            print(addr, "secure, user:", username, "algorithm:", algorithm)
            print(addr, "client public key:", client_public_key[:40] + "...")
            send_packet(conn, "(SC,secure connection ready)")
        else:
            send_error(conn, "100", "last field must be 0 or 1")
            return

        # ### operation phase
        while True:
            packet = receive_packet(conn)
            if packet == "":
                print(addr, "disconnected")
                break
            print(addr, "sent", packet[:60])

            if packet == "(END)":
                # ### closing phase
                send_packet(conn, "(SC,goodbye)")
                print(addr, "closed the connection")
                break

            elif packet.startswith("(CM,"):
                # (CM,command_type,arguments)
                fields = packet[1:-1].split(",", 2)
                if len(fields) != 3:
                    send_error(conn, "100", "bad command packet")
                elif fields[1] == "prompt":
                    cwd = run_command(conn, fields[2], cwd)
                elif fields[1] == "openRead":
                    path = os.path.join(cwd, fields[2])
                    if os.path.isfile(path):
                        f = open(path, "r")
                        content = f.read()
                        f.close()
                        # encrypt the file text before sending if secure
                        send_packet(conn, "(SC," + encrypt(content, algorithm, key) + ")")
                    else:
                        send_error(conn, "200", "file not found")
                elif fields[1] == "openWrite":
                    try:
                        write_file = os.path.join(cwd, fields[2])
                        f = open(write_file, "w")   # makes a new empty file
                        f.close()
                        send_packet(conn, "(SC,file created now send the data)")
                    except OSError:
                        write_file = None
                        send_error(conn, "300", "could not create the file")
                else:
                    send_error(conn, "100", "unknown command type")

            elif packet.startswith("(DP,"):
                if write_file is None:
                    send_error(conn, "100", "use openWrite first")
                    continue
                try:
                    text = decrypt(packet[4:-1], algorithm, key)
                except:
                    send_error(conn, "400", "could not decrypt the data")
                    continue
                f = open(write_file, "a")
                f.write(text)
                f.close()
                send_packet(conn, "(SC,data saved)")

            else:
                send_error(conn, "100", "unknown packet")

    except ConnectionResetError:
        print(addr, "connection lost")
    finally:
        conn.close()

def main():
    # create a TCP socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # so we can restart the server right away without "address already in use"
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # bind the socket to the port
    server.bind((HOST, PORT))
    # queue up to 5 requests
    server.listen(5)
    print('starting up on {} port {}'.format(HOST, PORT))

    while True:
        conn, addr = server.accept()
        # new thread for every client
        thread_obj = threading.Thread(target=handle_client, args=(conn, addr))
        thread_obj.start()
        print("Total number of threads", threading.active_count())

if __name__ == '__main__':
    main()
