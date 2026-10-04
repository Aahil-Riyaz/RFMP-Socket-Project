# CSEC-201 Project - RFMP (Remote File Management Protocol)
# Server side
# the server waits for clients and runs the commands they send
# every client gets its own thread so more than one can connect

import socket
import threading
import os
import subprocess

HOST = "0.0.0.0"
PORT = 5000

# our error codes for EE packets
# 100 = bad packet
# 200 = file or folder not found
# 300 = command failed / not allowed

# the 5 extra commands we picked and their names on windows
extra_commands = {"ls": "dir", "pwd": "cd", "whoami": "whoami", "hostname": "hostname", "cat": "type"}

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
            # TODO secure mode
            send_error(conn, "100", "secure mode is not done yet")
            return
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
                else:
                    send_error(conn, "100", "unknown command type")

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
