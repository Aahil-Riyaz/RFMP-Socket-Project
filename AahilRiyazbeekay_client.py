# CSEC-201 Project - RFMP (Remote File Management Protocol)
# Client side
# connects to the server and shows a menu so we can control the server

import socket
import base64
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

SERVER = "127.0.0.1"
PORT = 5000

def receive_packet(sock):
    # keep reading until the message ends with )
    data = b""
    while True:
        part = sock.recv(4096)
        if not part:
            break
        data = data + part
        if data.endswith(b")"):
            break
    return data.decode()

def send_packet(sock, packet):
    sock.sendall(packet.encode())

# ### Caesar cipher (same as the server)
def caesar_encrypt(text, shift):
    result = ""
    for ch in text:
        if ch.isupper():
            result = result + chr((ord(ch) - 65 + shift) % 26 + 65)
        elif ch.islower():
            result = result + chr((ord(ch) - 97 + shift) % 26 + 97)
        else:
            result = result + ch
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# ### AES (same as the server)
def aes_encrypt(text, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(text.encode(), 16))
    return base64.b64encode(iv + encrypted).decode()

def aes_decrypt(text, key):
    raw = base64.b64decode(text)
    iv = raw[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(raw[16:]), 16).decode()

def encrypt(text, algorithm, key):
    if algorithm == "AES":
        return aes_encrypt(text, key)
    if algorithm == "CAESAR":
        return caesar_encrypt(text, key)
    return text

def decrypt(text, algorithm, key):
    if algorithm == "AES":
        return aes_decrypt(text, key)
    if algorithm == "CAESAR":
        return caesar_decrypt(text, key)
    return text

# prints what the server answered
# (SC,message) or (EE,code,description)
def show_reply(reply):
    if reply.startswith("(SC"):
        print("[SUCCESS]", reply[4:-1])
    elif reply.startswith("(EE"):
        fields = reply[1:-1].split(",", 2)
        print("[ERROR " + fields[1] + "]", fields[2])
    else:
        print("unknown reply from server:", reply)

# setup phase, returns the algorithm and the session key
# (None, None if not secure)
def setup(sock):
    choice = input("Do you want secure communication? (y/n): ")
    if choice != "y":
        send_packet(sock, "(SS,RFMP,v1.0,0)")
        reply = receive_packet(sock)
        if reply != "(CC)":
            print("server did not confirm:", reply)
            sock.close()
            exit()
        print("connected (not secure)")
        return None, None

    algorithm = ""
    while algorithm != "AES" and algorithm != "CAESAR":
        algorithm = input("Choose algorithm (AES or Caesar): ").upper()
    username = input("Enter username: ")

    # 1. make the session key
    if algorithm == "AES":
        key = get_random_bytes(16)   # 16 bytes = 128 bit key
        session_key = key
    else:
        key = random.randint(1, 25)   # caesar shift
        session_key = str(key).encode()

    # 2. make the client RSA keys
    print("making RSA keys for the client...")
    client_key = RSA.generate(2048)
    client_public_key = base64.b64encode(client_key.publickey().export_key()).decode()

    # 3. start packet, 1 means secure
    send_packet(sock, "(SS,RFMP,v1.0,1)")
    reply = receive_packet(sock)
    if not reply.startswith("(CC,"):
        print("server did not send its public key:", reply)
        sock.close()
        exit()
    server_public_key = RSA.import_key(base64.b64decode(reply[4:-1]))

    # 4. lock the session key with the server public key
    rsa = PKCS1_OAEP.new(server_public_key)
    locked_key = base64.b64encode(rsa.encrypt(session_key)).decode()

    # 5. send the encryption packet
    send_packet(sock, "(EC," + algorithm + "," + locked_key + "," + username + ":" + client_public_key + ")")
    reply = receive_packet(sock)
    show_reply(reply)
    if not reply.startswith("(SC"):
        sock.close()
        exit()
    return algorithm, key

def main():
    # create a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((SERVER, PORT))
    except:
        print("could not connect to the server, is it running?")
        return

    algorithm, key = setup(sock)

    while True:
        print()
        print("======= RFMP MENU =======")
        print("1. mkdir (make folder)")
        print("2. cd (change folder)")
        print("3. rmdir (delete folder)")
        print("4. del (delete file)")
        print("5. ren (rename)")
        print("6. openRead (read a file)")
        print("7. openWrite (write a new file)")
        print("8. other commands (ls, pwd, whoami, hostname, cat)")
        print("9. exit")
        choice = input("choose: ")

        if choice == "1":
            name = input("folder name: ")
            send_packet(sock, "(CM,prompt,mkdir " + name + ")")
            show_reply(receive_packet(sock))

        elif choice == "2":
            path = input("path: ")
            send_packet(sock, "(CM,prompt,cd " + path + ")")
            show_reply(receive_packet(sock))

        elif choice == "3":
            name = input("folder name: ")
            send_packet(sock, "(CM,prompt,rmdir " + name + ")")
            show_reply(receive_packet(sock))

        elif choice == "4":
            name = input("file name: ")
            send_packet(sock, "(CM,prompt,del " + name + ")")
            show_reply(receive_packet(sock))

        elif choice == "5":
            old = input("old name: ")
            new = input("new name: ")
            send_packet(sock, "(CM,prompt,ren " + old + " " + new + ")")
            show_reply(receive_packet(sock))

        elif choice == "6":
            name = input("file to read: ")
            send_packet(sock, "(CM,openRead," + name + ")")
            reply = receive_packet(sock)
            if reply.startswith("(SC"):
                # file text comes encrypted if we are secure
                text = decrypt(reply[4:-1], algorithm, key)
                print("------ " + name + " ------")
                print(text)
                print("-------------------")
            else:
                show_reply(reply)

        elif choice == "7":
            name = input("file to create: ")
            send_packet(sock, "(CM,openWrite," + name + ")")
            reply = receive_packet(sock)
            show_reply(reply)
            if reply.startswith("(SC"):
                print("type your text, type END on a new line to stop")
                text = ""
                line = input()
                while line != "END":
                    text = text + line + "\n"
                    line = input()
                # encrypt before sending if secure
                send_packet(sock, "(DP," + encrypt(text, algorithm, key) + ")")
                show_reply(receive_packet(sock))

        elif choice == "8":
            cmd = input("command (ls, pwd, whoami, hostname, cat filename): ")
            send_packet(sock, "(CM,prompt," + cmd + ")")
            show_reply(receive_packet(sock))

        elif choice == "9":
            # closing phase
            send_packet(sock, "(END)")
            show_reply(receive_packet(sock))
            break

        else:
            print("wrong choice try again")

    sock.close()

if __name__ == '__main__':
    main()
