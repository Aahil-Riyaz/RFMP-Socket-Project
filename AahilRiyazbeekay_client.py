# CSEC-201 Project - RFMP (Remote File Management Protocol)
# Client side
# connects to the server and shows a menu so we can control the server

import socket

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

# setup phase, only non secure for now
def setup(sock):
    send_packet(sock, "(SS,RFMP,v1.0,0)")
    reply = receive_packet(sock)
    if reply != "(CC)":
        print("server did not confirm:", reply)
        sock.close()
        exit()
    print("connected (not secure)")

def main():
    # create a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((SERVER, PORT))
    except:
        print("could not connect to the server, is it running?")
        return

    setup(sock)

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
                text = reply[4:-1]
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
                send_packet(sock, "(DP," + text + ")")
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
