# RFMP - Remote File Management Protocol

CSEC-201 Programming for Information Security - Group Project

We are building a simple remote file management protocol using sockets in Python and C.
The client sends commands and the server runs them (kind of like a very small SSH).

## Team
- Aahil Riyaz Beekay (Team Leader)
- Zoheb Bamban
- Saquib Gudme
- Anay Nayak

## Files
- AahilRiyazbeekay_server.py - python server (multithreaded)
- AahilRiyazbeekay_client.py - python client with a menu
- AahilRiyazbeekay_client.c - C client (not secure, only openRead)
- sample.txt - test file for openRead

## How to run
First install the library for encryption:
```
pip install pycryptodome
```
Then open 2 terminals:
```
python AahilRiyazbeekay_server.py
python AahilRiyazbeekay_client.py
```
C client on windows:
```
gcc AahilRiyazbeekay_client.c -o client_c.exe -lws2_32
client_c.exe
```

## Packets
- (SS,RFMP,v1.0,0) or (SS,RFMP,v1.0,1) - start, 1 means secure
- (CC) or (CC,Server_public_key) - server confirms
- (EC,Algorithm,session_key,username:Client_public_key) - encryption info
- (CM,prompt,command) / (CM,openRead,file) / (CM,openWrite,file) - commands
- (DP,text) - data to write in the file
- (SC,message) - success
- (EE,code,description) - error
- (END) - close

## Error codes
- 100 bad packet
- 200 file or folder not found
- 300 command failed / not allowed
- 400 encryption error

## Commands
mkdir, cd, rmdir (rd), del, ren, openRead, openWrite
and our 5 extra commands: ls, pwd, whoami, hostname, cat
