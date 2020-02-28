import sys
import socket

if(len(sys.argv) < 2):
    exit(1)

if(int(sys.argv[1]) < 0 or int(sys.argv[1]) > 65535):
    exit(1)

PORT = int(sys.argv[1]) 
HOST = '127.0.0.1'

#create and bind the socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(0)

msg = "here you go\r\n"
while True:
    conn, addr = s.accept()
    data = conn.recv(4096)
    print(data)
    if not data:
        conn.close()
    if(conn.sendall(msg.encode()) == None):
        conn.close()

s.close()
