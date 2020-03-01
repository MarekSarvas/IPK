import sys
import socket
import re


def handleGET(recv_list):
  #  print("|"+recv_list[1].split("\r\n")[0]+"|")
    request_head = recv_list[1].split("\r\n")[0]
    if(re.fullmatch(r"\/resolve\?name=.*&type=(A|PTR) HTTP\/1\.1", request_head) != None):
        name = request_head.split("name=")[1]
        name = name.split("&")[0]

        request_type = request_head.split("type=")[1]
        request_type = request_type.split(" ")[0]

       # print("|"+name+request_type+"|")

        return resolveRequest(request_type, name)
    else:
        return b"HTTP/1.1 405 Method Not Allowed\r\n\r\n"

def handlePOST():
    print("POST")
    return b"default post\r\n"

def resolveRequest(req_type, req_name):
    if(req_type == "A"):
        
        return b"HTTP/1.1 200 Ok\r\n\r\n"
    elif(req_type == "PTR"):
        return b"HTTP/1.1 200 Ok\r\n\r\n"
    else:
        return b"HTTP/1.1 400 Bad Request\r\n\r\n"

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
    try:
        #accepts port
        client, addr = s.accept()
        #receives data
        data = client.recv(4096)
        #parse to get method
        list_data = data.decode().split(" ", 1)
        #handle method
        if(list_data[0] == "GET"):
    
            send_msg = handleGET(list_data)
        elif(list_data[0] == "POST"):
            send_msg = handlePOST()
        else:
            if(client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n") == None):
                client.close()

        #if not data:
        #   client.close()

        #send message
        if(client.sendall(send_msg) == None):
            client.close()
    except KeyboardInterrupt:
        s.close()
        sys.exit(0)
