##########################
# Name: Marek Sarvas     #
# Login: xsarva00        #
# School: VUT FIT 2BIT   #
# Subject: IPK           #
##########################
import sys
import socket
import re

def handleGET(recv_list):
    request_head = recv_list[1].split("\r\n")[0]
    if(re.fullmatch(r"\/resolve\?name=.*&type=(A|PTR) HTTP\/1\.1", request_head) != None):
        #split the name(url or ip addr) from request
        name = request_head.split("name=")[1]
        name = name.split("&")[0]
        #split the type(A or PTR) from request
        request_type = request_head.split("type=")[1]
        request_type = request_type.split(" ")[0]

        return resolveRequest(request_type, name)
    else:
        return b"HTTP/1.1 405 Method Not Allowed\r\n\r\n"

def handlePOST():
    print("POST")
    return b"default post\r\n"

def resolveRequest(req_type, req_name):
    if(req_type == "A"):
        try:
            ip = socket.gethostbyname(req_name)
            #if ip address is in GET request and type is A response error
            if(ip == req_name):
                return b"HTTP/1.1 400 Bad Request\r\n\r\n"
            #otherwise
            response = "HTTP/1.1 200 Ok\r\n\r\n"+req_name+":"+req_type+"="+ip+"\r\n"
            return response.encode()
        except socket.gaierror:
            return b"HTTP/1.1 400 Bad Request\r\n\r\n"

    elif(req_type == "PTR"):
        try:
            url = socket.gethostbyaddr(req_name)
            response = "HTTP/1.1 200 Ok\r\n\r\n"+req_name+":"+req_type+"="+url[0]+"\r\n"#url si tuple and url address is on index 0
            return response.encode()

        except socket.gaierror:
            return b"HTTP/1.1 400 Bad Request\r\n\r\n"
    else:
        return b"HTTP/1.1 400 Bad Request\r\n\r\n"

#argument handling
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
