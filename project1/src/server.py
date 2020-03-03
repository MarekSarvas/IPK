##########################
# Name: Marek Sarvas     #
# Login: xsarva00        #
# School: VUT FIT 2BIT   #
# Subject: IPK           #
##########################
import sys
import socket
import re
import ipaddress

def handleGET(recv_list):
    request_head = recv_list[1].split("\r\n")[0]
    if(re.fullmatch(r"\/resolve\?name=.*&type=(A|PTR) HTTP\/1\.1", request_head) != None):
        #split the name(url or ip addr) from request
        name = request_head.split("name=")[1]
        name = name.split("&")[0]
        #split the type(A or PTR) from request
        request_type = request_head.split("type=")[1]
        request_type = request_type.split(" ")[0]

        resolved = resolveRequest(request_type, name)
        if resolved == False:
            return b"HTTP/1.1 404 Not Found\n\n"
        else:
            return ("HTTP/1.1 200 Ok\n\n"+name+":"+request_type+"="+resolved+"\n").encode()

    else:
        return b"HTTP/1.1 404 Bad Request\n\n"

def handlePOST(recv_list):
    req_header = recv_list.split("\r\n")[0]
    if re.fullmatch(r"\/dns-query HTTP\/1\.1",req_header) != None:
        response_content = ""
        content = recv_list.split("\r\n\r\n",1)[1] # get rid of header
        content = content.split("\n")

        #go through POST content
        for req in content:
            if re.fullmatch(r".*:(A|PTR)", req) != None:
                resolved = resolveRequest(req.split(":")[1], req.split(":")[0])
                if resolved == False:
                    continue
                else:
                    response_content += req+"="+resolved+"\n"
            else:
                continue
        #response
        if response_content == "":
            return b"HTTP/1.1 404 Not Found\n\n"
        else:
            return ("HTTP/1.1 200 Ok\n\n"+response_content).encode()
    else:
        return b"HTTP/1.1 400 Bad Request\n\n"

def resolveRequest(req_type, req_name):
    if(req_type == "A"):
        try:
            ip = socket.gethostbyname(req_name)
            #if ip address is in GET request and type is A response error
            if(ip == req_name):
                return False
            #otherwise
            #response = "HTTP/1.1 200 Ok\r\n\r\n"+req_name+":"+req_type+"="+ip+"\r\n"
            return ip
        except (socket.gaierror, socket.herror):
            return False

    elif(req_type == "PTR"):
        try:
            #check if recieved name is valid ip address 
            ipaddress.ip_address(req_name)

            url = socket.gethostbyaddr(req_name)
            return url[0]
        except (socket.gaierror, socket.herror, ValueError):
            #return b"HTTP/1.1 400 Bad Request\r\n\r\n"
            return False
    else:
        return False

#argument handling
if len(sys.argv) < 2 or len(sys.argv) > 2:
    exit(70)

#if(int(sys.argv[1]) < 0 or int(sys.argv[1]) > 65535):
if not 0 <= int(sys.argv[1]) < 65536:
    sys.exit(70)

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
        data = client.recv(1024)

        data_len = int(data.decode().split("Content-Length: ")[1].split("\n")[0])
        print(data_len)
        while data_len > 1024:
            data +=client.recv(1024)
            data_len -= 1024 
        data +=client.recv(1024)
    
        #parse to get method
        list_data = data.decode().split(" ", 1)
        #handle method
        if(list_data[0] == "GET"):
            send_msg = handleGET(list_data)
        elif(list_data[0] == "POST"):
            send_msg = handlePOST(list_data[1])
        else:
            if(client.sendall(b"HTTP/1.1 405 Method Not Allowed\n\n") == None):
                client.close()

        #if not data:
        #   client.close()

        #send message
        if(client.sendall(send_msg) == None):
            client.close()
    except KeyboardInterrupt:
        s.close()
        sys.exit(0)