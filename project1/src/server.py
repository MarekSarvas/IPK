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
    request_head = recv_list[1]. split("\r\n\r\n")[0]
    if(re.fullmatch(r"\/resolve\?name=.*&type=(A|PTR) HTTP\/1\.1", request_head) != None):
        # split the name(url or ip addr) from request
        name = request_head.split("name=")[1]
        name = name.split("&")[0]
        # split the type(A or PTR) from request
        request_type = request_head.split("type=")[1]
        request_type = request_type.split(" ")[0]

        resolved = resolveRequest(request_type, name)
        if resolved == 400:
            return b"HTTP/1.1 400 Bad Request\n\n"
        elif resolved == 404:
            return b"HTTP/1.1 404 Not Found\n\n"
        else:
            return ("HTTP/1.1 200 Ok\n\n"+name+":"+request_type+"="+resolved+"\n").encode()

    else:
        return b"HTTP/1.1 404 Bad Request\n\n"

def handlePOST(recv_list):
    req_header = recv_list.split("\r\n")[0]
    
    if re.fullmatch(r"\/dns-query HTTP\/1\.1",req_header) != None:
        response_err = b"HTTP/1.1 404 Not Found\n\n" # placeholder
        response_content = ""
        
        content = recv_list.split("\r\n\r\n",1)[1] # get rid of header
        content = content.split("\n")

        # empty queries file
        if len(content) == 0:
            return b"HTTP/1.1 200 Ok\r\n\r\n"

        # remove empty items from the end
        if len(content) != 0:
            i = -1
            while content[i] == '':
                content.pop(i)
            
        # go through POST content
        for req in content:
            req = re.sub(r"\s+", '', req) # remove whitespaces
            if re.fullmatch(r".*:(A|PTR)", req) != None:
                resolved = resolveRequest(req.split(":")[1], req.split(":")[0])
                if resolved == 400:
                    response_err = b"HTTP/1.1 400 Bad Request\n\n"
                elif resolved == 404:
                    pass
                else:
                    response_content += req+"="+resolved+"\n"
            else:
                response_err = b"HTTP/1.1 400 Bad Request\n\n"
        
        #response
        if response_content == "":
            return response_err
        else:
            return ("HTTP/1.1 200 Ok\r\n\r\n"+response_content).encode()
    else:
        return b"HTTP/1.1 400 Bad Request\n\n"

def resolveRequest(req_type, req_name):
    if(req_type == "A"):
        try:
            ip = socket.gethostbyname(req_name)
            # if ip address is in GET request and type is A response error
            if(ip == req_name):
                return 400
            return ip
        except (socket.gaierror, socket.herror, UnicodeError):
            return 404

    elif(req_type == "PTR"):
        try:
            # check if recieved name is valid ip address 
            ipaddress.ip_address(req_name)

            url = socket.gethostbyaddr(req_name)
            return url[0]
        except (socket.gaierror, socket.herror):
            return 404
        except ValueError:
            return 400
    else:
        return 400

# argument handling
if len(sys.argv) != 2:
    sys.exit(77)

# if(int(sys.argv[1]) < 0 or int(sys.argv[1]) > 65535):
if not 0 <= int(sys.argv[1]) < 65536:
    sys.exit(77)

PORT = int(sys.argv[1]) 
HOST = '127.0.0.1'
RECV_BYTES = 1024
# create and bind the socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind((HOST, PORT))
except PermissionError:
    sys.exit(77)
s.listen(0)

while True:
    try:
        # accepts port
        client, addr = s.accept()
        # receives data
        data = client.recv(RECV_BYTES)

        # checks for content length and receves data according to it  
        if len(data.decode().split("Content-Length: ")) > 1:
            data_len = int(data.decode().split("Content-Length: ")[1].split("\n")[0])
            if data_len > RECV_BYTES :
                while data_len > 0:
                    data += client.recv(RECV_BYTES)
                    data_len -= RECV_BYTES 
          
        # parse to get method
        list_data = data.decode().split(" ", 1)
        # handle method
        if(list_data[0] == "GET"):
            send_msg = handleGET(list_data)
        elif(list_data[0] == "POST"):
            send_msg = handlePOST(list_data[1])
        else:
            if(client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n") == None):
                client.close()      
        # send message
        if(client.sendall(send_msg) == None):
            client.close()
    
    except (KeyboardInterrupt, BrokenPipeError):
        if client.fileno() != -1:
            if client.sendall(b"HTTP/1.1 500 Internal server error\r\n\r\n") == None:
                client.close()
        s.close()
        sys.exit(0)
