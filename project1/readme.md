# IPK Project 1 - HTTP domain name resolver

## Description
Simple server implementation using HTTP communication built in python using sockets. Server runs on local host by default and supports GET and POST methods for resolving domain names. 

## Usage
- server does not need to be built
- run server with **make run PORT=_port number_** where server runs on port *port number* and has to be integer between 0 and 65535
- server is running until _ctrl+c_ keyboard interrupt

## Implementation
* server is implemented as a script
* **"main body"** 
    * ensures that server is running until keyboard interrupt
    * ensures that port number is correct
    * bind port, listen and accept the client
    * if the method is POST i.e. received header has _Content-Length_ attribute
    data are received in loop to ensure server get all the data from client
    ```python
        data_len = int(data.decode().split("Content-Length: ")[1].split("\n")[0])
            while data_len > 0:
                data +=client.recv(RECV_BYTES)
                data_len -= RECV_BYTES 
    ``` 
* each method (GET, POST) has implemented function to handle it
* **handleGET** *function*
    * function receives client's request, parse it correctly and checks for correctrequest using regex
    ```python
        if re.fullmatch(r"\/resolve\?name=.*&type=(A|PTR) HTTP\/1\.1", request_head)!= None: 
    ```
    * parse the head to get *name* and *type* and calls function(*mentioned later*)for resolving domain name according to type(A or PTR)
    * return full response which will be sent to client in "main" loop
* **handlePOST** *function*
    * function receives client's request and parses it's head same as in *GET*(with different regex of course)
    ```python 
        if re.fullmatch(r"\/dns-query HTTP\/1\.1",req_header) != None: 
    ```
    * parse body into the list and in loop resolve every request by calling *resolveRequest* function same as in the *handleGET* function
        * every list's item is checked for correct pattern *REQUEST NAME(url or ip):TYPE(A or PTR)*
    * function returns one of the following: 
        * *200 Ok* if just 1 request in body is ok 
        * *404 Not Found* if none of the requested domain names cannot be resolved
        * *400 Bad Request* if just one request is incorrect and none of the left ones is correct and resolved
* **resolverRequest** *function*
    * checks if request type is *A* or *PTR* otherwise returns *400 Bad Request*
    * resolves domain name according to type and 
    * function returns of the following:
        * resolved domain name 
        * *400* when request name and request type combination are not correct
        * *404* when request name cannot be resolved

## Request formats
* **GET** *e.g.*:
`GET /resolve?name=apple.com&type=A HTTP/1.1`
or
`GET /resolve?name=147.229.14.131&type=PTR HTTP/1.1`
* **POST** *e.g.*:
`POST /dns-query HTTP/1.1`
where the example of a body is:
`www.fit.vutbr.cz:A`
`apple.com:A`
`147.229.14.131:PTR`
`seznam.cz:A`
## Acknowledgments
https://docs.python.org/3/library/socket.html

https://realpython.com/python-sockets/

## Author
Marek Sarvaš
xsarva00
07.03.202