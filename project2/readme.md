# Project 2 - Packet sniffer IPK 2019/2020
**Name:** Marek Sarvaš
**Login:** xsarva00

## Description
Programme for sniffing packets implemented in C++ using mainly pcap library. Project is implemented in one file **ipk-sniffer.cpp**
##Submited files
* ipk-sniffer.cpp
* <span>readme.</span>md
* Makefile
* Documentation.pdf

## Run
* compile project using makefile with command *make*, there is a need to run this programme with *sudo* (root privileges) this is include in Makefile, resulting executable file will be **ipk-sniffer**
```bash
make
```
* to run executable you need to run it with sudo command because of capturing packets on different ports e.g.:
```bash
sudo ./ipk-sniffer -i eth0
```
* there can be added more programme arguments for filtering tcp/udp packets, number of packets or specific port e.g.:
```bash
./ipk-sniffer -i eth0 -p 23 --tcp -n 2
```
all arguments possible are discribed in program help e.g.:
```bash
./ipk-sniffer --help
```
* *ipk-sniffer* executable can be run without *sudo* command in 2 cases
    * ipk-sniffer is  executed without arguments
    * ipk-sniffer is  executed with *--help* argument

## Implementation
* Programme sniffs first n packets set by programme argument(1 default). If flags are set(i.e.: tcp,udp or port number), filter is created and used. Programme runs until n packets are sniffed resolved and printed on stdout.
* Programme is sniffing only tcp or udp packets, user is still able to set interface as not ethernet e.g.: bluetooth but no packets will be sniffed and programme will eventually run forever/ until ctrl+C. Or if interface does not have implemented link-layer type filtering programm ends with return code 2.
* When -i(interface argument) is not used programme prints all edvices found by *finalldevs()* function.
* Information about every packet contain timestamp, source ip and port, destination ip and port. If IP can be resolved to address name by *getnameinfo()* function address name is printed. Sniffer supports only IPv4 address resolving, IPv6 address is always printed as IP.
* Using *getnameinfo()* causes small memory leak according to *valgrind* when IP address cannot be resolved.
