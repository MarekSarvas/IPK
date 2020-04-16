
all: ipk-sniffer.cpp
	sudo g++ -o ipk-sniffer ipk-sniffer.cpp  -lpcap
run : ipk-sniffer.cpp
	sudo g++ -o ipk-sniffer ipk-sniffer.cpp  -lpcap
	sudo valgrind ./ipk-sniffer -i wlp2s0