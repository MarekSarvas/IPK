#include <iostream>
#include <pcap.h>
#include <string>
#include <getopt.h>
#include<netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <iomanip>
typedef struct ARGS{
	std::string interf = ""; //name of interfacce
    std::string port = "";
    bool is_tcp = false;
    bool is_udp = false;
    int packet_num = 1;
} Targs;






bool check_args(int argc, char *argv[],Targs *args);
std::string create_filter(const Targs*);
void callback_f(u_char *args,const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char *argv[])
{
    Targs args;
    bool args_rc = check_args(argc, argv, &args);
    if(!args_rc){
        return 1;
    }


    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp;

    /* if interface is not given as program argument get all interfaces*/
    if(args.interf.empty()){
        if(pcap_findalldevs(&alldevsp, errbuf) == PCAP_ERROR){
            std::cerr << "Error finding interfaces\n";
            return 1;
        }
        while(alldevsp != nullptr){
            std::cout << alldevsp->name << std::endl;
            alldevsp = alldevsp->next;
        }
        return 0;
    }

    pcap_t *pc_handle; //packet capture handle
    struct bpf_program fp{}; //compiled filter expresion
    std::string filter = create_filter(&args);
    bpf_u_int32 net = 0;		/* The IP of our sniffing device */


    pc_handle = pcap_open_live(args.interf.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (pc_handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", "eth0", errbuf);
        return 2;
    }

    if (pcap_compile(pc_handle, &fp, filter.c_str(), 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter.c_str(), pcap_geterr(pc_handle));
        return(2);
    }
    std::cout << "NET:" << net << std::endl;
    if (pcap_setfilter(pc_handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter.c_str(), pcap_geterr(pc_handle));
        return(2);
    }
    std::cout << "DATA LINK:" << pcap_datalink(pc_handle) << std::endl;




    pcap_loop(pc_handle, args.packet_num, callback_f, reinterpret_cast<u_char *>(&args));


    pcap_close(pc_handle);
    pcap_freecode(&fp);
    return(0);
}

/* Function gets program number of arguments, program arguments and struct for storing them.
 * Using getopt_long check correct argument in case of not supported arg return false and end program with
 * return code 1
 */
bool check_args(int argc, char *argv[], Targs* args){
    /* long options for program arguments*/
    const struct option longopts[] ={
            {"tcp", 0, nullptr, 't'},
            {"udp", 0, nullptr, 'u'},
            {nullptr, 1, nullptr, 'i'},
            {nullptr, 1, nullptr, 'n'},
            {nullptr, 1, nullptr, 'p'},
            {nullptr,0,nullptr,0}
    };

    int curr_arg;
    int index;
    bool ret_code = true;
    char *endptr_tmp;  //tmp for correct number checking

    /*getopt for checking given arguments, default option indicates invalid program argument*/
    while((curr_arg = getopt_long(argc, argv, "tui:n:p:", longopts, &index)) != -1){
        switch(curr_arg) {
            case 't':
                args->is_tcp = true;
                break;
            case 'u':
                args->is_udp = true;
                break;
            case 'i':
                args->interf = std::string(optarg);
                break;
            case 'n':
                 //tmp for correct number checking
                args->packet_num = (int)std::strtol(optarg, &endptr_tmp, 10);
                if(endptr_tmp == optarg || *endptr_tmp != '\0') { //if port is not a number or starts with number
                    ret_code = false;
                }
                break;
            case 'p':
                std::strtol(optarg, &endptr_tmp, 10);
                if(endptr_tmp == optarg || *endptr_tmp != '\0') { //if port is not a number or starts with number
                    ret_code = false;
                }
                args->port = optarg;
                break;
            default:

                return false;
        }
    }
    return ret_code;
}

/* creates new filter based on program arguments*/
std::string create_filter(const Targs * args){
    std::string new_filter;

    /*if tcp is set and udp dont filter tcp*/
    if(args->is_tcp && !args->is_udp) {
        new_filter += "tcp";
    }
    /*if udp is set and tcp dont filter udp*/
    else if(!args->is_tcp && args->is_udp){
        new_filter = "udp";
    }
    /*if both tcp and udp is set or both are unset dont filter*/

    /*if port is set add it to the filter*/
    if(!args->port.empty()){
        new_filter += " port "+args->port;
    }
    std::cout << "FILTER" << new_filter << std::endl;
    return new_filter;
}
#define SIZE_ETHERNET 14
void callback_f(u_char *args,const struct pcap_pkthdr* pkthdr, const u_char* packet)

{
    //std::cout << pkthdr->len << ":" << std::hex  << std::setw(2) << packet[4] << std::endl;

    //printf("%d ",pkthdr->len);

    for(int i =0; i< pkthdr->len; i++){
        if(i%16 == 0){
            std::cout << std::endl << "0x" << std::hex << std::setfill('0') << std::setw(4) << std::right << i << " ";
        }
        printf("%02x ", packet[i]);
    }
    std::cout << std::endl << std::endl;
    ip a{};
    ethhdr b{};
    tcphdr c{};
    udphdr d{};

    auto * new_args = (Targs *)(args);

    const ethhdr *ethernet; /* The ethernet header */
    const struct ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const char *payload; /* Packet payload */



    /*
    u_int size_ip;
    u_int size_tcp;

    ethernet = (ethhdr*)(packet);

    ip = (iphdr *)(packet + SIZE_ETHERNET);
    ip->
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    */
}