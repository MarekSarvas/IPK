#include <iostream>
#include <pcap.h>
#include <string>
#include <getopt.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <iomanip>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>

#define SIZE_ETHERNET 14

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

std::string convert_time( long s, long us ) {

    long hr = s / 3600 ; //3600 seconds is one hour
    s = s - 3600 * hr; // subtract hours from all seconds

    long min = s / 60; //60 seconds in minute
    s = s - 60 * min; // subtract minutes from all seconds

    std::stringstream ss;
    //to get current hour % 24,
    ss << std::setfill('0') << std::setw(2) << hr%24<<":"<< std::setfill('0') << std::setw(2) << min<<":"<< std::setfill('0') << std::setw(2) << s<<"."<<us;
    return ss.str(); //return as string
}


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


    pc_handle = pcap_open_live(args.interf.c_str(), BUFSIZ, 0, 1000, errbuf);

    if (pc_handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", "eth0", errbuf);
        return 2;
    }

    if (pcap_compile(pc_handle, &fp, filter.c_str(), 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter.c_str(), pcap_geterr(pc_handle));
        return(2);
    }

    if (pcap_setfilter(pc_handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter.c_str(), pcap_geterr(pc_handle));
        return(2);
    }

     pcap_loop(pc_handle, args.packet_num, callback_f, nullptr);

    /*
        int rc = pcap_dispatch(pc_handle, args.packet_num, callback_f, reinterpret_cast<u_char *>(&args));
        struct pcap_pkthdr pkthdr{};
        pcap_next(pc_handle, &pkthdr);
        std::cout << rc << std::endl;
        printf("Jacked a packet with length of [%d]\n", pkthdr.len);
    */

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
    long port;
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
                port = std::strtol(optarg, &endptr_tmp, 10);
                if(endptr_tmp == optarg || *endptr_tmp != '\0') { //if port is not a number or starts with number
                    ret_code = false;
                }
                if(port < 0 || port > 65535){
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
        if(new_filter.empty()){
            new_filter += "port "+args->port;
        }
        else{
            new_filter += " port "+args->port;
        }
    }
    if(!new_filter.empty()){
        std::cout << "Filter set to: \"" << new_filter << "\"" << std::endl;
    }

    return new_filter;
}

void callback_f(u_char *args,const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    /* convert to ip to get source and destination address*/
    const struct ip *ip;
    const struct iphdr * iphdr;
    const struct tcphdr *tcp;
    const struct udphdr *udp;

    ip = (struct ip *)(packet + SIZE_ETHERNET);//ip struct to get source and destination address
    iphdr = (struct iphdr*)(packet+SIZE_ETHERNET); //iphdr to get protocol

    unsigned long protocol = (unsigned int) iphdr->protocol;
    //TCP
    if(protocol == 6){
        tcp = (struct tcphdr*) (packet + sizeof(ether_header)+sizeof(struct iphdr));
        std::cout << std::dec << convert_time(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec) << " " << inet_ntoa(ip->ip_src) << " : " <<  ntohs(tcp->source) << " > " << inet_ntoa(ip->ip_dst) << " : " <<  ntohs(tcp->dest) << std::endl;
    }
    //UDP protocol
    else{
        udp = (struct udphdr*) (packet + sizeof(ether_header)+sizeof(struct iphdr));
        std::cout <<  std::dec << convert_time(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec) << " " << inet_ntoa(ip->ip_src) << " : " <<  ntohs(udp->source) << " > " << inet_ntoa(ip->ip_dst) << " : " <<  ntohs(udp->dest) << std::endl;
    }

    std::stringstream ss;
    std::string ascii;
    int i = 0;
    for(; i< pkthdr->len; i++){
        /*after 16 bytes print theirs ascii values and beginning of new row, reset string with ascii values */
        if(i%16 == 0){
            std::cout << ascii;
            std::cout << std::endl << "0x" << std::hex << std::setfill('0') << std::setw(4) << std::right << i << " ";
            ascii = "";
        }
        /* formatting */
        if(i%16 == 8){
            std::cout << " ";
        }
        /* print  hex number and save ascii value into string */
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int16_t)packet[i] << " ";
        /* if it can be printed */
        if((int)packet[i] >= 32 && (int)packet[i] <= 127){
            ascii += char((int)packet[i]);
        }
        /* if not store '.' */
        else{
            ascii +=".";
        }
    }
    /* if last row does not have 16 hexa numbers print spaces instead */
    while(i%16 != 0){
        std::cout<< "   ";
        i++;
    }
    /* if last row does not have 16 hexa numbers print ascii values of remaining data */
    std::cout << ascii;
    std::cout << std::endl << std::endl;
}