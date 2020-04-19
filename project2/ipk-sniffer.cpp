#include <iostream>
#include <pcap.h>
#include <string>
#include <getopt.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <iomanip>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>
#include <sys/socket.h>
#include <netdb.h>


#define SIZE_ETHERNET 14

typedef struct ARGS{
	std::string interf = ""; //name of interfacce
    std::string port = "";  // port number as string
    bool is_tcp = false;   //tcp filter flag
    bool is_udp = false;  //udp filter flag
    int packet_num = 1;  //number of packets to be sniffed
} Targs;

int check_args(int argc, char *argv[],Targs *args);
std::string create_filter(const Targs*);
void callback_f(u_char *args,const struct pcap_pkthdr* pkthdr, const u_char* packet);
std::string convert_time( long s, long us );



int main(int argc, char *argv[])
{
    Targs args;
    //check program arguments
    int args_rc = check_args(argc, argv, &args);
    if(args_rc == 1){ // wrong arguments
        return 1;
    }
    else if(args_rc == 2){ // help
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp;
    pcap_if_t *to_free;
    /* if interface is not given as program argument get all interfaces */
    if(args.interf.empty()){
        if(pcap_findalldevs(&alldevsp, errbuf) == PCAP_ERROR){
            std::cerr << "Error finding interfaces\n";
            return 1;
        }
        to_free = alldevsp;
        while(alldevsp != nullptr){
            std::cout << alldevsp->name << std::endl;

            alldevsp = alldevsp->next;

        }
        pcap_freealldevs(to_free);
        return 0;
    }

    pcap_t *pc_handle;       //packet capture handle
    struct bpf_program fp{};//compiled filter expresion
    std::string filter = create_filter(&args);
    bpf_u_int32 net = 0;


    pc_handle = pcap_open_live(args.interf.c_str(), BUFSIZ, 0, 1000, errbuf);

    if (pc_handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", "eth0", errbuf);
        return 2;
    }
    //std::cout << "Link layer header number: " << pcap_datalink(pc_handle) << std::endl;
    if (pcap_compile(pc_handle, &fp, filter.c_str(), 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter.c_str(), pcap_geterr(pc_handle));
        return(2);
    }

    if (pcap_setfilter(pc_handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter.c_str(), pcap_geterr(pc_handle));
        return(2);
    }

    pcap_loop(pc_handle, args.packet_num, callback_f, nullptr);

    pcap_close(pc_handle);
    pcap_freecode(&fp);

    return(0);
}

/*
 * Function gets program number of arguments, program arguments and struct for storing them.
 * Using getopt_long check correct argument in case of not supported arg return false and end program with
 * return code 1
 */
int check_args(int argc, char *argv[], Targs* args){
    /* long options for program arguments*/
    const struct option longopts[] ={
            {"help", 0, nullptr, 'h'},
            {"tcp", 0, nullptr, 't'},
            {"udp", 0, nullptr, 'u'},
            {nullptr, 1, nullptr, 'i'},
            {nullptr, 1, nullptr, 'n'},
            {nullptr, 1, nullptr, 'p'},
            {nullptr,0,nullptr,0},
    };

    int curr_arg;
    int index;
    long port;
    bool help_flag = true;
    char *endptr_tmp;  //tmp for correct number checking

    /*getopt for checking given arguments, default option indicates invalid program argument*/
    while((curr_arg = getopt_long(argc, argv, "tui:n:p:h", longopts, &index)) != -1){
        switch(curr_arg) {
            case 't':
                args->is_tcp = true;
                help_flag = false;
                break;
            case 'u':
                args->is_udp = true;
                help_flag = false;
                break;
            case 'i':
                args->interf = std::string(optarg);
                help_flag = false;
                break;
            case 'n':
                 //tmp for correct number checking
                args->packet_num = (int)std::strtol(optarg, &endptr_tmp, 10);
                if(endptr_tmp == optarg || *endptr_tmp != '\0') { //if port is not a number or starts with number
                    return 1;
                }
                help_flag = false;
                break;
            case 'p':
                port = std::strtol(optarg, &endptr_tmp, 10);
                if(endptr_tmp == optarg || *endptr_tmp != '\0') { //if port is not a number or starts with number
                    return 1;
                }
                if(port < 0 || port > 65535){
                    return 1;
                }
                args->port = optarg;
                help_flag = false;
                break;
            case 'h':
                if(!help_flag){
                    return 1;
                }
                std::cout << "Packet sniffer by Marek Sarvas\n"
                             "--see readme.md for how to compile information\n--run program without arguments to see all available interfaces\n-i {interface} to select interface on which you want to sniff packets\n"
                             "-n {number} to select how many packet will be sniffed\n-p {port number} to select on which port packets will be sniffed\n"
                             "-t / --tcp to filter only tcp packets\n-u / --udp to filter only udp packets\n--if none of tcp or udp is selected packets sniffed will be either udp or tcp\n"
                             "--if port is not selected packets will be sniffed on all ports\n--if -n is not selected only one packet will be sniffed\n";
                return 2;
            default:
                return 1;
        }
    }
    return 0;
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

    struct sockaddr_in socket_addr{};    /* socket address         */
    socklen_t len;                      /* socket adress length   */
    char get_name[NI_MAXHOST];         /* array for address name */

    std::string src_name;
    std::string dest_name;

    /* IPv4 only */
    socket_addr.sin_family = AF_INET;                                /* IP protocol family.  */
    socket_addr.sin_addr.s_addr = inet_addr(inet_ntoa(ip->ip_src)); /* converted ip address into string then into number */
    len = sizeof(struct sockaddr_in);                              /* get length of socket address */


    //--------------------------------------------source name-------------------------------------------------//
    //socket address struct,    socket_addr len, host name, its length, service and length - does not need , flags - does not return numeric addresses - cannot convert IP and IP is used on stdout
    int rc = getnameinfo((struct sockaddr *) &socket_addr, len, get_name, sizeof(get_name),nullptr, 0, NI_NAMEREQD);
    if(rc){
       src_name = inet_ntoa(ip->ip_src);
    }else{
        src_name = get_name;
    }

    //---------------------------------------------destination name----------------------------------------//
    socket_addr.sin_addr.s_addr = inet_addr(inet_ntoa(ip->ip_dst));
    rc = getnameinfo((struct sockaddr *) &socket_addr, len, get_name, sizeof(get_name),nullptr, 0, NI_NAMEREQD);
    if(rc){
        dest_name = inet_ntoa(ip->ip_dst);
    }else{
        dest_name = get_name;
    }

    //TCP
    if(protocol == 6){
        tcp = (struct tcphdr*) (packet + sizeof(ether_header)+sizeof(struct iphdr));
        std::cout << std::dec << convert_time(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec) << " " << src_name << " : " <<  ntohs(tcp->source) << " > " << dest_name << " : " <<  ntohs(tcp->dest) << std::endl;
    }
    //UDP protocol
    else{
        udp = (struct udphdr*) (packet + sizeof(ether_header)+sizeof(struct iphdr));
        std::cout <<  std::dec << convert_time(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec) << " " << src_name << " : " <<  ntohs(udp->source) << " > " << dest_name << " : " <<  ntohs(udp->dest) << std::endl;
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

std::string convert_time( long s, long us ) {

    long hr = s / 3600 ; //3600 seconds is one hour
    s = s - 3600 * hr;  // subtract hours from all seconds
    long min = s / 60; //60 seconds in minute
    s = s - 60 * min; // subtract minutes from all seconds

    std::stringstream ss;
    //to get current hour % 24,
    ss << std::setfill('0') << std::setw(2) << hr%24<<":"<< std::setfill('0') << std::setw(2) << min<<":"<< std::setfill('0') << std::setw(2) << s<<"."<<us;
    return ss.str(); //return as string
}