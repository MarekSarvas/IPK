#include <iostream>
#include <pcap.h>
#include <string>
#include <getopt.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
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
#include <unordered_map>


//struct for storing argument values
typedef struct ARGS{
	std::string interf = ""; //name of interfacce
    std::string port = "";  // port number as string
    bool is_tcp = false;   //tcp filter flag
    bool is_udp = false;  //udp filter flag
    int packet_num = 1;  //number of packets to be sniffed
} Targs;

std::unordered_map<std::string, std::string> ip_cache = {}; // unordered map to simulate cache for ip address resolving

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
        to_free = alldevsp;//save list of interfaces to free memory at the end
        //print all interfaces
        while(alldevsp != nullptr){
            std::cout << alldevsp->name << std::endl;
            alldevsp = alldevsp->next;

        }
        pcap_freealldevs(to_free);//free memory allocated for interfaces
        return 0;
    }

    pcap_t *pc_handle;       //packet capture handle
    struct bpf_program fp{};//compiled filter expresion
    std::string filter = create_filter(&args);
    bpf_u_int32 net = 0;

    pc_handle = pcap_open_live(args.interf.c_str(), BUFSIZ, 0, 1000, errbuf);

    if (pc_handle == nullptr) {
        std::cerr << "Could not open interface " <<  args.interf.c_str() << ": " << errbuf << std::endl;
        return 1;
    }

    if (pcap_compile(pc_handle, &fp, filter.c_str(), 0, net) == -1) {
        std::cerr << "Could not compile filter " <<  filter.c_str() << ": " << pcap_geterr(pc_handle) << std::endl;
        return 1;
    }

    if (pcap_setfilter(pc_handle, &fp) == -1) {
        std::cerr << "Could not apply filter " <<  filter.c_str() << ": " << pcap_geterr(pc_handle) << std::endl;
        return 1;
    }

    pcap_loop(pc_handle, args.packet_num, callback_f, nullptr);

    //correctly close interface
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
    bool both = false;
    /*if tcp is set and udp dont filter tcp*/
    if(args->is_tcp && !args->is_udp) {
        new_filter = "(proto \\tcp)";
    }
    /*if udp is set and tcp dont filter udp*/
    else if(!args->is_tcp && args->is_udp){
        new_filter = "(proto \\udp)";
    }
    /*if both tcp and udp is set or both are unset*/
    else{
        new_filter = "(proto \\tcp) or (proto \\udp)";
        both = true;
    }
    /*if port is set add it to the filter*/
    if(!args->port.empty()){
        if(new_filter.empty()){
            new_filter += "port "+args->port;
        }
        else{
            if(both){
                new_filter = "(proto \\tcp) and (port "+args->port+") or (proto \\udp) and (port "+args->port+")";
            }else{
                new_filter += " and (port "+args->port+")";
            }

        }
    }
    if(!new_filter.empty()){
        std::cout << "Filter set to: \"" << new_filter << "\"" << std::endl;
    }

    return new_filter;
}

void callback_f(u_char *args,const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    //declaration of neccessary headers
    const struct iphdr * iphdr;
    const struct tcphdr *tcp;
    const struct udphdr *udp;
    const struct ip6_hdr *ip6hdr;
    const struct ether_header *ethhdr;
    const struct icmp_header *ih;
    // strings for ip addresses
    char ipv4_source[INET_ADDRSTRLEN];  //source address
    char ipv4_dest[INET_ADDRSTRLEN];  //destination address

    char ipv6_source[INET6_ADDRSTRLEN];  //source address
    char ipv6_dest[INET6_ADDRSTRLEN];  //destination address

    size_t ip_len;
    unsigned int protocol = 0;

    //strings for final resolved addresses
    std::string src_name;
    std::string dest_name;
    const char *src_to_resolve;
    const char *dest_to_resolve;

    ethhdr = (struct ether_header *)(packet); // make ethernet header to check for correct ethernet type( ipv4/ipv6)

    // check ethernet type for IPv4 or IPv6 and get source/destiantion address length of header and protocol
    if(ntohs(ethhdr->ether_type) == ETHERTYPE_IP){
        iphdr = (struct iphdr*)(packet+sizeof(ether_header)); //iphdr to get protocol
        // get ipv4 address from ipv4 header, address is stored into ipv4_source
        inet_ntop(AF_INET, &(iphdr->saddr), ipv4_source, INET_ADDRSTRLEN);
        src_to_resolve = ipv4_source;
        // same as source but for destination
        inet_ntop(AF_INET, &(iphdr->daddr), ipv4_dest, INET_ADDRSTRLEN);
        dest_to_resolve = ipv4_dest;
        // get length of ipv4 header
        ip_len = sizeof(struct iphdr);
        // UDP or TCP protocol
        protocol = (unsigned int) iphdr->protocol;
    }
    // same as above but for IPv6
    else if(ntohs(ethhdr->ether_type) == ETHERTYPE_IPV6){
        ip6hdr = (struct ip6_hdr*)(packet + sizeof(ether_header));

        inet_ntop(AF_INET6, &(ip6hdr->ip6_src), ipv6_source, INET6_ADDRSTRLEN);
        src_to_resolve = ipv6_source;

        inet_ntop(AF_INET6, &(ip6hdr->ip6_dst), ipv6_dest, INET6_ADDRSTRLEN);
        dest_to_resolve = ipv6_dest;

        ip_len = sizeof(struct ip6_hdr);
        protocol = (unsigned int) ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    }
    //should not happen
    else{
        std::cerr << "Ethernet type got from ethernet header of packet is not ETHERTYPE_IP nor ETHERTYPE_IPV6\n\n\n";
        return;
    }

    /* structures and variables for resolving packets source/destination ip addresses to name */
    struct addrinfo *result = nullptr;
    struct addrinfo hints{};

    //set values for address used for getting address info
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char get_name[NI_MAXHOST];         // array for address name


    //---------------------------------------------Source name----------------------------------------//
    // using unordered map as ip address cache, if source ip address count is 0, ip address is not in cache and resolving is performed, otherwise source name is loaded from "cache"
    if(ip_cache.count(src_to_resolve) == 0){
        // get addr structure into 'res' to get rid of ipv4 - ipv6 dependencies
        if (getaddrinfo(src_to_resolve, nullptr, &hints, &result) == 0){
            std::cerr << "Resolving source address\n";
            // get info about address, resolved name is in get_name, if function does not return 0 ip address is stored as src address instead
            if (getnameinfo(result->ai_addr, result->ai_addrlen, get_name, sizeof(get_name), nullptr, 0, NI_NAMEREQD) == 0){
                src_name = get_name;
            }
            else{
                src_name = src_to_resolve;
            }
            //free before next usage
            freeaddrinfo(result);
            result = nullptr;
        }
        // if error during getaddrinfo occures ip address from packet is used instead of resolved name
        else{
            src_name = src_to_resolve;
            freeaddrinfo(result);
            result = nullptr;
        }
        // added ip address into cache
        ip_cache.insert({src_to_resolve, src_name});
    }
    // loading source name from cache
    else{
        std::cerr << "Using cache for source address\n";
        src_name = ip_cache.find(src_to_resolve)->second;
    }

    //---------------------------------------------Destination name----------------------------------------//
    // same usage as in source name, uses same cache
    if(ip_cache.count(dest_to_resolve) == 0){
        // get addr structure into 'res' to get rid of ipv4 - ipv6 dependencies
        if (getaddrinfo(dest_to_resolve, nullptr, &hints, &result) == 0){
            std::cerr << "Resolving destination address\n\n";
            //get info about address, resolved name is in get_name, if function does not return 0 ip address is stored as src address instead
            if (getnameinfo(result->ai_addr, result->ai_addrlen, get_name, sizeof(get_name), nullptr, 0, NI_NAMEREQD) == 0){
                dest_name = get_name;
            }else{
                dest_name = dest_to_resolve;
            }
            freeaddrinfo(result);
            result = nullptr;
        }
        // if error during getaddrinfo occures ip address from packet is used instead of resolved name
        else{
            dest_name = dest_to_resolve;
            freeaddrinfo(result);
            result = nullptr;
        }
        // added ip address into cache
        ip_cache.insert({dest_to_resolve, dest_name});
    }
    // loading destination name from cache
    else{
        std::cerr << "Using cache for destination address\n\n";
        dest_name = ip_cache.find(dest_to_resolve)->second;
    }


    //TCP
    if(protocol == 6){
        tcp = (struct tcphdr*) (packet + sizeof(ether_header)+ip_len);
        std::cout << std::dec << convert_time(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec) << " " << src_name << " : " <<  ntohs(tcp->source) << " > " << dest_name << " : " <<  ntohs(tcp->dest) << std::endl;
    }
    //UDP
    else if (protocol == 17){
        udp = (struct udphdr*) (packet + sizeof(ether_header)+ip_len);
        std::cout <<  std::dec << convert_time(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec) << " " << src_name << " : " <<  ntohs(udp->source) << " > " << dest_name << " : " <<  ntohs(udp->dest) << std::endl;
    }
    //should not happen
    else{
        std::cerr << "Protocol of the packet is not TCP nor UDP\n";
        return;
    }

    // variables for correct format of packet output
    std::stringstream ss;
    std::string ascii;
    int i = 0;
    bool half = false;

    // print packet
    for(; i< pkthdr->len; i++){
        /*after 16 bytes print theirs ascii values and beginning of new row, reset string with ascii values */
        if(i%16 == 0){
            std::cout << " " << ascii;
            std::cout << std::endl << "0x" << std::hex << std::setfill('0') << std::setw(4) << std::right << i << " ";
            ascii = "";
            half = false;
        }
        /* formatting */
        if(i%16 == 8){
            std::cout << " ";
            half = true;
        }
        /* print  hex number and save ascii value into string */
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int16_t)packet[i] << " ";
        /* if it can be printed */
        if((int)packet[i] >= 32 && (int)packet[i] <= 127){
            if(i%16 == 8){
                ascii += " ";
            }
            ascii += char((int)packet[i]);
        }
        /* if not store '.' */
        else{
            if(i%16 == 8){
                ascii += " ";
            }
            ascii +=".";
        }
    }

    /* if last row does not have 16 hexa numbers print spaces instead so ascii characters are correctly formated*/
    if(i%16 != 0){
        while(i%16 != 0){
            std::cout << "   ";
            i++;
        }
        // if more than 8 bytes were print, print 1 space because of space in middle between 8th and 9th byte
        if(half){
            std::cout << " ";
        }
        // if less than 8 bytes were print, print 2 spaces
        else{
            std::cout << "  ";
        }
    }

    /* if last row does not have 16 hexa numbers print ascii values of remaining data */
    std::cout << ascii;
    std::cout << std::endl << std::endl << std::endl;
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