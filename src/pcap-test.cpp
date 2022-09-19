#include "pcap-test.hpp"

/*
 * Find ethernet header from packet and save several values
*/
void findEthHeader(struct libnet_ethernet_hdr& eth, const u_char* packet) {
    const int eth_header_size = sizeof(struct libnet_ethernet_hdr);

    memcpy(&eth, packet, eth_header_size);
    eth.ether_type = ntohs(eth.ether_type); // uint16_t, have to translate from NBO to HBO

    return;
}

/*
 * Find TCP header from the packet and save several values
 * ** Warning : libnet_tcp_hdr does not save TCP header, but several values from the packet **
 * ** This means that libnet_tcp_hdr's size can be different from the real TCP header size **
*/
void findTCPHeader(struct libnet_tcp_hdr& tcp, const u_char* packet) {
    const int tcp_header_size = sizeof(struct libnet_tcp_hdr);

    memcpy(&tcp, packet, tcp_header_size);
    tcp.th_sport = ntohs(tcp.th_sport);     // uint16_t, have to translate from NBO to HBO
    tcp.th_dport = ntohs(tcp.th_dport);     // uint16_t, have to translate from NBO to HBO
    tcp.th_seq = ntohl(tcp.th_seq);         // uint32_t, have to translate from NBO to HBO
    tcp.th_ack = ntohl(tcp.th_ack);         // uint32_t, have to translate from NBO to HBO
    tcp.th_win = ntohs(tcp.th_win);         // uint16_t, have to translate from NBO to HBO
    tcp.th_sum = ntohs(tcp.th_sum);         // uint16_t, have to translate from NBO to HBO
    tcp.th_urp = ntohs(tcp.th_urp);         // uint16_t, have to translate from NBO to HBO

    return;
}

/*
 * Find IP header from the packet and save several values
 * ** Warning : libnet_tcp_hdr does not save IP header, but several values from the packet **
 * ** This means that libnet_ip_hdr's size can be different from the real IP header size **
*/
void findIPHeader(struct libnet_ipv4_hdr& ipv4, const u_char* packet) {
    const int ip_header_size = sizeof(struct libnet_ipv4_hdr);

    memcpy(&ipv4, packet, ip_header_size);
    ipv4.ip_len = ntohs(ipv4.ip_len);       // uint16_t, have to translate from NBO to HBO
    ipv4.ip_id = ntohs(ipv4.ip_id);         // uint16_t, have to translate from NBO to HBO
    ipv4.ip_sum = ntohs(ipv4.ip_sum);       // uint16_t, have to translate from NBO to HBO

    return;
}

/*
 * extract MAC information from ethernet header to another pair of strings
*/
std::pair<std::string, std::string> MACtos(struct libnet_ethernet_hdr& eth) {
    std::stringstream srcMAC, destMAC;

    // for decent code :)
    srcMAC << std::hex;
    srcMAC << std::setw(2) << std::setfill('0') << (int)eth.ether_shost[0] << ':';
    srcMAC << std::setw(2) << std::setfill('0') << (int)eth.ether_shost[1] << ':';
    srcMAC << std::setw(2) << std::setfill('0') << (int)eth.ether_shost[2] << ':';
    srcMAC << std::setw(2) << std::setfill('0') << (int)eth.ether_shost[3] << ':';
    srcMAC << std::setw(2) << std::setfill('0') << (int)eth.ether_shost[4] << ':';
    srcMAC << std::setw(2) << std::setfill('0') << (int)eth.ether_shost[5];

    destMAC << std::hex;
    destMAC << std::setw(2) << std::setfill('0') << (int)eth.ether_dhost[0] << ':';
    destMAC << std::setw(2) << std::setfill('0') << (int)eth.ether_dhost[1] << ':';
    destMAC << std::setw(2) << std::setfill('0') << (int)eth.ether_dhost[2] << ':';
    destMAC << std::setw(2) << std::setfill('0') << (int)eth.ether_dhost[3] << ':';
    destMAC << std::setw(2) << std::setfill('0') << (int)eth.ether_dhost[4] << ':';
    destMAC << std::setw(2) << std::setfill('0') << (int)eth.ether_dhost[5];

    return std::make_pair(srcMAC.str(), destMAC.str());
}

int printPacket(const u_char* packet) {
    struct libnet_ethernet_hdr eth;
    struct libnet_tcp_hdr tcp;
    struct libnet_ipv4_hdr ipv4;

    int eth_header_size, ip_header_size, tcp_header_size, total_header_size, data_size;
    char MAC[STR_MAC_LEN] = { 0 };
    char payload[STR_PAYLOAD_LEN] = { 0 };

    std::pair<std::string, std::string> MACStrPair;

    // Find each header's size ---------------------------------------------------------------------
    eth_header_size = sizeof(struct libnet_ethernet_hdr);
    ip_header_size = (packet[eth_header_size] & 0x0f) << 2;                         // Word to Bytes
    tcp_header_size = (packet[eth_header_size + ip_header_size + 12] & 0xf0) >> 2;  // Word to Bytes
    total_header_size = eth_header_size + ip_header_size + tcp_header_size;
    // ---------------------------------------------------------------------------------------------

    // find headers from packet --------------------------------------------------------------------
    // find ethernet header from packet
    findEthHeader(eth, packet);
    if(eth.ether_type != ETHERTYPE_IP) return FAILURE_NOT_IP;

    // find IP header from packet
    findIPHeader(ipv4, packet + eth_header_size);
    if(ipv4.ip_p != IPTYPE_TCP) return FAILURE_NOT_TCP;

    // find TCP header from packet
    findTCPHeader(tcp, packet + eth_header_size + ip_header_size);
    
    // find payload size
    data_size = ipv4.ip_len - ip_header_size - tcp_header_size;
    // ---------------------------------------------------------------------------------------------

    // Print Packet --------------------------------------------------------------------------------
    MACStrPair = MACtos(eth);

    std::cout << "================<Packet Captured>================\n";
    std::cout << "[[Ethernet Layer]]\n";
    std::cout << "[Destination MAC] " << MACStrPair.first << '\n';
    std::cout << "[Source      MAC] " << MACStrPair.second << '\n';

    std::cout << "\n[[IP Layer]]\n";
    std::cout << "[Destination IP] " << inet_ntoa(ipv4.ip_dst) << '\n';
    std::cout << "[Source      IP] " << inet_ntoa(ipv4.ip_src) << '\n';

    std::cout << "\n[[Transport Layer]]\n";
    std::cout << "[Destination Port] " << std::dec << tcp.th_dport << '\n';
    std::cout << "[Source      Port] " << std::dec << tcp.th_sport << '\n';

    std::cout << "\n[Payload]\n";
    std::cout << "Total payload length : " << std::dec << data_size << '\n';

    for(int i = 0; i < data_size; i++) {
        if(i >= 10) break;
        
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)packet[total_header_size + i] << ' ';
        if(i % 8 == 7) std::cout << '\n';
    }

    std::cout << "\n=================================================" << std::endl;
    // ---------------------------------------------------------------------------------------------

    return SUCCESS;
}