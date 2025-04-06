#include "whs_sniff_tcpdump.hpp"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <pcap/pcap.h>
#include <cctype>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <tuple>

bool whs_sniff_tcpdump::hook(const u_char* pkt, const struct pcap_pkthdr* info, const int pktcount){
    std::stringstream ss;

    std::cout << "===== PACKET #" << std::setw(5) << std::setfill('0') << std::dec
        << pktcount << "=====" << std::endl;

    // print timestamp
    std::time_t raw_time = info->ts.tv_sec;
    struct tm* time_info = std::localtime(&raw_time);
    char buffer[64];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_info);
    ss << "Received packet at: " << buffer
        << "." << std::setfill('0') << std::setw(6) << info->ts.tv_usec << std::endl;

    // print ethenet frame info
    const u_char* next = whs_sniff_tcpdump::dump_ether(pkt, ss);
    if (next == NULL) return false;  // can not decode - early return

    // print IP packet info
    next = whs_sniff_tcpdump::dump_ip(next, ss);
    if (next == NULL) return false;  // can not decode - early return
    
    // print tcp packet info
    int datasize;
    std::tie(next, datasize) = whs_sniff_tcpdump::dump_tcp(next, (pkt + info->len) - next, ss);
    if (next == NULL) return false;  // can not decode - early return

    std::cout << ss.str();

    std::cout << "----- END LOG -----" << std::endl << std::endl;
    return false;
}

std::string whs_sniff_tcpdump::hexdump(const u_char* data, const char sep, const int size){
    std::stringstream ss;
    for (int i = 0; i < size; i++) {
        ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(data[i]);
        if (!(i == size - 1 || i % 16 == 15)) ss << sep;
        if (i % 16 == 15) {
            ss << " | 0x" << i - 15 << "-0x" << i << " | ";
            for (int j = -15; j <= 0; j++) {
                if (!std::isprint(data[i + j])) {
                    ss << ".";
                } else {
                    ss << data[i + j];
                }
            }
            ss << std::endl;
        }
    }
    if (sep == ' ' && size % 16 != 0) {
        int offset = (size % 16);
        int start_pos = size - offset;
        for (int i = 0; i < (16 - offset); i++) {
            ss << "   ";
        }
        ss << " | 0x" << start_pos << "-0x" << start_pos + offset << " | ";
        for (int i = start_pos; i < start_pos + offset; i++) {
            if (!std::isprint(data[i])) {
                ss << ".";
            } else {
                ss << data[i];
            }
        }
        ss <<std::endl;
    }
    return ss.str();
}


const u_char* whs_sniff_tcpdump::dump_ether(const u_char* pkt, std::stringstream& ss) {
    ss << "+++++ Ethernet Frame +++++" << std::endl;
    const struct ethheader* eth = reinterpret_cast<const ethheader *>(pkt);
    ss << "- EtherType: " << std::hex << std::setw(4) << ntohs(eth->ether_type) << std::endl;
    if (ntohs(eth->ether_type) != ETH_P_IP) {
        std::cout << "Warning: L3 Protocol is not IPv4. Ignoring this frame." << std::endl;
        return NULL;
    }

    ss << "- source MAC address: " << whs_sniff_tcpdump::hexdump(eth->ether_shost, ':', 6) << std::endl;
    ss << "- destination MAC address: " << whs_sniff_tcpdump::hexdump(eth->ether_dhost, ':', 6) << std::endl;
    return pkt + sizeof(struct ethheader);
}


const u_char* whs_sniff_tcpdump::dump_ip(const u_char* pkt, std::stringstream& ss) {
    ss << "+++++ IP Packet +++++" << std::endl;
    const struct ipheader* ip = reinterpret_cast<const ipheader *>(pkt);
    ss << "- Protocol: " << std::hex << static_cast<int>(ip->iph_protocol) << std::endl;
    if (static_cast<int>(ip->iph_protocol) != IPPROTO_TCP) {
        std::cout << "Warning: L3 Protocol is not TCP. Ignoring this packet." << std::endl;
        return NULL;
    }

    ss << "- From: " << std::dec << inet_ntoa(ip->iph_sourceip) << std::endl;
    ss << "- To: " << inet_ntoa(ip->iph_destip) << std::endl;
    ss << "- TTL: " << static_cast<unsigned short>(ip->iph_ttl) << std::endl;
    return pkt + (ip->iph_ihl * 4);
}

std::tuple<const u_char*, const int> whs_sniff_tcpdump::dump_tcp(const u_char* pkt, const int segment_size, std::stringstream& ss) {
    ss << "+++++ TCP Data +++++" << std::endl;
    const struct tcpheader* tcp = reinterpret_cast<const tcpheader*>(pkt);
    ss << "- From: port " << ntohs(tcp->tcp_sport) << std::endl;
    ss << "- To: port " << ntohs(tcp->tcp_dport) << std::endl;

    const u_char* data_ptr = pkt + (tcp->tcp_offx2 / 4);
    int data_size = segment_size - (tcp->tcp_offx2 / 4);
    ss << "- Data size: " << data_size << std::endl;
    ss << std::endl;
    ss << "data dump start :::::" << std::endl;
    ss << whs_sniff_tcpdump::hexdump(data_ptr, ' ', data_size > 64 ? 64 : data_size);
    ss << "::::: dump end" << std::endl;
    
    return std::make_tuple(data_ptr, data_size);
}
