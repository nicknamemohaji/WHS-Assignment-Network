#include <cstdlib>
#include <pcap/pcap.h>

#include <iostream>
#include <string>

#include "whs_sniff.hpp"
#include "whs_sniff_tcpdump.hpp"

int main(const int argc, const char **argv)
{
    // fetch target network interface from argument
    if (argc != 2) {
        std::cerr << "Usage: ./whs_sniff {IFACE}" << std::endl;
        std::exit(1);
    }

    // need nonblocking to make this functionality...
    // // set handler for graceful quit
    // whs_sniff::SetSignalHandler();

    // start sniffer
    whs_sniff::g_running = 1;
    whs_sniff::Sniff sniffer(argv[1], "tcp[tcpflags] & (tcp-push) != 0", &whs_sniff_tcpdump::hook);
    std::cout << "Starting whs_sniff" << std::endl;
    while (whs_sniff::g_running && !sniffer.HasError()) {
        sniffer.Loop();
    }

    return 0;
}
