#include "whs_sniff.hpp"

#include <csignal>
#include <cstdlib>
#include <pcap/pcap.h>

#include <iostream>

sig_atomic_t whs_sniff::g_running = 0;

whs_sniff::Sniff::Sniff(const char* interface, const char* filter, PacketHandler handler){
    // initialize variables
    this->error_ = "";
    this->errorbuf_[0] = '\0';
    this->packet_count_ = 0;
    this->hook_ = handler;

    // initialize pcap handle
    this->pcap_handle_ = pcap_open_live(interface, BUFSIZ, true, 500, this->errorbuf_);
    if (this->pcap_handle_ == NULL) {
        perror("Error opening interface:");
        this->error_ = "Fail: open device";
        return;
    }
    bpf_u_int32 net = PCAP_NETMASK_UNKNOWN;
    struct bpf_program fp;
    pcap_compile(this->pcap_handle_, &fp, filter, 0, net);
    if (pcap_setfilter(this->pcap_handle_, &fp) !=0) {
        pcap_perror(this->pcap_handle_, "Error setting filter:");
        this->error_ = "Fail: set filter";
        return;
    }
}

whs_sniff::Sniff::~Sniff(void) {
    if (this->pcap_handle_ == NULL) return;
    pcap_close(this->pcap_handle_);
}

void whs_sniff::Sniff::Loop(void) {
    struct pcap_pkthdr header;
    const u_char* packet;

    packet = pcap_next(this->pcap_handle_, &header);
    if (packet == NULL) {
        pcap_perror(this->pcap_handle_, "Error while receiving packet:");
        this->error_ = "Error: pcap_next";
        return;
    }
    this->packet_count_ += 1;
    bool hook_err = this->hook_(packet, &header, this->packet_count_);
    if (hook_err) {
        pcap_perror(this->pcap_handle_, "Error while handling event:");
        this->error_ = "Error: from event hook";
    }
}

void whs_sniff::Sniff::SetEventHook(PacketHandler handler) {
    this->hook_ = handler;
}

bool whs_sniff::Sniff::HasError(void) const {
    return this->error_.length() == 0 ? false : true;
}

const std::string& whs_sniff::Sniff::ErrorMessage(void) const{
    return this->error_;
}

void whs_sniff::SetSignalHandler(void) {
    sigset_t mask;
    sigemptyset(&mask);
    struct sigaction action;
    action.sa_sigaction = &whs_sniff::HandleSignal;
    action.sa_mask = mask;
    action.sa_flags = 0;
    sigaction(SIGINT, &action, NULL);
    if (sigaction(SIGINT, &action, NULL)) {
        std::perror("Error setting handler: ");
        exit(1);
    }
}

void whs_sniff::HandleSignal(int signo, siginfo_t *info, void *ucontext)
{
    (void) signo;
    (void) info;
    (void) ucontext;
    whs_sniff::g_running = 0;
}